//! The engine a node runs: the executor, with its chain kept in a database.
//!
//! [`DurableEngine`] wraps a [`chain_exec::Executor`] and a [`chain_db::Db`]
//! and is itself an [`Engine`] and a [`ChainView`], so the consensus host,
//! which is generic over both, runs on it unchanged. It adds two things the
//! executor, being tier A and doing no I/O, cannot:
//!
//! - **Finalising commits before it advances.** A block is finalised in three
//!   steps: the executor checks it and stages the next state
//!   (`prepare_finalisation`), the database commits the block, its root and
//!   its state diff as one atomic transaction, and only then does the
//!   executor install the staged state. A crash before the commit leaves the
//!   chain at the parent; a crash after it leaves the chain at the block;
//!   nothing in between exists. If the commit fails, the in-memory head has
//!   not moved, which is what the engine contract requires.
//! - **Opening is starting or restoring, and nothing else.** With an empty
//!   database it builds the chain from genesis and records the starting point.
//!   With a database that already holds a chain it rebuilds the executor from
//!   what is stored — after checking that the database was made from *this*
//!   genesis, that the tip block and its recorded root are there, and that the
//!   state hashes to that root and passes the audit
//!   ([`Executor::restore`]). Anything that does not add up is an error: a
//!   node never starts from state it did not commit.
//!
//! The database lives in a `chain` directory inside the node's directory,
//! beside the consensus host's own files ([`crate::NodeDisk`]).

use std::fs;
use std::path::Path;

use chain_db::{Db, DbError};
use chain_engine_api::{
    Block, BlockLimits, BlockRejected, ChainView, ChainViewError, Engine, ExecutedBlock,
    FinaliseError, FinaliseErrorReason, Head, ValidatorInfo,
};
use chain_exec::genesis_config::GenesisConfig;
use chain_exec::{Executor, ExecutorError};
use chain_state::StateRoot;
use chain_types::{BlockHeight, Hash, Transaction};

/// Where the database lives inside the node's directory.
const DATABASE_DIRECTORY: &str = "chain";

/// Why a node's chain could not be started or restored.
#[derive(Debug)]
pub enum OpenError {
    /// The directory for the database could not be made.
    Io(std::io::Error),
    /// The database failed.
    Storage(DbError),
    /// The chain could not be built from genesis, or the stored state was
    /// refused by [`Executor::restore`].
    Executor(ExecutorError),
    /// The database holds a chain that started from a different genesis.
    WrongGenesis { stored: Hash, given: Hash },
    /// The database does not hold a chain that adds up.
    Damaged(&'static str),
}

impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cannot prepare the chain directory: {error}"),
            Self::Storage(error) => write!(f, "the chain database failed: {error}"),
            Self::Executor(error) => write!(f, "{error}"),
            Self::WrongGenesis { stored, given } => write!(
                f,
                "this database belongs to a different chain: it was made from genesis {stored}, but the genesis given is {given}"
            ),
            Self::Damaged(reason) => write!(f, "the chain database is damaged: {reason}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<DbError> for OpenError {
    fn from(error: DbError) -> Self {
        Self::Storage(error)
    }
}

impl From<ExecutorError> for OpenError {
    fn from(error: ExecutorError) -> Self {
        Self::Executor(error)
    }
}

/// An [`Engine`] and [`ChainView`] whose chain survives a restart. See the
/// module docs.
pub struct DurableEngine {
    executor: Executor,
    db: Db,
    /// The last thing the database refused, kept because the engine
    /// contract can only say "storage unavailable".
    last_storage_error: Option<DbError>,
}

impl DurableEngine {
    /// Starts the chain `config` describes in `dir`, or restores the one
    /// already there. See the module docs.
    pub fn open(dir: &Path, config: &GenesisConfig) -> Result<Self, OpenError> {
        let path = dir.join(DATABASE_DIRECTORY);
        fs::create_dir_all(&path).map_err(OpenError::Io)?;
        let db = Db::open(&path)?;
        let executor = match db.genesis_hash()? {
            None => Self::start(&db, config)?,
            Some(stored) => Self::restore(&db, config, stored)?,
        };
        Ok(Self {
            executor,
            db,
            last_storage_error: None,
        })
    }

    /// A new chain: built from genesis, and its starting point recorded in
    /// one transaction, so a crash here leaves an empty database that the
    /// next start builds again the same way.
    fn start(db: &Db, config: &GenesisConfig) -> Result<Executor, OpenError> {
        if db.tip_height()?.is_some() {
            return Err(OpenError::Damaged(
                "it holds blocks but no record of the genesis they follow",
            ));
        }
        let executor = Executor::from_genesis(config)?;
        db.initialise(
            config.hash(),
            executor.state_root().as_hash(),
            executor.state_entries(),
        )?;
        Ok(executor)
    }

    /// The chain the database holds, checked against everything the
    /// database recorded about it.
    fn restore(db: &Db, config: &GenesisConfig, stored: Hash) -> Result<Executor, OpenError> {
        if stored != config.hash() {
            return Err(OpenError::WrongGenesis {
                stored,
                given: config.hash(),
            });
        }
        // The tip block gives the hash the next block names as its parent;
        // with no block yet that is the genesis hash.
        let (tip_hash, tip_height, tip_timestamp) = match db.tip_height()? {
            None => (config.hash(), BlockHeight(0), None),
            Some(height) => {
                let block = db
                    .get_block(height)?
                    .ok_or(OpenError::Damaged("the tip block is missing"))?;
                if block.height != height {
                    return Err(OpenError::Damaged(
                        "the tip block is stored at another height",
                    ));
                }
                (block.hash(), height, Some(block.timestamp_millis))
            }
        };
        let root = db
            .get_root(tip_height)?
            .ok_or(OpenError::Damaged("the state root at the tip is missing"))?;
        let executor = Executor::restore(
            config.chain_id(),
            db.load_state()?,
            tip_hash,
            StateRoot::from_hash(root),
        )?;
        if executor.head_height() != Some(tip_height.0) {
            return Err(OpenError::Damaged(
                "the state's head is not the tip block's height",
            ));
        }
        if let Some(timestamp) = tip_timestamp {
            if executor.head_timestamp_millis() != Some(timestamp) {
                return Err(OpenError::Damaged(
                    "the state's head time is not the tip block's",
                ));
            }
        }
        Ok(executor)
    }

    /// The executor, for reading and auditing.
    pub const fn executor(&self) -> &Executor {
        &self.executor
    }

    /// The database, for reading (serving blocks to a peer, for one). The
    /// engine is the only thing that should commit to it.
    pub const fn database(&self) -> &Db {
        &self.db
    }

    /// What the database last refused, if a finalisation failed for it.
    pub const fn last_storage_error(&self) -> Option<&DbError> {
        self.last_storage_error.as_ref()
    }
}

impl Engine for DurableEngine {
    fn propose_block(
        &self,
        parent_block_hash: Hash,
        parent_state_root: StateRoot,
        height: BlockHeight,
        timestamp_millis: u64,
        candidate_transactions: Vec<Transaction>,
        limits: BlockLimits,
    ) -> Block {
        self.executor.propose_block(
            parent_block_hash,
            parent_state_root,
            height,
            timestamp_millis,
            candidate_transactions,
            limits,
        )
    }

    fn execute_block(
        &self,
        parent_state_root: StateRoot,
        block: &Block,
    ) -> Result<ExecutedBlock, BlockRejected> {
        self.executor.execute_block(parent_state_root, block)
    }

    /// Check and stage, commit durably, then advance. If the database
    /// refuses, the executor has not moved.
    ///
    /// The executor cannot move between the stage and the install: this
    /// takes `&mut self`, so nothing else runs in between.
    fn finalise_block(
        &mut self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<(), FinaliseError> {
        let prepared = self.executor.prepare_finalisation(block, executed)?;
        if let Err(error) =
            self.db
                .commit_block(block, executed.state_root.as_hash(), &executed.state_diff)
        {
            self.last_storage_error = Some(error);
            return Err(FinaliseError {
                reason: FinaliseErrorReason::StorageUnavailable,
            });
        }
        self.executor.apply_prepared_finalisation(prepared)
    }
}

impl ChainView for DurableEngine {
    fn head(&self) -> Result<Head, ChainViewError> {
        ChainView::head(&self.executor)
    }

    fn validator_set(&self) -> Result<Vec<ValidatorInfo>, ChainViewError> {
        ChainView::validator_set(&self.executor)
    }

    fn block_limits(&self) -> Result<BlockLimits, ChainViewError> {
        ChainView::block_limits(&self.executor)
    }
}
