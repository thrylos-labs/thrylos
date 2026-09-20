//! An MDBX-backed flat key-value store: blocks, the state they
//! produced, and per-height state roots, each committed atomically.
//! See `crate`'s doc comment for what this pass covers and defers.

use std::path::Path;

use chain_engine_api::Block;
use chain_state::{StateChange, StateDiff, StateKey, StateValue};
use chain_types::codec::{decode_exact, Encode};
use chain_types::collections::BTreeMap;
use chain_types::{BlockHeight, Hash};
use libmdbx::{
    DatabaseFlags, Environment, EnvironmentFlags, Geometry, MdbxError, Mode, SyncMode, WriteFlags,
};

use crate::error::DbError;
use crate::schema::{
    height_from_bytes, height_key, BLOCKS_TABLE, GENESIS_HASH_KEY, MAX_KEY_BYTES, META_TABLE,
    ROOTS_TABLE, STATE_TABLE, TIP_HEIGHT_KEY,
};

/// Refuses a key the store will not write. See [`MAX_KEY_BYTES`].
fn check_key(key: &StateKey) -> Result<(), DbError> {
    let length = key.as_bytes().len();
    if length > MAX_KEY_BYTES {
        return Err(DbError::KeyTooLarge { length });
    }
    Ok(())
}

/// Upper bound on the memory-mapped address range MDBX reserves for
/// this environment. MDBX only allocates disk pages as they're
/// actually written, so this is a ceiling on growth, not a
/// pre-allocation — sized generously for this pass rather than
/// measured against real state growth (`docs/spec.md`'s "State growth
/// is priced" fee work, not yet built, is what would eventually bound
/// this for real).
const MAX_SIZE_BYTES: usize = 64 * 1024 * 1024 * 1024; // 64 GiB

pub struct Db {
    env: Environment,
}

impl Db {
    /// Opens (creating if absent) an MDBX environment at `path`.
    ///
    /// Fsync policy: [`SyncMode::Durable`] — MDBX's default, and its
    /// only mode that "guarantees the integrity of the database in the
    /// event of a crash at any time" (this crate's own dependency doc
    /// comment on the type). Every [`Db::commit_block`] flushes both
    /// the written data *and* the meta-page before returning, which is
    /// exactly `docs/spec.md`'s "State, storage and sync" requirement:
    /// "Writes are batched per block and committed atomically with the
    /// block header. A crash mid-write leaves the node at block N or
    /// N+1, never between." Set explicitly (it also happens to be the
    /// default) rather than left implicit, since the faster modes
    /// (`NoMetaSync`/`SafeNoSync`/`UtterlyNoSync`) trade away exactly
    /// this guarantee for throughput — a choice this crate is not
    /// making silently.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let mut builder = Environment::builder();
        builder
            .set_max_dbs(4)
            .set_flags(EnvironmentFlags {
                mode: Mode::ReadWrite {
                    sync_mode: SyncMode::Durable,
                },
                ..Default::default()
            })
            .set_geometry(Geometry {
                size: Some(0..MAX_SIZE_BYTES),
                ..Default::default()
            });
        let env = builder.open(path)?;
        Ok(Self { env })
    }

    /// Persists `block`, the state root it produced, and `diff` — the
    /// keys its execution actually wrote — as one MDBX write
    /// transaction. Nothing here is visible to a reader, and nothing
    /// is durable, until this returns `Ok`; a crash any time before
    /// that leaves the store exactly as it was before the call, since
    /// the transaction was never committed. There is no partially-
    /// applied state in between (`docs/spec.md`'s "block N or N+1,
    /// never between") — see `tests/crash_durability.rs`, which kills
    /// a process mid-write and confirms the tip doesn't move.
    pub fn commit_block(
        &self,
        block: &Block,
        state_root: Hash,
        diff: &StateDiff,
    ) -> Result<(), DbError> {
        let txn = self.env.begin_rw_sync()?;

        let blocks_db = txn.create_db(Some(BLOCKS_TABLE), DatabaseFlags::empty())?;
        let roots_db = txn.create_db(Some(ROOTS_TABLE), DatabaseFlags::empty())?;
        let state_db = txn.create_db(Some(STATE_TABLE), DatabaseFlags::empty())?;
        let meta_db = txn.create_db(Some(META_TABLE), DatabaseFlags::empty())?;

        let committed_tip: Option<Vec<u8>> = txn.get(meta_db.dbi(), TIP_HEIGHT_KEY)?;
        let expected = match committed_tip.as_deref().and_then(height_from_bytes) {
            Some(height) => BlockHeight(height.0.checked_add(1).ok_or(
                DbError::NonSequentialCommit {
                    expected: height,
                    actual: block.height,
                },
            )?),
            None => BlockHeight(1),
        };
        if block.height != expected {
            return Err(DbError::NonSequentialCommit {
                expected,
                actual: block.height,
            });
        }

        let mut block_bytes = Vec::new();
        block.encode(&mut block_bytes);
        txn.put(
            blocks_db,
            height_key(block.height),
            block_bytes,
            WriteFlags::UPSERT,
        )?;
        txn.put(
            roots_db,
            height_key(block.height),
            state_root.as_bytes(),
            WriteFlags::UPSERT,
        )?;
        for (key, change) in diff.iter() {
            check_key(key)?;
            match change {
                StateChange::Put(value) => {
                    txn.put(
                        state_db,
                        key.as_bytes(),
                        value.as_bytes(),
                        WriteFlags::UPSERT,
                    )?;
                }
                // Deleting a key MDBX doesn't hold is not an error: the
                // diff says the key is absent afterwards, and it is.
                StateChange::Delete => {
                    txn.del(state_db, key.as_bytes(), None)?;
                }
            }
        }
        txn.put(
            meta_db,
            TIP_HEIGHT_KEY,
            height_key(block.height),
            WriteFlags::UPSERT,
        )?;

        txn.commit()?;
        Ok(())
    }

    /// Records where the chain starts: the hash of the genesis configuration,
    /// the state root at height 0, and every entry of the genesis state, as
    /// one transaction. [`Self::commit_block`] writes only what a block
    /// *changes*, so without this the genesis state (the allocations, the
    /// validators, the parameters) would exist nowhere on disk, and the
    /// chain could not be rebuilt from it.
    ///
    /// Refuses with [`DbError::AlreadyInitialised`] if a genesis hash is
    /// already recorded or any block has been committed. Nothing is
    /// visible, and nothing is durable, until this returns `Ok`.
    pub fn initialise<'a>(
        &self,
        genesis_hash: Hash,
        genesis_root: Hash,
        state: impl IntoIterator<Item = (&'a StateKey, &'a StateValue)>,
    ) -> Result<(), DbError> {
        let txn = self.env.begin_rw_sync()?;

        let roots_db = txn.create_db(Some(ROOTS_TABLE), DatabaseFlags::empty())?;
        let state_db = txn.create_db(Some(STATE_TABLE), DatabaseFlags::empty())?;
        let meta_db = txn.create_db(Some(META_TABLE), DatabaseFlags::empty())?;
        txn.create_db(Some(BLOCKS_TABLE), DatabaseFlags::empty())?;

        let genesis: Option<Vec<u8>> = txn.get(meta_db.dbi(), GENESIS_HASH_KEY)?;
        let tip: Option<Vec<u8>> = txn.get(meta_db.dbi(), TIP_HEIGHT_KEY)?;
        if genesis.is_some() || tip.is_some() {
            return Err(DbError::AlreadyInitialised);
        }

        for (key, value) in state {
            check_key(key)?;
            txn.put(
                state_db,
                key.as_bytes(),
                value.as_bytes(),
                WriteFlags::UPSERT,
            )?;
        }
        txn.put(
            roots_db,
            height_key(BlockHeight(0)),
            genesis_root.as_bytes(),
            WriteFlags::UPSERT,
        )?;
        txn.put(
            meta_db,
            GENESIS_HASH_KEY,
            genesis_hash.as_bytes(),
            WriteFlags::UPSERT,
        )?;

        txn.commit()?;
        Ok(())
    }

    /// The hash of the genesis configuration this database was initialised
    /// with, or `None` if [`Self::initialise`] has not run.
    pub fn genesis_hash(&self) -> Result<Option<Hash>, DbError> {
        let txn = self.env.begin_ro_sync()?;
        let db = match txn.open_db(Some(META_TABLE)) {
            Ok(db) => db,
            Err(MdbxError::NotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let bytes: Option<Vec<u8>> = txn.get(db.dbi(), GENESIS_HASH_KEY)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DbError::Mdbx(MdbxError::BadValSize))?;
        Ok(Some(Hash::from_bytes(array)))
    }

    /// Every entry of the committed state, in key order: the genesis state
    /// with every block's diff applied. Reads it all into memory, from one
    /// snapshot, so it is a consistent state of the chain at some height
    /// even if a block is committed while it runs. Meant for starting a
    /// node, not for serving queries.
    pub fn load_state(&self) -> Result<BTreeMap<StateKey, StateValue>, DbError> {
        let txn = self.env.begin_ro_sync()?;
        let db = match txn.open_db(Some(STATE_TABLE)) {
            Ok(db) => db,
            Err(MdbxError::NotFound) => return Ok(BTreeMap::new()),
            Err(err) => return Err(err.into()),
        };
        let mut cursor = txn.cursor(db)?;
        let mut state = BTreeMap::new();
        let mut entry = cursor.first::<Vec<u8>, Vec<u8>>()?;
        while let Some((key, value)) = entry {
            state.insert(StateKey::new(key), StateValue::new(value));
            entry = cursor.next::<Vec<u8>, Vec<u8>>()?;
        }
        Ok(state)
    }

    pub fn get_block(&self, height: BlockHeight) -> Result<Option<Block>, DbError> {
        let txn = self.env.begin_ro_sync()?;
        let db = match txn.open_db(Some(BLOCKS_TABLE)) {
            Ok(db) => db,
            Err(MdbxError::NotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let bytes: Option<Vec<u8>> = txn.get(db.dbi(), &height_key(height))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        Ok(Some(decode_exact(&bytes)?))
    }

    pub fn get_state_value(&self, key: &StateKey) -> Result<Option<StateValue>, DbError> {
        let txn = self.env.begin_ro_sync()?;
        let db = match txn.open_db(Some(STATE_TABLE)) {
            Ok(db) => db,
            Err(MdbxError::NotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let bytes: Option<Vec<u8>> = txn.get(db.dbi(), key.as_bytes())?;
        Ok(bytes.map(StateValue::new))
    }

    pub fn get_root(&self, height: BlockHeight) -> Result<Option<Hash>, DbError> {
        let txn = self.env.begin_ro_sync()?;
        let db = match txn.open_db(Some(ROOTS_TABLE)) {
            Ok(db) => db,
            Err(MdbxError::NotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let bytes: Option<Vec<u8>> = txn.get(db.dbi(), &height_key(height))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DbError::Mdbx(MdbxError::BadValSize))?;
        Ok(Some(Hash::from_bytes(array)))
    }

    pub fn tip_height(&self) -> Result<Option<BlockHeight>, DbError> {
        let txn = self.env.begin_ro_sync()?;
        let db = match txn.open_db(Some(META_TABLE)) {
            Ok(db) => db,
            Err(MdbxError::NotFound) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let bytes: Option<Vec<u8>> = txn.get(db.dbi(), TIP_HEIGHT_KEY)?;
        Ok(bytes.and_then(|b| height_from_bytes(&b)))
    }
}
