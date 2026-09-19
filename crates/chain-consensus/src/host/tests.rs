//! How the host judges a block it has been given, one condition at a time.
//!
//! The end-to-end behaviour is in `tests/network.rs`; these pin down the
//! checks the host makes *itself*. The real executor happens to make several
//! of them too (height, parent, timestamp order), so the engine here is a
//! stub that accepts any block: `Engine::execute_block` is documented not to
//! check the parent, and the host must not lean on whichever implementation
//! sits behind it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use blst::min_pk::SecretKey;
use chain_engine_api::{
    Block, BlockLimits, BlockRejected, ChainView, ChainViewError, Engine, ExecutedBlock,
    FinaliseError, Head, ValidatorInfo,
};
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_exec::Executor;
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_signer::{InMemoryStore, Signer};
use chain_state::{StateDiff, StateRoot};
use chain_types::beacon::beacon_message;
use chain_types::beacon::genesis_seed;
use chain_types::bls::DST_BEACON;
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::{Address, BlockHeight, BlsPublicKey, ChainId, Hash, PublicKey};
use ed25519_dalek::SigningKey;
use malachite_core_types::Validity;

use super::*;

const GENESIS_TIME: u64 = 1_700_000_000_000;

/// A real chain that executes any block it is handed without complaint.
struct Lenient(Executor);

impl ChainView for Lenient {
    fn head(&self) -> Result<Head, ChainViewError> {
        ChainView::head(&self.0)
    }
    fn validator_set(&self) -> Result<Vec<ValidatorInfo>, ChainViewError> {
        ChainView::validator_set(&self.0)
    }
    fn block_limits(&self) -> Result<BlockLimits, ChainViewError> {
        ChainView::block_limits(&self.0)
    }
}

impl Engine for Lenient {
    fn propose_block(
        &self,
        parent_block_hash: Hash,
        parent_state_root: StateRoot,
        height: BlockHeight,
        timestamp_millis: u64,
        candidate_transactions: Vec<Transaction>,
        limits: BlockLimits,
    ) -> Block {
        self.0.propose_block(
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
        _block: &Block,
    ) -> Result<ExecutedBlock, BlockRejected> {
        Ok(ExecutedBlock {
            state_root: parent_state_root,
            gas_used: 0,
            state_diff: StateDiff::default(),
            outcomes: Vec::new(),
        })
    }
    fn finalise_block(
        &mut self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<(), FinaliseError> {
        self.0.finalise_block(block, executed)
    }
}

type TestHost = Host<Lenient, NoTransactions, FixedClock, InMemoryStore, MemorySignedLog>;

fn secret() -> SecretKey {
    SecretKey::key_gen(&[1; 32], &[]).unwrap()
}

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

struct NoTransactions;

impl TransactionSource for NoTransactions {
    fn candidates(&mut self, _max: usize) -> Vec<Transaction> {
        Vec::new()
    }
    fn committed(&mut self, _block: &Block) {}
}

fn operator(seed: u8) -> PublicKey {
    let key = SigningKey::from_bytes(&[seed; 32]);
    PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap()
}

fn host(now: u64) -> TestHost {
    let secret = secret();
    let key = BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes()).unwrap();
    let config = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![Allocation {
            owner: operator(50),
            amount: 1_000,
        }],
        vec![GenesisValidator {
            operator: operator(1),
            consensus_key: key,
            proof_of_possession: BlsSignature::from_bytes(
                secret
                    .sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
                    .to_bytes(),
            )
            .unwrap(),
            self_stake: GENESIS_PARAM_VALUES.min_self_stake,
        }],
    )
    .unwrap();
    Host::new(
        HostConfig::default(),
        Address::from_public_key(&operator(1)),
        Lenient(Executor::from_genesis(&config).unwrap()),
        Ports {
            source: NoTransactions,
            clock: FixedClock(now),
            signer: Signer::load(secret, InMemoryStore::new()).unwrap(),
            log: MemorySignedLog::new(),
        },
        genesis_seed(&config.hash()),
    )
    .unwrap()
}

/// The verdict on `block` once it is one the host holds.
fn judged(host: &mut TestHost, block: Block) -> Validity {
    let id = block.hash();
    host.env.blocks.insert(id, block);
    host.env.judge(id).unwrap().validity
}

/// An empty block that is right in every respect for a host at `head`.
fn good_block(head: &chain_engine_api::Head) -> Block {
    Block {
        parent_block_hash: head.block_hash,
        height: BlockHeight(head.height.0 + 1),
        timestamp_millis: head.timestamp_ms + 1,
        transactions: Vec::new(),
    }
}

#[test]
fn a_block_that_is_right_in_every_respect_is_valid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    assert_eq!(judged(&mut host, good_block(&head)), Validity::Valid);
}

#[test]
fn a_block_that_does_not_extend_our_chain_is_invalid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    let mut block = good_block(&head);
    block.parent_block_hash = Hash::from_bytes([9; 32]);
    assert_eq!(judged(&mut host, block), Validity::Invalid);
}

#[test]
fn a_block_for_another_height_is_invalid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    for height in [head.height.0, head.height.0 + 2] {
        let mut block = good_block(&head);
        block.height = BlockHeight(height);
        assert_eq!(
            judged(&mut host, block),
            Validity::Invalid,
            "height {height}"
        );
    }
}

#[test]
fn a_block_no_later_than_its_parent_is_invalid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    for timestamp in [head.timestamp_ms, head.timestamp_ms - 1] {
        let mut block = good_block(&head);
        block.timestamp_millis = timestamp;
        assert_eq!(
            judged(&mut host, block),
            Validity::Invalid,
            "timestamp {timestamp}"
        );
    }
}

#[test]
fn a_block_from_beyond_the_clock_tolerance_is_invalid() {
    // The clock reads `GENESIS_TIME`; the tolerance is five seconds.
    let mut host = host(GENESIS_TIME);
    let head = host.env.exec.head().unwrap();
    for (offset, expected) in [(5_000, Validity::Valid), (5_001, Validity::Invalid)] {
        let mut block = good_block(&head);
        block.timestamp_millis = GENESIS_TIME + offset;
        assert_eq!(judged(&mut host, block), expected, "offset {offset}");
    }
}

#[test]
fn a_block_the_host_was_never_given_is_invalid() {
    let host = host(GENESIS_TIME + 1);
    let verdict = host.env.judge(Hash::from_bytes([1; 32])).unwrap();
    assert_eq!(verdict.validity, Validity::Invalid);
}

// ---- blocks that arrive ------------------------------------------------------

/// A block message from the one validator, with a reveal that checks out for
/// `height` and the host's current seed. `variant` makes distinct blocks.
fn genuine(host: &TestHost, height: u64, variant: u64) -> ProposedBlock {
    let head = host.env.exec.head().unwrap();
    ProposedBlock {
        proposer: Address::from_public_key(&operator(1)),
        block: Block {
            parent_block_hash: head.block_hash,
            height: BlockHeight(height),
            timestamp_millis: head.timestamp_ms + 1 + variant,
            transactions: Vec::new(),
        },
        reveal: BlsSignature::from_bytes(
            secret()
                .sign(
                    &beacon_message(BlockHeight(height), host.seed()),
                    DST_BEACON,
                    &[],
                )
                .to_bytes(),
        )
        .unwrap(),
    }
}

#[test]
fn a_block_with_a_genuine_reveal_is_kept_and_one_with_a_forged_reveal_is_not() {
    let mut host = host(GENESIS_TIME + 1);
    let mut forged = genuine(&host, 1, 0);
    forged.reveal =
        BlsSignature::from_bytes(secret().sign(b"not a reveal", DST_BEACON, &[]).to_bytes())
            .unwrap();
    host.handle_message(Message::Block(forged));
    assert!(host.env.blocks.is_empty());
    assert!(host.env.reveals.is_empty());

    host.handle_message(Message::Block(genuine(&host, 1, 0)));
    assert_eq!(host.env.blocks.len(), 1);
    assert_eq!(host.env.reveals.len(), 1);
}

#[test]
fn a_block_from_someone_who_is_not_a_validator_is_dropped() {
    let mut host = host(GENESIS_TIME + 1);
    let mut stranger = genuine(&host, 1, 0);
    stranger.proposer = Address::from_public_key(&operator(7));
    host.handle_message(Message::Block(stranger));
    assert!(host.env.blocks.is_empty());
}

#[test]
fn blocks_held_for_the_height_are_capped() {
    let mut host = host(GENESIS_TIME + 1);
    let cap = host.env.config.max_pending_per_height;
    for variant in 0..u64::try_from(cap + 10).unwrap() {
        host.handle_message(Message::Block(genuine(&host, 1, variant)));
    }
    assert_eq!(host.env.blocks.len(), cap);
}

#[test]
fn blocks_for_later_heights_are_held_up_to_a_cap_and_a_window() {
    let mut host = host(GENESIS_TIME + 1);
    let cap = host.env.config.max_pending_per_height;
    let window = host.env.config.max_future_heights;
    for variant in 0..u64::try_from(cap + 10).unwrap() {
        host.handle_message(Message::Block(genuine(&host, 2, variant)));
    }
    assert_eq!(host.env.future_blocks[&2].len(), cap);

    // Inside the window, kept; beyond it, and behind the chain, dropped.
    host.handle_message(Message::Block(genuine(&host, 1 + window, 0)));
    assert!(host.env.future_blocks.contains_key(&(1 + window)));
    host.handle_message(Message::Block(genuine(&host, 2 + window, 0)));
    assert!(!host.env.future_blocks.contains_key(&(2 + window)));
    host.handle_message(Message::Block(genuine(&host, 0, 0)));
    assert!(!host.env.future_blocks.contains_key(&0));
    assert!(host.env.blocks.is_empty());
}
