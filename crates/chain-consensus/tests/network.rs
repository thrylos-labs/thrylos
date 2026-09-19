//! A network of consensus hosts, in one process: each with its own real
//! `Executor`, its own BLS key behind a real `chain-signer`, and a simulated
//! network and clock between them. Blocks are proposed, executed, voted on,
//! decided and committed by the real machinery end to end, and every kind of
//! trouble — a silent proposer, a fast clock, a refusing signer, a node that
//! misses a block — is staged by deciding what the network delivers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::type_complexity
)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use blst::min_pk::SecretKey;
use chain_consensus::certificate::verify_commit_certificate;
use chain_consensus::context::ThrylosContext;
use chain_consensus::host::{
    Clock, CommitRecord, Committed, HaltReason, Host, HostConfig, MemorySignedLog, MemoryStorage,
    Message, Ports, SyncRequest, SyncResponse, TimerCommand, TransactionSource, WalError,
};
use chain_consensus::types::{ConsensusAddress, ConsensusHeight, ConsensusValidatorSet};
use chain_consensus::wire::{decode_message, encode_message};
use chain_engine_api::{Block, ChainView};
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_exec::native::{STAKE, STAKING_MODULE_NAME, STAKING_PACKAGE_ADDRESS};
use chain_exec::Executor;
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_signer::{HighWaterMark, HighWaterMarkStore, InMemoryStore, Signer, Step};
use chain_types::beacon::{genesis_seed, next_seed, verify_reveal};
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::{
    Address, BlockHeight, BlsPublicKey, ChainId, DuplicateVoteEvidence, Encode, GasAmount,
    GasPrice, Hash, MoveCall, PublicKey, Round, SequenceNumber, Signature, Transaction,
    TransactionBody,
};
use ed25519_dalek::{Signer as _, SigningKey};
use malachite_core_types::{Context as _, Timeout};

const GENESIS_TIME: u64 = 1_700_000_000_000;
const MIN: u128 = GENESIS_PARAM_VALUES.min_self_stake;

// ---- identities ----------------------------------------------------------

fn operator_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn operator_public(seed: u8) -> PublicKey {
    PublicKey::from_ed25519_bytes(operator_key(seed).verifying_key().to_bytes()).unwrap()
}

fn operator_address(seed: u8) -> Address {
    Address::from_public_key(&operator_public(seed))
}

fn bls_secret(seed: u8) -> SecretKey {
    SecretKey::key_gen(&[seed; 32], &[]).unwrap()
}

fn bls_public(seed: u8) -> BlsPublicKey {
    BlsPublicKey::from_bytes(bls_secret(seed).sk_to_pk().to_bytes()).unwrap()
}

fn genesis_validator(seed: u8, stake: u128) -> GenesisValidator {
    let sk = bls_secret(seed);
    let key = bls_public(seed);
    GenesisValidator {
        operator: operator_public(seed),
        consensus_key: key,
        proof_of_possession: BlsSignature::from_bytes(
            sk.sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
                .to_bytes(),
        )
        .unwrap(),
        self_stake: stake,
    }
}

/// A funded account that is not a validator, for transactions.
const USER: u8 = 50;

fn config(stakes: &[u128]) -> GenesisConfig {
    GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![Allocation {
            owner: operator_public(USER),
            amount: 1_000_000_000,
        }],
        stakes
            .iter()
            .enumerate()
            .map(|(i, stake)| genesis_validator(u8::try_from(i).unwrap() + 1, *stake))
            .collect(),
    )
    .unwrap()
}

fn stake_tx(sequence: u64, validator: Address, amount: u128) -> Transaction {
    let body = TransactionBody {
        chain_id: ChainId(1),
        sender: operator_public(USER),
        sequence_number: SequenceNumber(sequence),
        expiry: BlockHeight(5_000),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(10),
        declared_inputs: Vec::new(),
        call: MoveCall {
            module_address: Address::from_bytes(STAKING_PACKAGE_ADDRESS),
            module_name: STAKING_MODULE_NAME.as_bytes().to_vec(),
            function_name: STAKE.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments: vec![validator.as_bytes().to_vec(), amount.to_le_bytes().to_vec()],
        },
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    let signature = Signature::from_ed25519_bytes(operator_key(USER).sign(&bytes).to_bytes());
    Transaction { body, signature }
}

/// What arrives when `message` is sent: everything the simulated network
/// carries goes through the real encoding and back.
fn over_the_wire(message: &Message) -> Message {
    decode_message(&encode_message(message)).expect("what a host sends decodes")
}

// ---- the ports -------------------------------------------------------------

#[derive(Clone)]
struct SimClock(Rc<Cell<u64>>);

impl Clock for SimClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Default)]
struct SharedSource(Rc<RefCell<Vec<Transaction>>>);

impl TransactionSource for SharedSource {
    fn candidates(&mut self, max: usize) -> Vec<Transaction> {
        self.0.borrow().iter().take(max).cloned().collect()
    }

    fn committed(&mut self, block: &Block) {
        self.0
            .borrow_mut()
            .retain(|tx| !block.transactions.contains(tx));
    }
}

/// What a node keeps on disk: these outlive the host, so a restarted one is
/// handed the same ones.
#[derive(Clone, Default)]
struct SharedMark(Rc<RefCell<InMemoryStore>>);

impl HighWaterMarkStore for SharedMark {
    type Error = std::convert::Infallible;

    fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
        self.0.borrow().load()
    }

    fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
        self.0.borrow_mut().persist(mark)
    }
}

#[derive(Clone, Default)]
struct SharedSigned(Rc<RefCell<MemorySignedLog>>);

impl chain_consensus::host::SignedLog for SharedSigned {
    fn get(&self, position: HighWaterMark) -> Option<chain_consensus::host::SignedEntry> {
        self.0.borrow().get(position)
    }

    fn record(&mut self, position: HighWaterMark, entry: chain_consensus::host::SignedEntry) {
        self.0.borrow_mut().record(position, entry);
    }
}

/// The host's own storage. `forgetful` makes its write-ahead log return
/// nothing at a restart, which is what having no log is.
#[derive(Clone, Default)]
struct SharedStorage {
    inner: Rc<RefCell<MemoryStorage>>,
    forgetful: bool,
}

impl chain_consensus::host::CommitLog for SharedStorage {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash) {
        self.inner.borrow_mut().record(record, seed_after);
    }

    fn range(&self, from: BlockHeight, max: usize) -> Vec<CommitRecord> {
        self.inner.borrow().range(from, max)
    }

    fn seed_after(&self, height: BlockHeight) -> Option<Hash> {
        self.inner.borrow().seed_after(height)
    }
}

impl chain_consensus::host::Wal for SharedStorage {
    fn append(&mut self, height: BlockHeight, entry: &[u8]) -> Result<(), WalError> {
        self.inner.borrow_mut().append(height, entry)
    }

    fn flush(&mut self) -> Result<(), WalError> {
        self.inner.borrow_mut().flush()
    }

    fn start_height(&mut self, height: BlockHeight) -> Result<Vec<Vec<u8>>, WalError> {
        let entries = self.inner.borrow_mut().start_height(height)?;
        Ok(if self.forgetful { Vec::new() } else { entries })
    }
}

#[derive(Clone, Default)]
struct Disk {
    mark: SharedMark,
    signed: SharedSigned,
    storage: SharedStorage,
}

type TestHost = Host<Executor, SharedSource, SimClock, SharedMark, SharedSigned, SharedStorage>;

// ---- the network -------------------------------------------------------------

struct Sim {
    nodes: Vec<TestHost>,
    clocks: Vec<SimClock>,
    /// How far ahead of the true time each node's clock runs.
    skew: Vec<u64>,
    sources: Vec<SharedSource>,
    inbox: VecDeque<(usize, usize, Message)>,
    timers: Vec<Vec<(Timeout, u64)>>,
    committed: Vec<Vec<Committed>>,
    evidence: Vec<Vec<DuplicateVoteEvidence>>,
    /// `(from, to, message)`: whether to deliver it.
    filter: Box<dyn FnMut(usize, usize, &Message) -> bool>,
    now: u64,
    config: GenesisConfig,
    host_config: HostConfig,
    disks: Vec<Disk>,
    /// How many events (messages, timers, ticks) each node has handled.
    events: Vec<usize>,
    /// `(node, n)`: restart `node` right after it handles its `n`th event,
    /// before anything that event produced has left it.
    crash_at: Option<(usize, usize)>,
    /// Restarts that have happened.
    restarts: usize,
    /// How many times each node has been told to start the propose timer of
    /// round 0 at each height: once per start of a height.
    height_starts: std::collections::BTreeMap<(usize, u64), usize>,
}

struct Options {
    stakes: Vec<u128>,
    skew: Vec<u64>,
    /// Signers that start with their mark already advanced.
    advanced_signers: Vec<usize>,
    /// Nodes whose *chain* differs from everyone else's (same validators
    /// and the same seed, but a different genesis state), so they judge
    /// every block invalid.
    divergent: Vec<usize>,
    filter: Box<dyn FnMut(usize, usize, &Message) -> bool>,
    host: HostConfig,
    /// Every node's write-ahead log is lost at a restart.
    forgetful: bool,
    crash_at: Option<(usize, usize)>,
}

impl Options {
    fn new(n: usize) -> Self {
        Self {
            stakes: vec![MIN; n],
            skew: vec![0; n],
            advanced_signers: Vec::new(),
            divergent: Vec::new(),
            filter: Box::new(|_, _, _| true),
            host: HostConfig::default(),
            forgetful: false,
            crash_at: None,
        }
    }
}

impl Sim {
    fn new(options: Options) -> Self {
        let n = options.stakes.len();
        let config = config(&options.stakes);
        let start = GENESIS_TIME + 1_000;
        let mut sim = Self {
            nodes: Vec::new(),
            clocks: Vec::new(),
            skew: options.skew.clone(),
            sources: Vec::new(),
            inbox: VecDeque::new(),
            timers: vec![Vec::new(); n],
            committed: vec![Vec::new(); n],
            evidence: vec![Vec::new(); n],
            filter: options.filter,
            now: start,
            config,
            host_config: options.host,
            disks: Vec::new(),
            events: vec![0; n],
            crash_at: options.crash_at,
            restarts: 0,
            height_starts: std::collections::BTreeMap::new(),
        };
        for i in 0..n {
            let disk = Disk {
                storage: SharedStorage {
                    forgetful: options.forgetful,
                    ..SharedStorage::default()
                },
                ..Disk::default()
            };
            if options.advanced_signers.contains(&i) {
                disk.mark
                    .0
                    .borrow_mut()
                    .persist(HighWaterMark::new(
                        BlockHeight(99),
                        Round(0),
                        Step::Precommit,
                    ))
                    .unwrap();
            }
            let executor = if options.divergent.contains(&i) {
                let mut other = self::config(&options.stakes);
                other = GenesisConfig::new(
                    other.chain_id(),
                    other.genesis_time_ms(),
                    *other.parameters(),
                    vec![Allocation {
                        owner: operator_public(USER),
                        amount: 1_000_000_001, // one more than everyone else's
                    }],
                    other.validators().to_vec(),
                )
                .unwrap();
                Executor::from_genesis(&other).unwrap()
            } else {
                Executor::from_genesis(&sim.config).unwrap()
            };
            sim.clocks
                .push(SimClock(Rc::new(Cell::new(start + options.skew[i]))));
            sim.sources.push(SharedSource::default());
            sim.disks.push(disk);
            let host = sim.host_on(i, executor);
            sim.nodes.push(host);
        }
        for node in &mut sim.nodes {
            node.start();
        }
        sim
    }

    /// A host for node `i` on `executor`, with the disk the node has.
    fn host_on(&self, i: usize, executor: Executor) -> TestHost {
        let seed = u8::try_from(i).unwrap() + 1;
        let disk = self.disks[i].clone();
        Host::new(
            self.host_config,
            operator_address(seed),
            executor,
            Ports {
                source: self.sources[i].clone(),
                clock: self.clocks[i].clone(),
                signer: Signer::load(bls_secret(seed), disk.mark).unwrap(),
                log: disk.signed,
                storage: disk.storage,
            },
            genesis_seed(&self.config.hash()),
        )
        .unwrap()
    }

    /// Node `i` crashes and starts again. Whatever it had produced and not
    /// yet handed over is gone, so is what it had appended to its log and not
    /// flushed, and so are its timers; its chain and what it keeps on disk
    /// are what they were.
    fn restart(&mut self, i: usize) {
        drop(self.nodes[i].take_outbox());
        self.disks[i]
            .storage
            .inner
            .borrow_mut()
            .wal
            .lose_unflushed();
        self.timers[i].clear();
        let old = self.nodes.remove(i);
        let executor = old.into_chain();
        let mut host = self.host_on(i, executor);
        host.start();
        self.nodes.insert(i, host);
        self.restarts += 1;
    }

    fn n(&self) -> usize {
        self.nodes.len()
    }

    /// Collects what node `i` wants done.
    fn drain(&mut self, i: usize) {
        let outbox = self.nodes[i].take_outbox();
        for message in outbox.messages {
            for to in 0..self.n() {
                if to != i && (self.filter)(i, to, &message) {
                    self.inbox.push_back((i, to, over_the_wire(&message)));
                }
            }
        }
        for (address, message) in outbox.directed {
            let to = self.node_of(&address);
            if to != i && (self.filter)(i, to, &message) {
                self.inbox.push_back((i, to, over_the_wire(&message)));
            }
        }
        for command in outbox.timers {
            match command {
                TimerCommand::Schedule { timeout, after } => {
                    if timeout == Timeout::propose(malachite_core_types::Round::new(0)) {
                        let height = self.nodes[i].height().0;
                        *self.height_starts.entry((i, height)).or_default() += 1;
                    }
                    self.timers[i].retain(|(t, _)| *t != timeout);
                    let due = self.now + u64::try_from(after.as_millis()).unwrap();
                    self.timers[i].push((timeout, due));
                }
                TimerCommand::Cancel(timeout) => self.timers[i].retain(|(t, _)| *t != timeout),
                TimerCommand::CancelAll => self.timers[i].clear(),
            }
        }
        self.committed[i].extend(outbox.committed);
        self.evidence[i].extend(outbox.evidence);
    }

    fn set_time(&mut self, now: u64) {
        self.now = now;
        for (clock, skew) in self.clocks.iter().zip(&self.skew) {
            clock.0.set(now + skew);
        }
    }

    /// One thing happens: a message is delivered, or the next timer fires,
    /// or a node that has been behind long enough is ticked. Returns the
    /// node it happened to, or `None` if there was nothing to do.
    fn step(&mut self) -> Option<usize> {
        for i in 0..self.n() {
            self.drain(i);
        }
        let node = if let Some((_, to, message)) = self.inbox.pop_front() {
            self.nodes[to].handle_message(message);
            to
        } else {
            // Nothing in flight: the next thing to happen, in time then node
            // order — a timer firing, or a node that has been behind long
            // enough to ask for what it missed.
            let timers = (0..self.n()).flat_map(|i| {
                self.timers[i]
                    .iter()
                    .map(move |(t, due)| (*due, i, Some(*t)))
            });
            let wakes = (0..self.n()).filter_map(|i| {
                let wake = self.nodes[i].next_wake_ms()?;
                Some((wake.saturating_sub(self.skew[i]), i, None))
            });
            let (due, i, timeout) = timers.chain(wakes).min_by_key(|(due, i, _)| (*due, *i))?;
            self.set_time(self.now.max(due));
            match timeout {
                Some(timeout) => {
                    self.timers[i].retain(|(t, _)| *t != timeout);
                    self.nodes[i].handle_timeout(timeout);
                }
                None => self.nodes[i].tick(),
            }
            i
        };
        self.events[node] += 1;
        if self.crash_at == Some((node, self.events[node])) {
            self.crash_at = None;
            self.restart(node);
        }
        Some(node)
    }

    /// Runs the network until `done`, panicking if it stalls or runs on.
    fn run_until(&mut self, done: impl Fn(&Sim) -> bool) {
        for _ in 0..200_000 {
            for i in 0..self.n() {
                self.drain(i);
            }
            if done(self) {
                return;
            }
            if self.step().is_none() {
                panic!("the network is idle and nothing is due: a deadlock");
            }
        }
        let state: Vec<String> = (0..self.n())
            .map(|i| {
                format!(
                    "node {i}: height {} committed {} {:?} halted {:?} timers {:?}",
                    self.nodes[i].height().0,
                    self.committed[i].len(),
                    self.committed[i]
                        .iter()
                        .map(|c| (c.certificate.round, c.block.timestamp_millis))
                        .collect::<Vec<_>>(),
                    self.nodes[i].halted(),
                    self.timers[i]
                )
            })
            .collect();
        panic!(
            "the network did not reach the goal in 200,000 steps; now={} inbox={}\n{}",
            self.now,
            self.inbox.len(),
            state.join("\n")
        );
    }

    fn heights_committed(&self, i: usize) -> usize {
        self.committed[i].len()
    }

    fn all_committed(&self, count: usize) -> bool {
        (0..self.n()).all(|i| self.heights_committed(i) >= count)
    }

    /// The node index of the validator with this address.
    fn node_of(&self, address: &Address) -> usize {
        (0..self.n())
            .find(|i| &operator_address(u8::try_from(*i).unwrap() + 1) == address)
            .unwrap()
    }
}

/// The proposer `select_proposer` picks for `round` of `height` under `seed`,
/// for a chain whose validators are `exec`'s.
fn expected_proposer(exec: &Executor, seed: &Hash, height: u64, round: u32) -> Address {
    let set = ConsensusValidatorSet::from_infos(&ChainView::validator_set(exec).unwrap(), *seed);
    ThrylosContext::new()
        .select_proposer(
            &set,
            ConsensusHeight(BlockHeight(height)),
            malachite_core_types::Round::new(round),
        )
        .address
        .0
}

// ---- the happy path ----------------------------------------------------------

#[test]
fn four_validators_commit_three_heights_and_end_up_in_exactly_the_same_place() {
    let mut sim = Sim::new(Options::new(4));
    sim.run_until(|s| s.all_committed(3));

    let reference = &sim.committed[0];
    for i in 1..sim.n() {
        let theirs = &sim.committed[i];
        for height in 0..3 {
            assert_eq!(
                theirs[height].block, reference[height].block,
                "node {i}, block {height}"
            );
            assert_eq!(
                theirs[height].executed.state_root,
                reference[height].executed.state_root
            );
            assert_eq!(theirs[height].seed_after, reference[height].seed_after);
        }
    }
    let roots: Vec<_> = sim.nodes.iter().map(|n| n.chain().state_root()).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "the same state on every node"
    );
    for node in &sim.nodes {
        assert_eq!(node.chain().head().unwrap().height, BlockHeight(3));
        node.chain().audit().unwrap();
    }
}

#[test]
fn every_decision_carries_a_valid_quorum_certificate_and_links_to_its_parent() {
    let mut sim = Sim::new(Options::new(4));
    sim.run_until(|s| s.all_committed(3));

    let infos = ChainView::validator_set(sim.nodes[0].chain()).unwrap();
    let set = ConsensusValidatorSet::from_infos(&infos, genesis_seed(&sim.config.hash()));
    let mut parent = sim.config.hash();
    for committed in &sim.committed[0] {
        assert_eq!(committed.certificate.value_id, committed.block.hash());
        assert_eq!(committed.certificate.height.0, committed.height);
        verify_commit_certificate(&committed.certificate, &set, Default::default()).unwrap();
        assert_eq!(
            committed.block.parent_block_hash, parent,
            "the chain links up"
        );
        parent = committed.block.hash();
    }
}

#[test]
fn the_proposer_of_each_height_is_the_one_the_beacon_draw_picks_and_the_seed_chain_advances() {
    let mut sim = Sim::new(Options::new(4));
    sim.run_until(|s| s.all_committed(6));

    let reference = sim.nodes[0].chain();
    let mut seed = genesis_seed(&sim.config.hash());
    let mut proposers = Vec::new();
    for committed in &sim.committed[0] {
        let round = committed.certificate.round.as_u32().unwrap();
        let proposer = expected_proposer(reference, &seed, committed.height.0, round);
        // The reveal that the next seed is built from is genuinely that
        // proposer's, for this height and seed.
        let key = bls_public(u8::try_from(sim.node_of(&proposer)).unwrap() + 1);
        verify_reveal(&key, committed.height, &seed, &committed.reveal).unwrap();
        seed = next_seed(&seed, &committed.reveal);
        assert_eq!(committed.seed_after, seed);
        proposers.push(proposer);
    }
    let distinct: std::collections::BTreeSet<_> = proposers.iter().collect();
    assert!(
        distinct.len() > 1,
        "the schedule moves between validators: {proposers:?}"
    );
    for node in &sim.nodes {
        assert_eq!(node.seed(), &seed, "every node is on the same seed");
    }
}

#[test]
fn a_transaction_offered_to_every_mempool_is_included_once_and_moves_coin_the_same_everywhere() {
    let mut sim = Sim::new(Options::new(4));
    let target = operator_address(1);
    let tx = stake_tx(0, target, 40_000);
    for source in &sim.sources {
        source.0.borrow_mut().push(tx.clone());
    }
    sim.run_until(|s| s.all_committed(3));

    let included: usize = sim.committed[0]
        .iter()
        .map(|c| c.block.transactions.iter().filter(|t| **t == tx).count())
        .sum();
    assert_eq!(included, 1, "exactly once");
    for node in &sim.nodes {
        let balance = node
            .chain()
            .read_account(operator_address(USER))
            .unwrap()
            .balance;
        assert_eq!(balance, 1_000_000_000 - 40_000 - 1_000);
        node.chain().audit().unwrap();
    }
    for source in &sim.sources {
        assert!(source.0.borrow().is_empty(), "every mempool forgot it");
    }
}

// ---- trouble ---------------------------------------------------------------

/// The node index of the round-0 proposer at height 1.
fn first_proposer(n: usize) -> usize {
    let config = config(&vec![MIN; n]);
    let exec = Executor::from_genesis(&config).unwrap();
    let address = expected_proposer(&exec, &genesis_seed(&config.hash()), 1, 0);
    (0..n)
        .find(|i| operator_address(u8::try_from(*i).unwrap() + 1) == address)
        .unwrap()
}

#[test]
fn a_silent_proposer_costs_a_round_not_the_chain() {
    let silent = first_proposer(4);
    let mut options = Options::new(4);
    options.filter = Box::new(move |from, _, _| from != silent);
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.all_committed(1));

    let round = sim.committed[0][0].certificate.round.as_u32().unwrap();
    assert!(
        round >= 1,
        "round 0's proposer said nothing, so it was decided later: {round}"
    );
    for i in 0..4 {
        assert_eq!(sim.committed[i][0].block, sim.committed[0][0].block);
    }
    // It was not the silent validator's block, and a later proposer's
    // reveal made the seed.
    let seed = genesis_seed(&sim.config.hash());
    let proposer = expected_proposer(sim.nodes[0].chain(), &seed, 1, round);
    assert_ne!(sim.node_of(&proposer), silent);
}

#[test]
fn a_proposer_whose_clock_is_far_ahead_is_voted_against_and_the_next_round_decides() {
    let fast = first_proposer(4);
    let mut options = Options::new(4);
    options.skew[fast] = 60_000; // a minute ahead of everyone else
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.all_committed(1));

    let round = sim.committed[0][0].certificate.round.as_u32().unwrap();
    assert!(round >= 1, "the fast proposer's round-0 block was rejected");
    // The block that was decided has an honest timestamp.
    assert!(sim.committed[0][0].block.timestamp_millis < GENESIS_TIME + 30_000);
}

#[test]
fn a_clock_five_seconds_ahead_is_tolerated_and_one_millisecond_more_is_not() {
    let fast = first_proposer(4);

    let mut options = Options::new(4);
    options.skew[fast] = 5_000;
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.all_committed(1));
    assert_eq!(
        sim.committed[0][0].certificate.round.as_u32(),
        Some(0),
        "exactly five seconds ahead is accepted"
    );

    let mut options = Options::new(4);
    options.skew[fast] = 5_001;
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.all_committed(1));
    assert!(sim.committed[0][0].certificate.round.as_u32().unwrap() >= 1);
}

#[test]
fn a_signer_that_refuses_halts_its_host_and_the_others_carry_on() {
    let mut options = Options::new(4);
    options.advanced_signers = vec![3]; // node 3's signer is already past height 99
    let mut sim = Sim::new(options);
    sim.run_until(|s| (0..3).all(|i| s.heights_committed(i) >= 2));

    assert!(
        matches!(sim.nodes[3].halted(), Some(HaltReason::SignerRefused(_))),
        "{:?}",
        sim.nodes[3].halted()
    );
    assert!(sim.committed[3].is_empty(), "a halted node commits nothing");
    for i in 0..3 {
        assert!(sim.nodes[i].halted().is_none());
    }
}

/// `who`'s genuine reveal for `height` under `seed`.
fn reveal_by(who: u8, height: BlockHeight, seed: &Hash) -> BlsSignature {
    BlsSignature::from_bytes(
        bls_secret(who)
            .sign(
                &chain_types::beacon::beacon_message(height, seed),
                chain_types::bls::DST_BEACON,
                &[],
            )
            .to_bytes(),
    )
    .unwrap()
}

/// Two networks with the same genesis: what one decided, the other can be
/// shown. `records` are the first `count` decided blocks of `from`.
fn decided(count: usize) -> Vec<CommitRecord> {
    let mut sim = Sim::new(Options::new(4));
    sim.run_until(|s| s.all_committed(count));
    sim.committed[0].iter().map(Committed::record).collect()
}

/// A network whose node `victim` hears no block messages, so it can never
/// judge what the others decide.
fn network_without_blocks_for(victim: usize) -> Sim {
    let mut options = Options::new(4);
    options.filter =
        Box::new(move |_, to, message| !(to == victim && matches!(message, Message::Block(_))));
    Sim::new(options)
}

fn agree(sim: &Sim, count: usize) {
    let reference = sim.nodes[0].chain().head().unwrap();
    for (i, node) in sim.nodes.iter().enumerate() {
        assert!(node.halted().is_none(), "node {i} halted");
        assert!(
            sim.committed[i].len() >= count,
            "node {i} committed too few"
        );
        let head = node.chain().head().unwrap();
        if head.height == reference.height {
            assert_eq!(head, reference, "node {i} is on a different chain");
        }
        node.chain().audit().unwrap();
    }
}

#[test]
fn a_node_that_never_receives_a_block_still_ends_up_with_every_decided_one() {
    let victim = (0..4).find(|i| *i != first_proposer(4)).unwrap();
    let mut sim = network_without_blocks_for(victim);
    sim.run_until(|s| s.all_committed(4));
    agree(&sim, 4);

    // Not by luck: it never held a block message, so every block it has, it
    // got by asking, and it checked each one.
    assert!(sim.committed[victim]
        .iter()
        .all(|c| c.certificate.commit_signatures.len() >= 3));
}

#[test]
fn a_node_cut_off_for_many_heights_catches_up_in_one_go_when_reconnected() {
    let healed = Rc::new(Cell::new(false));
    let flag = healed.clone();
    let mut options = Options::new(4);
    options.filter = Box::new(move |_, to, _| to != 3 || flag.get());
    let mut sim = Sim::new(options);
    sim.run_until(|s| (0..3).all(|i| s.heights_committed(i) >= 6));
    assert_eq!(sim.nodes[3].chain().head().unwrap().height, BlockHeight(0));

    healed.set(true);
    sim.run_until(|s| s.heights_committed(3) >= 6);
    let target = sim.nodes[0].chain().head().unwrap().height;
    sim.run_until(|s| s.nodes[3].chain().head().unwrap().height >= target);
    agree(&sim, 6);
    assert_eq!(sim.nodes[3].seed(), sim.nodes[0].seed());
}

#[test]
fn a_network_that_is_keeping_up_never_asks_anyone_for_anything() {
    let asked = Rc::new(Cell::new(0usize));
    let counter = asked.clone();
    let mut options = Options::new(4);
    options.filter = Box::new(move |_, _, message| {
        if matches!(message, Message::SyncRequest(_)) {
            counter.set(counter.get() + 1);
        }
        true
    });
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.all_committed(6));
    assert_eq!(asked.get(), 0);
}

#[test]
fn a_peer_that_will_not_answer_does_not_hold_up_a_node_that_is_behind() {
    // Node 3 hears no blocks, and the first peer it asks stays silent.
    let victim = 3;
    let silent: Rc<Cell<Option<usize>>> = Rc::new(Cell::new(None));
    let who = silent.clone();
    let mut options = Options::new(4);
    options.filter = Box::new(move |from, to, message| match message {
        Message::Block(_) => to != victim,
        Message::SyncRequest(_) => {
            if who.get().is_none() {
                who.set(Some(to));
            }
            true
        }
        Message::SyncResponse(_) => Some(from) != who.get(),
        _ => true,
    });
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.heights_committed(victim) >= 3);
    assert!(silent.get().is_some());
    agree(&sim, 3);
}

// ---- what a node will and will not adopt ----------------------------------------

/// A fresh network in which nobody has decided anything, and node 0's
/// address — the one every reply here is for.
fn fresh() -> (Sim, Address) {
    (Sim::new(Options::new(4)), operator_address(1))
}

fn response(requester: Address, commits: Vec<CommitRecord>) -> Message {
    Message::SyncResponse(SyncResponse { requester, commits })
}

fn untouched(sim: &Sim) {
    assert_eq!(sim.nodes[0].chain().head().unwrap().height, BlockHeight(0));
    assert!(sim.nodes[0].halted().is_none());
}

#[test]
fn a_proven_answer_is_adopted_and_the_node_carries_on_from_there() {
    let records = decided(3);
    let (mut sim, me) = fresh();
    sim.nodes[0].handle_message(response(me, records.clone()));
    assert_eq!(sim.nodes[0].chain().head().unwrap().height, BlockHeight(3));
    assert_eq!(sim.nodes[0].height(), BlockHeight(4));
    assert!(sim.nodes[0].halted().is_none());
    // The seed is the one three reveals lead to.
    let mut seed = genesis_seed(&sim.config.hash());
    for record in &records {
        seed = next_seed(&seed, &record.reveal);
    }
    assert_eq!(sim.nodes[0].seed(), &seed);
}

#[test]
fn an_answer_meant_for_someone_else_is_ignored() {
    let records = decided(1);
    let (mut sim, _) = fresh();
    sim.nodes[0].handle_message(response(operator_address(2), records));
    untouched(&sim);
}

#[test]
fn a_block_with_no_certificate_for_it_is_not_adopted() {
    let mut records = decided(2);
    // The certificate is for height 1's block; this is height 2's.
    records[1].certificate = records[0].certificate.clone();
    let (mut sim, me) = fresh();
    sim.nodes[0].handle_message(response(me, vec![records[0].clone(), records[1].clone()]));
    // The first was fine and stands; the second was refused.
    assert_eq!(sim.nodes[0].chain().head().unwrap().height, BlockHeight(1));
    assert!(sim.nodes[0].halted().is_none());
}

#[test]
fn a_certificate_short_of_a_quorum_is_not_adopted() {
    let mut records = decided(1);
    records[0].certificate.commit_signatures.truncate(2);
    let (mut sim, me) = fresh();
    sim.nodes[0].handle_message(response(me, records));
    untouched(&sim);
}

#[test]
fn a_certificate_with_a_forged_signature_is_not_adopted() {
    let mut records = decided(1);
    let stolen = records[0].certificate.commit_signatures[1].signature;
    records[0].certificate.commit_signatures[0].signature = stolen;
    let (mut sim, me) = fresh();
    sim.nodes[0].handle_message(response(me, records));
    untouched(&sim);
}

#[test]
fn a_block_swapped_under_a_genuine_certificate_is_not_adopted() {
    let mut records = decided(1);
    records[0].block.timestamp_millis += 1;
    let (mut sim, me) = fresh();
    sim.nodes[0].handle_message(response(me, records));
    untouched(&sim);
}

#[test]
fn a_reveal_that_is_not_the_proposers_is_not_adopted() {
    let mut records = decided(1);
    // Another validator's genuine reveal for this height and seed: it would
    // steer the next seed while every certificate still checks out.
    let (mut sim, me) = fresh();
    let seed = genesis_seed(&sim.config.hash());
    let round = records[0].certificate.round.as_u32().unwrap();
    let real = expected_proposer(sim.nodes[0].chain(), &seed, 1, round);
    let other = (1..=4).find(|n| operator_address(*n) != real).unwrap();
    records[0].reveal = reveal_by(other, BlockHeight(1), &seed);
    sim.nodes[0].handle_message(response(me, records));
    untouched(&sim);
}

#[test]
fn an_answer_that_skips_a_height_is_not_adopted() {
    let records = decided(2);
    let (mut sim, me) = fresh();
    sim.nodes[0].handle_message(response(me, vec![records[1].clone()]));
    untouched(&sim);
}

#[test]
fn what_a_node_already_has_is_skipped_not_reapplied() {
    let records = decided(2);
    let (mut sim, me) = fresh();
    sim.nodes[0].handle_message(response(me, vec![records[0].clone()]));
    sim.nodes[0].handle_message(response(me, records));
    assert_eq!(sim.nodes[0].chain().head().unwrap().height, BlockHeight(2));
    assert!(sim.nodes[0].halted().is_none());
}

#[test]
fn a_node_on_another_chain_halts_when_shown_what_the_network_decided() {
    // Node 3 started from a different genesis. It is not silently stuck: it
    // notices the network moving on, asks, is shown a decision certified by
    // a quorum that does not extend its chain, and stops.
    let mut options = Options::new(4);
    options.divergent = vec![3];
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.nodes[3].halted().is_some());

    assert!(matches!(
        sim.nodes[3].halted(),
        Some(HaltReason::CannotCommit { height }) if *height == BlockHeight(1)
    ));
    assert!(sim.committed[3].is_empty());
    assert_eq!(sim.nodes[3].chain().head().unwrap().height, BlockHeight(0));
}

// ---- serving -----------------------------------------------------------------------

#[test]
fn a_node_serves_what_it_decided_to_a_validator_that_asks() {
    let mut sim = Sim::new(Options::new(4));
    sim.run_until(|s| s.all_committed(3));
    sim.nodes[1].handle_message(Message::SyncRequest(SyncRequest {
        requester: operator_address(4),
        from: BlockHeight(2),
    }));
    let outbox = sim.nodes[1].take_outbox();
    let [(to, Message::SyncResponse(answer))] = outbox.directed.as_slice() else {
        panic!("expected exactly one answer, got {:?}", outbox.directed);
    };
    assert_eq!(*to, operator_address(4));
    let heights: Vec<u64> = answer.commits.iter().map(|c| c.block.height.0).collect();
    assert!(heights.starts_with(&[2, 3]), "{heights:?}");
    assert!(heights.windows(2).all(|w| w[1] == w[0] + 1));
}

#[test]
fn an_answer_is_capped_at_the_configured_batch() {
    let mut options = Options::new(4);
    options.host.sync_batch = 2;
    let mut sim = Sim::new(options);
    sim.run_until(|s| s.all_committed(4));
    sim.nodes[1].handle_message(Message::SyncRequest(SyncRequest {
        requester: operator_address(4),
        from: BlockHeight(1),
    }));
    let outbox = sim.nodes[1].take_outbox();
    let [(_, Message::SyncResponse(answer))] = outbox.directed.as_slice() else {
        panic!("expected one answer");
    };
    assert_eq!(answer.commits.len(), 2);
}

#[test]
fn a_request_from_a_stranger_or_for_a_height_not_yet_decided_gets_no_answer() {
    let mut sim = Sim::new(Options::new(4));
    sim.run_until(|s| s.all_committed(3));
    for request in [
        SyncRequest {
            requester: operator_address(77),
            from: BlockHeight(1),
        },
        SyncRequest {
            requester: operator_address(4),
            from: BlockHeight(1_000),
        },
    ] {
        sim.nodes[1].handle_message(Message::SyncRequest(request));
        assert!(sim.nodes[1].take_outbox().directed.is_empty());
    }
}

#[test]
fn a_forged_reveal_in_the_real_proposers_name_cannot_steer_the_seed() {
    // Before anything else happens, every node is handed a block message
    // naming the true proposer of height 1 with a reveal that is not theirs.
    // Were it kept, it would stand in for the proposer's real reveal and the
    // next seed — and with it every later proposer — would be the forger's
    // to choose.
    let mut sim = Sim::new(Options::new(4));
    let proposer = first_proposer(4);
    let forged = Message::Block(chain_consensus::host::ProposedBlock {
        proposer: operator_address(u8::try_from(proposer).unwrap() + 1),
        block: Block {
            parent_block_hash: sim.config.hash(),
            height: BlockHeight(1),
            timestamp_millis: GENESIS_TIME + 500,
            transactions: Vec::new(),
        },
        reveal: BlsSignature::from_bytes(
            bls_secret(9)
                .sign(b"not a reveal", chain_types::bls::DST_BEACON, &[])
                .to_bytes(),
        )
        .unwrap(),
    });
    for node in &mut sim.nodes {
        node.handle_message(forged.clone());
    }
    sim.run_until(|s| s.all_committed(2));

    let seed = genesis_seed(&sim.config.hash());
    let key = bls_public(u8::try_from(proposer).unwrap() + 1);
    for committed in sim.committed.iter().map(|c| &c[0]) {
        verify_reveal(&key, BlockHeight(1), &seed, &committed.reveal).unwrap();
    }
    let first = sim.committed[0][1].seed_after;
    for i in 0..4 {
        assert!(sim.nodes[i].halted().is_none());
        assert_eq!(sim.committed[i][1].seed_after, first, "node {i} agrees");
    }
}

#[test]
fn a_witnessed_double_vote_comes_out_as_evidence_that_convicts_the_offender() {
    let mut sim = Sim::new(Options::new(4));
    // Validator 4 (node 3) signs two conflicting prevotes for height 1,
    // round 0, and node 0 sees both before anything else happens.
    let vote = |value: u8| {
        let vote = chain_consensus::types::ConsensusVote {
            height: ConsensusHeight(BlockHeight(1)),
            round: malachite_core_types::Round::new(0),
            value_id: malachite_core_types::NilOrVal::Val(Hash::from_bytes([value; 32])),
            vote_type: malachite_core_types::VoteType::Prevote,
            validator_address: ConsensusAddress(operator_address(4)),
            extension: None,
        };
        let mut bytes = Vec::new();
        vote.encode(&mut bytes);
        let signature = BlsSignature::from_bytes(
            bls_secret(4)
                .sign(&bytes, chain_types::bls::DST_VOTE, &[])
                .to_bytes(),
        )
        .unwrap();
        Message::Consensus(malachite_core_consensus::SignedConsensusMsg::Vote(
            malachite_core_types::SignedVote::new(vote, signature),
        ))
    };
    sim.nodes[0].handle_message(vote(1));
    sim.nodes[0].handle_message(vote(2));

    sim.run_until(|s| s.all_committed(1) && !s.evidence[0].is_empty());
    let evidence = &sim.evidence[0][0];
    assert_eq!(evidence.validator(), operator_address(4));
    evidence.verify(&bls_public(4)).unwrap();
}

// ---- noticing that the network has moved on ------------------------------------------

/// A prevote for `height`, round 0, in `voter`'s name, signed with `key`'s
/// secret — which is the voter's own unless it is a forgery.
fn prevote_at(height: u64, voter: u8, key: u8) -> Message {
    let vote = chain_consensus::types::ConsensusVote {
        height: ConsensusHeight(BlockHeight(height)),
        round: malachite_core_types::Round::new(0),
        value_id: malachite_core_types::NilOrVal::Nil,
        vote_type: malachite_core_types::VoteType::Prevote,
        validator_address: ConsensusAddress(operator_address(voter)),
        extension: None,
    };
    let mut bytes = Vec::new();
    vote.encode(&mut bytes);
    let signature = BlsSignature::from_bytes(
        bls_secret(key)
            .sign(&bytes, chain_types::bls::DST_VOTE, &[])
            .to_bytes(),
    )
    .unwrap();
    Message::Consensus(malachite_core_consensus::SignedConsensusMsg::Vote(
        malachite_core_types::SignedVote::new(vote, signature),
    ))
}

/// What node 0 has been asked to send to one peer since last looked.
fn requests(sim: &mut Sim) -> Vec<(Address, SyncRequest)> {
    sim.nodes[0]
        .take_outbox()
        .directed
        .into_iter()
        .filter_map(|(to, message)| match message {
            Message::SyncRequest(request) => Some((to, request)),
            _ => None,
        })
        .collect()
}

const GRACE: u64 = 1_000;
const RETRY: u64 = 3_000;

#[test]
fn a_node_seeing_a_peer_ahead_waits_out_the_grace_then_asks_that_peer() {
    let (mut sim, me) = fresh();
    let seen = sim.now;
    sim.nodes[0].handle_message(prevote_at(3, 2, 2));
    assert!(requests(&mut sim).is_empty(), "not at once");
    assert_eq!(sim.nodes[0].next_wake_ms(), Some(seen + GRACE));

    sim.set_time(seen + GRACE - 1);
    sim.nodes[0].tick();
    assert!(requests(&mut sim).is_empty(), "not a moment before");

    sim.set_time(seen + GRACE);
    sim.nodes[0].tick();
    assert_eq!(
        requests(&mut sim),
        vec![(
            operator_address(2),
            SyncRequest {
                requester: me,
                from: BlockHeight(1)
            }
        )]
    );
    // And not again until the retry.
    sim.nodes[0].tick();
    assert!(requests(&mut sim).is_empty());
    assert_eq!(sim.nodes[0].next_wake_ms(), Some(seen + GRACE + RETRY));
}

#[test]
fn a_retry_goes_to_a_different_peer_than_the_last_request() {
    let (mut sim, _) = fresh();
    let seen = sim.now;
    sim.nodes[0].handle_message(prevote_at(3, 2, 2));
    sim.nodes[0].handle_message(prevote_at(3, 3, 3));
    sim.set_time(seen + GRACE);
    sim.nodes[0].tick();
    let first = requests(&mut sim);
    sim.set_time(seen + GRACE + RETRY - 1);
    sim.nodes[0].tick();
    assert!(requests(&mut sim).is_empty(), "not before the retry");
    sim.set_time(seen + GRACE + RETRY);
    sim.nodes[0].tick();
    let second = requests(&mut sim);
    assert_eq!((first.len(), second.len()), (1, 1));
    assert_ne!(first[0].0, second[0].0);
}

#[test]
fn a_vote_from_a_peer_ahead_is_not_believed_unless_its_signature_is_genuine() {
    let (mut sim, _) = fresh();
    // In validator 2's name, signed by validator 3; and in a stranger's name.
    sim.nodes[0].handle_message(prevote_at(3, 2, 3));
    sim.nodes[0].handle_message(prevote_at(3, 77, 77));
    let now = sim.now;
    assert_eq!(sim.nodes[0].next_wake_ms(), None);
    sim.set_time(now + 10 * GRACE);
    sim.nodes[0].tick();
    assert!(requests(&mut sim).is_empty());
}

#[test]
fn a_peer_at_the_nodes_own_height_is_not_ahead() {
    let (mut sim, _) = fresh();
    sim.nodes[0].handle_message(prevote_at(1, 2, 2));
    assert_eq!(sim.nodes[0].next_wake_ms(), None);
}

#[test]
fn catching_up_ends_the_episode_and_the_next_one_starts_its_own_clock() {
    let records = decided(3);
    let (mut sim, me) = fresh();
    let start = sim.now;

    // Behind, asks, and is answered.
    sim.nodes[0].handle_message(prevote_at(3, 2, 2));
    sim.set_time(start + GRACE);
    sim.nodes[0].tick();
    assert_eq!(requests(&mut sim).len(), 1);
    sim.set_time(start + GRACE + 10);
    sim.nodes[0].handle_message(response(me, records));
    let outbox = sim.nodes[0].take_outbox();
    assert!(
        outbox
            .timers
            .contains(&chain_consensus::host::TimerCommand::CancelAll),
        "the stuck height's timers are cancelled"
    );
    assert_eq!(sim.nodes[0].next_wake_ms(), None, "no longer behind");

    // Behind again, later: the grace runs from now, and the earlier request
    // does not hold up the next.
    let later = start + GRACE + 20;
    sim.set_time(later);
    sim.nodes[0].handle_message(prevote_at(9, 2, 2));
    assert_eq!(sim.nodes[0].next_wake_ms(), Some(later + GRACE));
    sim.set_time(later + GRACE);
    sim.nodes[0].tick();
    assert_eq!(requests(&mut sim).len(), 1);
}

#[test]
fn the_grace_runs_from_the_first_sighting_not_the_latest() {
    let (mut sim, _) = fresh();
    let first = sim.now;
    sim.nodes[0].handle_message(prevote_at(3, 2, 2));
    sim.set_time(first + 400);
    sim.nodes[0].handle_message(prevote_at(3, 3, 3));
    assert_eq!(sim.nodes[0].next_wake_ms(), Some(first + GRACE));
}

// ---- restarts --------------------------------------------------------------------------

impl Sim {
    /// Runs until `done`, giving up (with `false`) if the network goes quiet
    /// or `max` things have happened.
    fn try_run(&mut self, done: impl Fn(&Sim) -> bool, max: usize) -> bool {
        for _ in 0..max {
            for i in 0..self.n() {
                self.drain(i);
            }
            if done(self) {
                return true;
            }
            if self.step().is_none() {
                return false;
            }
        }
        false
    }

    /// What node `i` has in its write-ahead log for `height`.
    fn wal(&self, i: usize, height: u64) -> Vec<Vec<u8>> {
        use chain_consensus::host::Wal as _;
        self.disks[i]
            .storage
            .inner
            .borrow_mut()
            .start_height(BlockHeight(height))
            .unwrap()
    }
}

/// How many events each node handles in an undisturbed run to `heights`.
fn events_to_commit(heights: usize) -> Vec<usize> {
    let mut sim = Sim::new(Options::new(4));
    sim.run_until(|s| s.all_committed(heights));
    sim.events
}

#[test]
fn a_node_that_crashes_at_any_moment_comes_back_without_halting_or_disagreeing() {
    // Restart each node in turn right after each of the events it handles —
    // messages, timers — with everything it had just produced lost, and let
    // the network carry on. However it is cut off, it must come back to the
    // same place as the others: its log gives it back what it had locked and
    // seen, and its signer's record makes every re-signed message the one it
    // signed before.
    let events = events_to_commit(3);
    // One thread per node: each builds its own networks, so nothing is
    // shared between them.
    let handles: Vec<_> = (0..4)
        .map(|node| {
            let count = events[node];
            std::thread::spawn(move || {
                let mut restarts = 0;
                for at in 1..=count {
                    let mut options = Options::new(4);
                    options.crash_at = Some((node, at));
                    let mut sim = Sim::new(options);
                    sim.run_until(|s| s.all_committed(3));
                    restarts += sim.restarts;
                    for (i, host) in sim.nodes.iter().enumerate() {
                        assert!(
                            host.halted().is_none(),
                            "node {i} halted ({:?}) after node {node} restarted at its event {at}",
                            host.halted()
                        );
                    }
                    assert!(
                        sim.evidence.iter().all(Vec::is_empty),
                        "an equivocation was witnessed after node {node} restarted at event {at}"
                    );
                    agree(&sim, 3);
                }
                restarts
            })
        })
        .collect();
    let restarts: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    // Every crash point was reached: the run up to it is the undisturbed one.
    assert_eq!(restarts, events.iter().sum::<usize>());
}

#[test]
fn without_a_log_a_restart_leaves_a_node_stuck_or_halted() {
    // The same sweep with a log that comes back empty. The signer still
    // keeps the node from signing twice, so what it costs is the node: at
    // some moments a restart finds it asked to sign something different from
    // what it signed before, and it stops. That is the log earning its keep.
    let events = events_to_commit(3);
    let mut casualties = 0;
    'sweep: for (node, count) in events.iter().copied().enumerate() {
        for at in 1..=count {
            let mut options = Options::new(4);
            options.forgetful = true;
            options.crash_at = Some((node, at));
            let mut sim = Sim::new(options);
            let finished = sim.try_run(|s| s.all_committed(3), 1_500);
            let halted = sim.nodes.iter().any(|h| h.halted().is_some());
            if halted || !finished {
                casualties += 1;
                break 'sweep;
            }
        }
    }
    assert!(casualties > 0, "no restart without a log did any harm");
}

#[test]
fn a_restarted_proposer_proposes_the_block_it_had_already_proposed() {
    let proposer = first_proposer(4);
    let mut sim = Sim::new(Options::new(4));
    let sent = |outbox: chain_consensus::host::Outbox| -> Vec<Vec<u8>> {
        outbox
            .messages
            .iter()
            .filter(|m| {
                matches!(
                    m,
                    Message::Block(_)
                        | Message::Consensus(
                            malachite_core_consensus::SignedConsensusMsg::Proposal(_)
                        )
                )
            })
            .map(encode_message)
            .collect()
    };
    let before = sent(sim.nodes[proposer].take_outbox());
    assert_eq!(before.len(), 2, "a block and a proposal");

    // Later, a block built now would carry a later timestamp and be another
    // block altogether.
    sim.set_time(sim.now + 700);
    sim.restart(proposer);
    let after = sent(sim.nodes[proposer].take_outbox());
    assert_eq!(after, before);
}

#[test]
fn a_vote_against_a_block_is_not_reversed_by_a_restart_with_a_later_clock() {
    // The proposer's clock is a minute ahead, so a node that has seen its
    // block votes nil. Restarted with a clock that has caught up, the same
    // block would look fine: the node must still vote nil, since it has
    // signed that, and the log is what remembers why.
    let fast = first_proposer(4);
    let victim = (0..4).find(|i| *i != fast).unwrap();
    let mut options = Options::new(4);
    options.skew[fast] = 60_000;
    let mut sim = Sim::new(options);
    let judged_invalid = |sim: &Sim| {
        sim.wal(victim, 1)
            .iter()
            .any(|entry| entry.first() == Some(&3))
    };
    for _ in 0..1_000 {
        if judged_invalid(&sim) {
            break;
        }
        assert!(sim.step().is_some());
    }
    assert!(
        judged_invalid(&sim),
        "the victim never judged the block invalid"
    );

    sim.skew[victim] += 61_000;
    sim.set_time(sim.now);
    sim.restart(victim);
    sim.run_until(|s| s.all_committed(2));
    assert!(sim.nodes[victim].halted().is_none());
    agree(&sim, 2);
}

#[test]
fn a_node_that_crashes_while_catching_up_still_catches_up() {
    // The starved node again — every block it ever gets it gets by asking —
    // restarted at each point of the run: mid-request, mid-answer, between
    // two adopted blocks.
    let victim = (0..4).find(|i| *i != first_proposer(4)).unwrap();
    let starved = move |crash_at: Option<(usize, usize)>| {
        let mut options = Options::new(4);
        options.filter =
            Box::new(move |_, to, message| !(to == victim && matches!(message, Message::Block(_))));
        options.crash_at = crash_at;
        Sim::new(options)
    };
    let mut baseline = starved(None);
    baseline.run_until(|s| s.all_committed(3));
    let total = baseline.events[victim];

    let handles: Vec<_> = (0..4)
        .map(|lane| {
            std::thread::spawn(move || {
                for at in (1..=total).filter(|at| at % 4 == lane) {
                    let mut sim = starved(Some((victim, at)));
                    let finished = sim.try_run(|s| s.all_committed(3), 5_000);
                    let halted: Vec<_> = sim.nodes.iter().map(|h| h.halted().cloned()).collect();
                    assert!(
                        finished,
                        "stuck after restarting at {at}: halted {halted:?}, committed {:?}",
                        sim.committed.iter().map(Vec::len).collect::<Vec<_>>()
                    );
                    assert!(halted.iter().all(Option::is_none), "at {at}: {halted:?}");
                    agree(&sim, 3);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn a_node_that_only_ever_gets_blocks_by_asking_keeps_up_for_many_heights() {
    // Over enough heights a round goes past 0 and a block is re-proposed by
    // someone else — whose reveal never reaches a node that hears no block
    // messages. The engine decides; the node cannot commit from what it
    // holds, and must ask for the block rather than stop.
    let victim = (0..4).find(|i| *i != first_proposer(4)).unwrap();
    let mut sim = network_without_blocks_for(victim);
    assert!(sim.try_run(|s| s.all_committed(12), 20_000));
    agree(&sim, 12);
    // A decision the node could not commit did not restart its height: each
    // height was started once, and stayed open until the answer closed it.
    assert!(sim.height_starts.values().all(|starts| *starts == 1));
}

#[test]
fn a_timeout_that_fired_before_a_restart_fires_again_in_the_replay() {
    // A node whose propose timer fires votes nil for the round, and signs
    // that. The proposal arrives late, and the node hears it. If a restart
    // replayed the proposal but not the timeout, the node would find itself
    // still waiting for a proposal, see one, and vote for it: two different
    // votes for the same round.
    let proposer = first_proposer(4);
    let node = (0..4).find(|i| *i != proposer).unwrap();
    let mut sim = Sim::new(Options::new(4));
    sim.nodes[node].handle_timeout(Timeout::propose(malachite_core_types::Round::new(0)));
    for _ in 0..1_000 {
        if sim.events[node] >= 3 {
            break;
        }
        assert!(sim.step().is_some());
    }
    assert!(sim.events[node] >= 3, "the late proposal was heard");

    sim.restart(node);
    sim.run_until(|s| s.all_committed(2));
    assert!(
        sim.nodes[node].halted().is_none(),
        "{:?}",
        sim.nodes[node].halted()
    );
    agree(&sim, 2);
}
