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
    Clock, Committed, HaltReason, Host, HostConfig, MemorySignedLog, Message, Ports, TimerCommand,
    TransactionSource,
};
use chain_consensus::types::{ConsensusAddress, ConsensusHeight, ConsensusValidatorSet};
use chain_engine_api::{Block, ChainView};
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_exec::native::{STAKE, STAKING_MODULE_NAME, STAKING_PACKAGE_ADDRESS};
use chain_exec::Executor;
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_signer::{HighWaterMark, InMemoryStore, Signer, Step};
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

type TestHost = Host<Executor, SharedSource, SimClock, InMemoryStore, MemorySignedLog>;

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
}

impl Options {
    fn new(n: usize) -> Self {
        Self {
            stakes: vec![MIN; n],
            skew: vec![0; n],
            advanced_signers: Vec::new(),
            divergent: Vec::new(),
            filter: Box::new(|_, _, _| true),
        }
    }
}

impl Sim {
    fn new(options: Options) -> Self {
        let n = options.stakes.len();
        let config = config(&options.stakes);
        let start = GENESIS_TIME + 1_000;
        let mut nodes = Vec::new();
        let mut clocks = Vec::new();
        let mut sources = Vec::new();
        for i in 0..n {
            let seed = u8::try_from(i).unwrap() + 1;
            let clock = SimClock(Rc::new(Cell::new(start + options.skew[i])));
            let source = SharedSource::default();
            let mut store = InMemoryStore::new();
            if options.advanced_signers.contains(&i) {
                chain_signer::HighWaterMarkStore::persist(
                    &mut store,
                    HighWaterMark::new(BlockHeight(99), Round(0), Step::Precommit),
                )
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
                Executor::from_genesis(&config).unwrap()
            };
            let host = Host::new(
                HostConfig::default(),
                operator_address(seed),
                executor,
                Ports {
                    source: source.clone(),
                    clock: clock.clone(),
                    signer: Signer::load(bls_secret(seed), store).unwrap(),
                    log: MemorySignedLog::new(),
                },
                genesis_seed(&config.hash()),
            )
            .unwrap();
            nodes.push(host);
            clocks.push(clock);
            sources.push(source);
        }
        let mut sim = Self {
            nodes,
            clocks,
            skew: options.skew,
            sources,
            inbox: VecDeque::new(),
            timers: vec![Vec::new(); n],
            committed: vec![Vec::new(); n],
            evidence: vec![Vec::new(); n],
            filter: options.filter,
            now: start,
            config,
        };
        for node in &mut sim.nodes {
            node.start();
        }
        sim
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
                    self.inbox.push_back((i, to, message.clone()));
                }
            }
        }
        for command in outbox.timers {
            match command {
                TimerCommand::Schedule { timeout, after } => {
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

    /// Runs the network until `done`, panicking if it stalls or runs on.
    fn run_until(&mut self, done: impl Fn(&Sim) -> bool) {
        for _ in 0..200_000 {
            for i in 0..self.n() {
                self.drain(i);
            }
            if done(self) {
                return;
            }
            if let Some((_, to, message)) = self.inbox.pop_front() {
                self.nodes[to].handle_message(message);
                continue;
            }
            // Nothing in flight: the next timer to fire, in time then node
            // order.
            let next = (0..self.n())
                .flat_map(|i| self.timers[i].iter().map(move |(t, due)| (*due, i, *t)))
                .min_by_key(|(due, i, _)| (*due, *i));
            let Some((due, i, timeout)) = next else {
                panic!("the network is idle and nothing is due: a deadlock");
            };
            self.set_time(self.now.max(due));
            self.timers[i].retain(|(t, _)| *t != timeout);
            self.nodes[i].handle_timeout(timeout);
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

#[test]
fn a_node_that_never_receives_the_block_stalls_safely_and_commits_nothing_it_cannot_vouch_for() {
    // A validator that is not the round-0 proposer loses every block message.
    let first = first_proposer(4);
    let victim = (0..4).find(|i| *i != first).unwrap();
    let mut options = Options::new(4);
    options.filter =
        Box::new(move |_, to, message| !(to == victim && matches!(message, Message::Block(_))));
    let mut sim = Sim::new(options);
    let others: Vec<usize> = (0..4).filter(|i| *i != victim).collect();
    sim.run_until(|s| others.iter().all(|i| s.heights_committed(*i) >= 3));

    // It could not judge the block, so it did not vote for it and cannot
    // decide it: it is stuck at the height, not halted and not wrong.
    assert!(sim.nodes[victim].halted().is_none());
    assert!(sim.committed[victim].len() < sim.committed[others[0]].len());
    assert_eq!(
        sim.nodes[victim].chain().head().unwrap().height.0,
        u64::try_from(sim.committed[victim].len()).unwrap(),
        "its chain holds exactly what it committed"
    );
    sim.nodes[victim].chain().audit().unwrap();
}

#[test]
fn a_node_whose_chain_disagrees_with_the_network_never_commits_what_it_rejects() {
    // Node 3 starts from a different genesis state, so it judges every block
    // invalid and votes against it. The other three decide anyway. Node 3
    // holds the blocks and has rejected them: it must not commit them.
    let mut options = Options::new(4);
    options.divergent = vec![3];
    let mut sim = Sim::new(options);
    sim.run_until(|s| (0..3).all(|i| s.heights_committed(i) >= 2));

    assert!(sim.committed[3].is_empty());
    assert_eq!(sim.nodes[3].chain().head().unwrap().height, BlockHeight(0));
    let network_head = sim.nodes[0].chain().head().unwrap().block_hash;
    assert_ne!(
        sim.nodes[3].chain().head().unwrap().block_hash,
        network_head
    );
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
    let offender = 3usize;
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
    let _ = offender;
}
