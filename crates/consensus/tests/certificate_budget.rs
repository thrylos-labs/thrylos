//! Manual performance budget for the deliberately simple certificate format.
//!
//! Run with:
//!
//! ```text
//! cargo test --release -p chain-consensus --test certificate_budget -- --ignored --nocapture
//! ```
//!
//! This is ignored because latency thresholds are meaningful only on named
//! reference hardware. It remains in the tree so every release can repeat the
//! same measurement instead of relying on an anecdotal benchmark.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::unwrap_used
)]

use std::time::{Duration, Instant};

use blst::min_pk::SecretKey;
use chain_consensus::certificate::verify_commit_certificate;
use chain_consensus::context::ThrylosContext;
use chain_consensus::host::CommitRecord;
use chain_consensus::types::{
    ConsensusAddress, ConsensusHeight, ConsensusValidator, ConsensusValidatorSet, ConsensusVote,
};
use chain_consensus::wire::encode_commit_record;
use chain_engine_api::Block;
use chain_types::bls::{BlsSignature, DST_BEACON, DST_VOTE};
use chain_types::{Address, BlockHeight, ChainId, Encode, Hash};

/// The chain the tests' votes are signed for, and their context runs on.
const CHAIN: ChainId = ChainId(1);

use malachite_core_consensus::ThresholdParams;
use malachite_core_types::{CommitCertificate, CommitSignature, NilOrVal, Round, VoteType};

const VALIDATORS: usize = 128;
const WARMUP_RUNS: usize = 10;
const SAMPLES: usize = 100;
const MAX_P99: Duration = Duration::from_millis(200);
const MAX_WIRE_BYTES: usize = 32 * 1024;

fn key(index: usize) -> SecretKey {
    let mut ikm = [0u8; 32];
    let encoded = u64::try_from(index).unwrap().to_le_bytes();
    ikm[..encoded.len()].copy_from_slice(&encoded);
    ikm[31] = 1;
    SecretKey::key_gen(&ikm, &[]).unwrap()
}

fn fixture() -> (
    CommitCertificate<ThrylosContext>,
    ConsensusValidatorSet,
    BlsSignature,
) {
    let height = ConsensusHeight(BlockHeight(1));
    let round = Round::new(0);
    let value = Hash::from_bytes([7u8; 32]);
    let mut validators = Vec::with_capacity(VALIDATORS);
    let mut signatures = Vec::with_capacity(VALIDATORS);
    let mut first_key = None;

    for index in 0..VALIDATORS {
        let secret = key(index);
        if first_key.is_none() {
            first_key = Some(secret.clone());
        }
        let public_key =
            chain_types::BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes()).unwrap();
        let mut address_bytes = [0u8; 32];
        address_bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
        let address = ConsensusAddress(Address::from_bytes(address_bytes));
        validators.push(ConsensusValidator {
            address,
            public_key,
            voting_power: 1,
        });

        let vote = ConsensusVote {
            chain_id: CHAIN,
            height,
            round,
            value_id: NilOrVal::Val(value),
            vote_type: VoteType::Precommit,
            validator_address: address,
            extension: None,
        };
        let mut message = Vec::new();
        vote.encode(&mut message);
        let signature =
            BlsSignature::from_bytes(secret.sign(&message, DST_VOTE, &[]).to_bytes()).unwrap();
        signatures.push(CommitSignature::new(address, signature));
    }

    let reveal_key = first_key.unwrap();
    let reveal =
        BlsSignature::from_bytes(reveal_key.sign(b"budget", DST_BEACON, &[]).to_bytes()).unwrap();
    (
        CommitCertificate {
            height,
            round,
            value_id: value,
            commit_signatures: signatures,
        },
        ConsensusValidatorSet::new(validators),
        reveal,
    )
}

fn percentile(samples: &[Duration], numerator: usize, denominator: usize) -> Duration {
    let scaled = samples.len().saturating_mul(numerator);
    let index = scaled
        .saturating_add(denominator.saturating_sub(1))
        .checked_div(denominator)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(samples.len().saturating_sub(1));
    samples[index]
}

#[test]
#[ignore = "manual measurement: requires named reference hardware"]
fn individual_signatures_at_the_validator_cap() {
    let (certificate, validator_set, reveal) = fixture();
    let params = ThresholdParams::default();

    for _ in 0..WARMUP_RUNS {
        verify_commit_certificate(&certificate, &validator_set, params, CHAIN).unwrap();
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        verify_commit_certificate(&certificate, &validator_set, params, CHAIN).unwrap();
        samples.push(started.elapsed());
    }
    samples.sort_unstable();

    let record = CommitRecord {
        block: Block {
            parent_block_hash: Hash::from_bytes([0u8; 32]),
            height: BlockHeight(1),
            timestamp_millis: 1,
            transactions: Vec::new(),
        },
        certificate,
        reveal,
    };
    let wire_bytes = encode_commit_record(&record).len();
    let p99 = percentile(&samples, 99, 100);

    eprintln!(
        "128-signature certificate: median={:?}, p95={:?}, p99={:?}, encoded commit record={} bytes",
        percentile(&samples, 50, 100),
        percentile(&samples, 95, 100),
        p99,
        wire_bytes,
    );

    assert!(
        p99 <= MAX_P99,
        "certificate verification p99 {p99:?} exceeds {MAX_P99:?}"
    );
    assert!(
        wire_bytes <= MAX_WIRE_BYTES,
        "encoded commit record {wire_bytes} bytes exceeds {MAX_WIRE_BYTES} bytes"
    );
}
