use std::cell::RefCell;
use std::time::Duration;

use blst::min_pk::SecretKey;
use chain_engine_api::{BlockLimits, Engine, ExecutedBlock, GENESIS_MAX_BLOCK_GAS};
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_exec::native::{
    GOVERNANCE_MODULE_NAME, GOVERNANCE_PACKAGE_ADDRESS, REGISTER_VALIDATOR, STAKE,
    STAKING_MODULE_NAME, STAKING_PACKAGE_ADDRESS, SUBMIT_EVIDENCE, SUBMIT_PROPOSAL, UNJAIL,
    UNSTAKE, VOTE,
};
use chain_exec::Executor;
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_state::{apply, compute_root};
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::{
    Address, BlockHeight, BlsPublicKey, ChainId, Encode, GasAmount, GasPrice, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};

const VALIDATOR_SEED: u8 = 1;
const SENDER_SEED: u8 = 9;
const GAS_LIMIT: u64 = 10_000;

thread_local! {
    static EXECUTOR: RefCell<Executor> = RefCell::new(executor());
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(seed: u8) -> PublicKey {
    PublicKey::from_ed25519_bytes(signing_key(seed).verifying_key().to_bytes())
        .unwrap_or_else(|error| panic!("fixed Ed25519 key is invalid: {error}"))
}

fn validator() -> GenesisValidator {
    let secret = SecretKey::key_gen(&[VALIDATOR_SEED; 32], &[])
        .unwrap_or_else(|error| panic!("fixed BLS key is invalid: {error:?}"));
    let consensus_key = BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes())
        .unwrap_or_else(|error| panic!("fixed BLS public key is invalid: {error}"));
    let proof_of_possession = BlsSignature::from_bytes(
        secret
            .sign(&consensus_key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("fixed BLS proof is invalid: {error}"));
    GenesisValidator {
        operator: public_key(VALIDATOR_SEED),
        consensus_key,
        proof_of_possession,
        self_stake: GENESIS_PARAM_VALUES.min_self_stake,
    }
}

fn executor() -> Executor {
    let config = GenesisConfig::new(
        ChainId(1),
        1_700_000_000_000,
        GENESIS_PARAM_VALUES,
        vec![Allocation {
            owner: public_key(SENDER_SEED),
            amount: 1_000_000_000_000_000,
        }],
        vec![validator()],
    )
    .unwrap_or_else(|error| panic!("fixed fuzz genesis is invalid: {error}"));
    Executor::from_genesis(&config)
        .unwrap_or_else(|error| panic!("fixed fuzz executor failed to start: {error}"))
}

fn bcs_bytes(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len().min(127);
    let mut encoded = vec![u8::try_from(len).unwrap_or(127)];
    encoded.extend_from_slice(bytes.get(..len).unwrap_or_default());
    encoded
}

fn u128_from(input: &[u8]) -> u128 {
    let mut bytes = [0u8; 16];
    for (to, from) in bytes.iter_mut().zip(input.iter().copied()) {
        *to = from;
    }
    u128::from_le_bytes(bytes)
}

fn call(input: &[u8]) -> MoveCall {
    let selector = input.first().copied().unwrap_or(0) % 7;
    let payload = input.get(1..).unwrap_or_default();
    let validator_address = Address::from_public_key(&public_key(VALIDATOR_SEED));
    let amount = u128_from(payload) % 1_000_000;

    let (package, module, function, arguments) = match selector {
        0 => {
            let seed = payload.first().copied().unwrap_or(2).max(1);
            let secret = SecretKey::key_gen(&[seed; 32], &[])
                .unwrap_or_else(|error| panic!("generated BLS key is invalid: {error:?}"));
            let key = BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes())
                .unwrap_or_else(|error| panic!("generated BLS public key is invalid: {error}"));
            let pop = secret.sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[]);
            (
                STAKING_PACKAGE_ADDRESS,
                STAKING_MODULE_NAME,
                REGISTER_VALIDATOR,
                vec![
                    key.to_bytes().to_vec(),
                    pop.to_bytes().to_vec(),
                    GENESIS_PARAM_VALUES.min_self_stake.to_le_bytes().to_vec(),
                ],
            )
        }
        1 => (
            STAKING_PACKAGE_ADDRESS,
            STAKING_MODULE_NAME,
            STAKE,
            vec![
                validator_address.as_bytes().to_vec(),
                amount.to_le_bytes().to_vec(),
            ],
        ),
        2 => (
            STAKING_PACKAGE_ADDRESS,
            STAKING_MODULE_NAME,
            UNSTAKE,
            vec![
                validator_address.as_bytes().to_vec(),
                amount.to_le_bytes().to_vec(),
            ],
        ),
        3 => (
            STAKING_PACKAGE_ADDRESS,
            STAKING_MODULE_NAME,
            UNJAIL,
            Vec::new(),
        ),
        4 => (
            STAKING_PACKAGE_ADDRESS,
            STAKING_MODULE_NAME,
            SUBMIT_EVIDENCE,
            vec![bcs_bytes(payload)],
        ),
        5 => (
            GOVERNANCE_PACKAGE_ADDRESS,
            GOVERNANCE_MODULE_NAME,
            SUBMIT_PROPOSAL,
            vec![bcs_bytes(payload)],
        ),
        _ => (
            GOVERNANCE_PACKAGE_ADDRESS,
            GOVERNANCE_MODULE_NAME,
            VOTE,
            vec![
                u64::from(selector).to_le_bytes().to_vec(),
                vec![payload.first().copied().unwrap_or(0) % 3],
            ],
        ),
    };

    MoveCall {
        module_address: Address::from_bytes(package),
        module_name: module.as_bytes().to_vec(),
        function_name: function.as_bytes().to_vec(),
        type_arguments: Vec::new(),
        arguments,
    }
}

fn transaction(input: &[u8]) -> Transaction {
    let key = signing_key(SENDER_SEED);
    let body = TransactionBody {
        chain_id: ChainId(1),
        sender: public_key(SENDER_SEED),
        sequence_number: SequenceNumber(0),
        expiry: BlockHeight(7_000),
        gas_limit: GasAmount(GAS_LIMIT),
        max_fee_per_gas: GasPrice(10),
        declared_inputs: Vec::new(),
        call: call(input),
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    Transaction {
        body,
        signature: Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes()),
    }
}

pub fn execute(input: &[u8]) -> (ExecutedBlock, Duration) {
    EXECUTOR.with(|cell| {
        let executor = cell.borrow();
        let parent_root = executor.state_root();
        let block = executor.propose_block(
            executor.tip_block_hash(),
            parent_root,
            BlockHeight(1),
            1_700_000_001_000,
            vec![transaction(input)],
            BlockLimits {
                max_gas: GENESIS_MAX_BLOCK_GAS,
                max_size_bytes: chain_engine_api::MAX_BLOCK_SIZE_BYTES,
            },
        );
        assert_eq!(
            block.transactions.len(),
            1,
            "constructed call was not proposed"
        );
        let start = std::time::Instant::now();
        let executed = executor
            .execute_block(parent_root, &block)
            .unwrap_or_else(|error| {
                panic!("constructed protocol call rejected its block: {error:?}")
            });
        let elapsed = start.elapsed();
        let mut incremental = executor
            .state_entries()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        apply(&mut incremental, &executed.state_diff);
        assert_eq!(
            compute_root(&incremental),
            executed.state_root,
            "incremental StateDiff application diverged from full execution"
        );
        (executed, elapsed)
    })
}
