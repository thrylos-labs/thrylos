//! Helpers shared by the publish and entry-call tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::io::Write;

use chain_engine_api::{AbortReason, Block, BlockLimits, Engine, TransactionOutcome};
use chain_exec::keys::package_key;
use chain_exec::publish::{package_address, MOVE_MODULE_NAME, MOVE_PACKAGE_ADDRESS, PUBLISH};
use chain_exec::Executor;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};
use move_compiler::Compiler;

pub const START_MS: u64 = 1_700_000_000_000;
pub const MAX_FEE: u64 = 10;
pub const PUBLISH_GAS: u64 = 200_000;

/// Compile `source` (modules written against the address `0x0`) to bytes,
/// one entry per module, keyed by module name.
pub fn compile(source: &str) -> BTreeMap<String, Vec<u8>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("package.move");
    writeln!(std::fs::File::create(&path).unwrap(), "{source}").unwrap();
    let (_, units) = Compiler::from_files(
        None,
        vec![path.to_str().unwrap().to_string()],
        vec![],
        BTreeMap::<String, move_compiler::shared::NumericalAddress>::new(),
    )
    .build_and_report()
    .expect("the test source compiles");
    units
        .into_iter()
        .map(|unit| {
            let module = unit.named_module.module;
            let mut bytes = Vec::new();
            module
                .serialize_with_version(module.version, &mut bytes)
                .unwrap();
            (module.self_id().name().to_string(), bytes)
        })
        .collect()
}

pub const ONE_MODULE: &str = "module 0x0::hello { public fun answer(): u64 { 42 } }";
pub const TWO_MODULES: &str = "
    module 0x0::first { public fun one(): u64 { 1 } }
    module 0x0::second { public fun two(): u64 { 0x0::first::one() + 1 } }
";

pub struct Publisher {
    pub key: SigningKey,
    pub sequence: u64,
}

impl Publisher {
    pub fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            sequence: 0,
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::from_ed25519_bytes(self.key.verifying_key().to_bytes()).unwrap()
    }

    pub fn address(&self) -> Address {
        self.tx_with(0, 1_000, MOVE_PACKAGE_ADDRESS, PUBLISH, vec![])
            .sender_address()
    }

    pub fn tx_with(
        &self,
        sequence: u64,
        gas_limit: u64,
        package: [u8; 32],
        function: &str,
        arguments: Vec<Vec<u8>>,
    ) -> Transaction {
        let body = TransactionBody {
            chain_id: ChainId(1),
            sender: self.public(),
            sequence_number: SequenceNumber(sequence),
            expiry: BlockHeight(5_000),
            gas_limit: GasAmount(gas_limit),
            max_fee_per_gas: GasPrice(MAX_FEE),
            declared_inputs: Vec::new(),
            call: MoveCall {
                module_address: Address::from_bytes(package),
                module_name: MOVE_MODULE_NAME.as_bytes().to_vec(),
                function_name: function.as_bytes().to_vec(),
                type_arguments: Vec::new(),
                arguments,
            },
        };
        let mut bytes = Vec::new();
        body.encode(&mut bytes);
        let signature = Signature::from_ed25519_bytes(self.key.sign(&bytes).to_bytes());
        Transaction { body, signature }
    }

    /// The next transaction from this publisher: a call of `function` in
    /// `module` of the package at `package`.
    pub fn call(
        &mut self,
        package: [u8; 32],
        module: &str,
        function: &str,
        arguments: Vec<Vec<u8>>,
    ) -> Transaction {
        let mut tx = self.tx_with(self.sequence, 100_000, package, function, arguments);
        tx.body.call.module_name = module.as_bytes().to_vec();
        let mut bytes = Vec::new();
        tx.body.encode(&mut bytes);
        tx.signature = Signature::from_ed25519_bytes(self.key.sign(&bytes).to_bytes());
        self.sequence += 1;
        tx
    }

    /// `tx` with its signature made again, after its body was changed.
    pub fn resign(&self, mut tx: Transaction) -> Transaction {
        let mut bytes = Vec::new();
        tx.body.encode(&mut bytes);
        tx.signature = Signature::from_ed25519_bytes(self.key.sign(&bytes).to_bytes());
        tx
    }

    pub fn publish(&mut self, modules: Vec<Vec<u8>>) -> Transaction {
        self.publish_with_gas(PUBLISH_GAS, modules)
    }

    pub fn publish_with_gas(&mut self, gas: u64, modules: Vec<Vec<u8>>) -> Transaction {
        let tx = self.tx_with(self.sequence, gas, MOVE_PACKAGE_ADDRESS, PUBLISH, modules);
        self.sequence += 1;
        tx
    }
}

pub struct Chain {
    pub executor: Executor,
    pub now_ms: u64,
}

impl Chain {
    pub fn new() -> Self {
        Self {
            executor: Executor::genesis(ChainId(1)).unwrap(),
            now_ms: START_MS,
        }
    }

    pub fn fund(&mut self, who: &Publisher, amount: u128) {
        self.executor.credit_account(who.address(), amount).unwrap();
    }

    pub fn run(&mut self, tx: Transaction) -> TransactionOutcome {
        self.now_ms += 1_000;
        let root = self.executor.state_root();
        let height = BlockHeight(self.executor.head_height().unwrap() + 1);
        let block: Block = self.executor.propose_block(
            self.executor.tip_block_hash(),
            root,
            height,
            self.now_ms,
            vec![tx],
            BlockLimits {
                max_gas: u64::MAX,
                max_size_bytes: 4 * 1024 * 1024,
            },
        );
        let executed = self.executor.execute_block(root, &block).unwrap();
        self.executor.finalise_block(&block, &executed).unwrap();
        self.executor.audit().unwrap();
        executed.outcomes[0]
    }

    pub fn package(&self, id: [u8; 32]) -> Option<Vec<u8>> {
        let key = package_key(move_core_types::account_address::AccountAddress::new(id));
        self.executor
            .state_entries()
            .find(|(k, _)| **k == key)
            .map(|(_, v)| v.as_bytes().to_vec())
    }

    pub fn balance(&self, who: Address) -> u128 {
        self.executor.read_account(who).unwrap().balance
    }
}

pub const SUCCESS: TransactionOutcome = TransactionOutcome::Success;
pub const REFUSED: TransactionOutcome = TransactionOutcome::Aborted(AbortReason::PublishRefused);

pub fn rich() -> (Chain, Publisher) {
    let mut chain = Chain::new();
    let publisher = Publisher::new(1);
    chain.fund(&publisher, 1_000_000_000_000);
    (chain, publisher)
}

pub fn id_of(publisher: &Publisher, sequence: u64) -> [u8; 32] {
    package_address(&publisher.address(), sequence).into_bytes()
}
