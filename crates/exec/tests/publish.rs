//! Publishing Move packages end to end: real signed transactions in real
//! blocks, real compiled Move, and the state checked afterwards.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::io::Write;

use chain_engine_api::{AbortReason, Block, BlockLimits, Engine, TransactionOutcome};
use chain_exec::keys::package_key;
use chain_exec::move_config::{MAX_MODULES_PER_PACKAGE, MAX_MODULE_BYTES};
use chain_exec::native::NEW_ENTRY_STORAGE_DEPOSIT;
use chain_exec::publish::{
    package_address, publish_gas, MOVE_MODULE_NAME, MOVE_PACKAGE_ADDRESS, PUBLISH,
    PUBLISH_BASE_GAS, PUBLISH_DEPOSIT_PER_KIB,
};
use chain_exec::Executor;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};
use move_binary_format::file_format::CompiledModule;
use move_compiler::Compiler;

const START_MS: u64 = 1_700_000_000_000;
const MAX_FEE: u64 = 10;
const PUBLISH_GAS: u64 = 200_000;

/// Compile `source` (modules written against the address `0x0`) to bytes,
/// one entry per module, keyed by module name.
fn compile(source: &str) -> BTreeMap<String, Vec<u8>> {
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

const ONE_MODULE: &str = "module 0x0::hello { public fun answer(): u64 { 42 } }";
const TWO_MODULES: &str = "
    module 0x0::first { public fun one(): u64 { 1 } }
    module 0x0::second { public fun two(): u64 { 0x0::first::one() + 1 } }
";

struct Publisher {
    key: SigningKey,
    sequence: u64,
}

impl Publisher {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            sequence: 0,
        }
    }

    fn public(&self) -> PublicKey {
        PublicKey::from_ed25519_bytes(self.key.verifying_key().to_bytes()).unwrap()
    }

    fn address(&self) -> Address {
        self.tx_with(0, 1_000, MOVE_PACKAGE_ADDRESS, PUBLISH, vec![])
            .sender_address()
    }

    fn tx_with(
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

    fn publish(&mut self, modules: Vec<Vec<u8>>) -> Transaction {
        self.publish_with_gas(PUBLISH_GAS, modules)
    }

    fn publish_with_gas(&mut self, gas: u64, modules: Vec<Vec<u8>>) -> Transaction {
        let tx = self.tx_with(self.sequence, gas, MOVE_PACKAGE_ADDRESS, PUBLISH, modules);
        self.sequence += 1;
        tx
    }
}

struct Chain {
    executor: Executor,
    now_ms: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            executor: Executor::genesis(ChainId(1)).unwrap(),
            now_ms: START_MS,
        }
    }

    fn fund(&mut self, who: &Publisher, amount: u128) {
        self.executor.credit_account(who.address(), amount).unwrap();
    }

    fn run(&mut self, tx: Transaction) -> TransactionOutcome {
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

    fn package(&self, id: [u8; 32]) -> Option<Vec<u8>> {
        let key = package_key(move_core_types::account_address::AccountAddress::new(id));
        self.executor
            .state_entries()
            .find(|(k, _)| **k == key)
            .map(|(_, v)| v.as_bytes().to_vec())
    }

    fn balance(&self, who: Address) -> u128 {
        self.executor.read_account(who).unwrap().balance
    }
}

const SUCCESS: TransactionOutcome = TransactionOutcome::Success;
const REFUSED: TransactionOutcome = TransactionOutcome::Aborted(AbortReason::PublishRefused);

fn rich() -> (Chain, Publisher) {
    let mut chain = Chain::new();
    let publisher = Publisher::new(1);
    chain.fund(&publisher, 1_000_000_000_000);
    (chain, publisher)
}

fn id_of(publisher: &Publisher, sequence: u64) -> [u8; 32] {
    package_address(&publisher.address(), sequence).into_bytes()
}

#[test]
fn a_package_is_stored_at_the_address_its_publisher_and_sequence_give_it() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(ONE_MODULE).into_values().collect();
    let expected = id_of(&publisher, 0);
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);

    let stored = chain
        .package(expected)
        .expect("stored at the derived address");
    let decoded: Vec<Vec<u8>> = chain_types::codec::decode_exact(&stored).unwrap();
    assert_eq!(decoded.len(), 1);
    let module = CompiledModule::deserialize_with_defaults(&decoded[0]).unwrap();
    assert_eq!(module.self_id().address().into_bytes(), expected);
    assert_eq!(module.self_id().name().as_str(), "hello");
}

#[test]
fn a_package_of_several_modules_that_use_each_other_is_published_whole() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(TWO_MODULES).into_values().collect();
    let expected = id_of(&publisher, 0);
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);

    let stored = chain.package(expected).unwrap();
    let decoded: Vec<Vec<u8>> = chain_types::codec::decode_exact(&stored).unwrap();
    let names: Vec<String> = decoded
        .iter()
        .map(|bytes| {
            let m = CompiledModule::deserialize_with_defaults(bytes).unwrap();
            assert_eq!(m.self_id().address().into_bytes(), expected);
            m.self_id().name().to_string()
        })
        .collect();
    assert_eq!(names, ["first", "second"]);
}

#[test]
fn the_order_the_modules_are_listed_in_does_not_change_what_is_stored() {
    let (mut chain_a, mut a) = rich();
    let (mut chain_b, mut b) = rich();
    let mut forward: Vec<_> = compile(TWO_MODULES).into_values().collect();
    let expected = id_of(&a, 0);
    assert_eq!(chain_a.run(a.publish(forward.clone())), SUCCESS);
    forward.reverse();
    assert_eq!(chain_b.run(b.publish(forward)), SUCCESS);
    assert_eq!(chain_a.package(expected), chain_b.package(expected));
    assert_eq!(chain_a.executor.state_root(), chain_b.executor.state_root());
}

#[test]
fn publishing_burns_the_fee_and_the_deposit_and_nothing_else() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(ONE_MODULE).into_values().collect();
    let total: usize = modules.iter().map(Vec::len).sum();
    let before = chain.balance(publisher.address());
    let supply = chain.executor.supply().unwrap();
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);

    let fee = u128::from(publish_gas(total)); // base fee is 1
    let deposit = NEW_ENTRY_STORAGE_DEPOSIT
        + u128::try_from(total.div_ceil(1024)).unwrap() * PUBLISH_DEPOSIT_PER_KIB;
    assert_eq!(chain.balance(publisher.address()), before - fee - deposit);
    assert_eq!(chain.executor.supply().unwrap(), supply - fee - deposit);
}

#[test]
fn the_same_package_published_twice_lands_at_two_addresses() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(ONE_MODULE).into_values().collect();
    let (first, second) = (id_of(&publisher, 0), id_of(&publisher, 1));
    assert_ne!(first, second);
    assert_eq!(chain.run(publisher.publish(modules.clone())), SUCCESS);
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);
    assert!(chain.package(first).is_some());
    assert!(chain.package(second).is_some());
}

#[test]
fn two_publishers_never_share_an_address() {
    let (a, b) = (Publisher::new(1), Publisher::new(2));
    assert_ne!(id_of(&a, 0), id_of(&b, 0));
}

#[test]
fn bytes_that_are_not_a_module_are_refused_and_store_nothing() {
    let (mut chain, mut publisher) = rich();
    assert_eq!(
        chain.run(publisher.publish(vec![b"not bytecode".to_vec()])),
        REFUSED
    );
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_module_with_trailing_bytes_is_refused() {
    let (mut chain, mut publisher) = rich();
    let mut module: Vec<u8> = compile(ONE_MODULE).into_values().next().unwrap();
    module.push(0);
    assert_eq!(chain.run(publisher.publish(vec![module])), REFUSED);
}

#[test]
fn a_module_that_names_a_real_address_for_itself_is_refused() {
    let (mut chain, mut publisher) = rich();
    let module = compile("module 0x99::elsewhere { public fun f(): u64 { 1 } }")
        .into_values()
        .next()
        .unwrap();
    assert_eq!(chain.run(publisher.publish(vec![module])), REFUSED);
}

#[test]
fn two_modules_with_one_name_are_refused() {
    let (mut chain, mut publisher) = rich();
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(
        chain.run(publisher.publish(vec![module.clone(), module])),
        REFUSED
    );
}

#[test]
fn an_import_from_an_address_outside_the_allowed_ones_is_refused() {
    let (mut chain, mut publisher) = rich();
    // Compiled against another package's address: the demo `calculator`.
    let source = "
        module 0x0101010101010101010101010101010101010101010101010101010101010101::calculator {
            public fun add(a: u64, b: u64): u64 { a + b }
        }
        module 0x0::user { public fun f(): u64 {
            0x0101010101010101010101010101010101010101010101010101010101010101::calculator::add(1, 2)
        } }";
    let all = compile(source);
    let user = all.get("user").unwrap().clone();
    assert_eq!(chain.run(publisher.publish(vec![user])), REFUSED);
}

#[test]
fn no_modules_and_too_many_modules_are_refused() {
    let (mut chain, mut publisher) = rich();
    assert_eq!(chain.run(publisher.publish(vec![])), REFUSED);
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    let many = vec![module; MAX_MODULES_PER_PACKAGE + 1];
    assert_eq!(chain.run(publisher.publish(many)), REFUSED);
}

#[test]
fn a_module_over_the_size_limit_is_refused() {
    let (mut chain, mut publisher) = rich();
    let oversize = vec![0u8; MAX_MODULE_BYTES + 1];
    assert_eq!(chain.run(publisher.publish(vec![oversize])), REFUSED);
}

#[test]
fn a_gas_limit_below_the_publish_charge_is_refused() {
    let (mut chain, mut publisher) = rich();
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    let tx = publisher.publish_with_gas(PUBLISH_BASE_GAS - 1, vec![module]);
    assert_eq!(chain.run(tx), REFUSED);
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_refused_publish_burns_the_gas_limit_and_still_advances_the_sequence() {
    let (mut chain, mut publisher) = rich();
    let before = chain.balance(publisher.address());
    assert_eq!(
        chain.run(publisher.publish(vec![b"nope".to_vec()])),
        REFUSED
    );
    assert_eq!(
        chain.balance(publisher.address()),
        before - u128::from(PUBLISH_GAS)
    );
    // The next publish uses the next sequence number, and succeeds.
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(chain.run(publisher.publish(vec![module])), SUCCESS);
    assert!(chain.package(id_of(&publisher, 1)).is_some());
}

#[test]
fn a_publisher_who_cannot_pay_the_deposit_is_refused_and_pays_only_the_fee() {
    let mut chain = Chain::new();
    let mut publisher = Publisher::new(3);
    // Enough for the fee reserve, not for the deposit on top of it.
    chain.fund(
        &publisher,
        u128::from(PUBLISH_GAS) * u128::from(MAX_FEE) + 1,
    );
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(
        chain.run(publisher.publish(vec![module])),
        TransactionOutcome::Aborted(AbortReason::InsufficientBalance)
    );
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_call_to_the_publish_package_that_is_not_publish_aborts() {
    let (mut chain, publisher) = rich();
    let tx = publisher.tx_with(0, 1_000, MOVE_PACKAGE_ADDRESS, "upgrade", vec![]);
    assert_eq!(
        chain.run(tx),
        TransactionOutcome::Aborted(AbortReason::UnknownFunction)
    );
}

#[test]
fn a_module_that_deserializes_but_fails_bytecode_verification_is_refused() {
    use move_binary_format::file_format::Bytecode;
    let (mut chain, mut publisher) = rich();
    let bytes = compile(ONE_MODULE).into_values().next().unwrap();
    let mut module = CompiledModule::deserialize_with_defaults(&bytes).unwrap();
    // Pops from an empty stack: well-formed bytes, but not a safe program.
    module.function_defs[0].code.as_mut().unwrap().code = vec![Bytecode::Pop, Bytecode::Ret];
    let mut broken = Vec::new();
    module
        .serialize_with_version(module.version, &mut broken)
        .unwrap();
    assert_eq!(chain.run(publisher.publish(vec![broken])), REFUSED);
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_chain_with_publishing_switched_off_refuses_every_publish() {
    let params = chain_modules::ParamValues {
        publish_enabled: false,
        ..chain_modules::params::GENESIS_PARAM_VALUES
    };
    let mut chain = Chain {
        executor: Executor::genesis_with_params(ChainId(1), params).unwrap(),
        now_ms: START_MS,
    };
    let mut publisher = Publisher::new(1);
    chain.fund(&publisher, 1_000_000_000_000);
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(chain.run(publisher.publish(vec![module])), REFUSED);
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}
