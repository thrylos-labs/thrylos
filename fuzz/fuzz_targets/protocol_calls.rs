#![no_main]

mod protocol_support;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let (executed, _) = protocol_support::execute(input);
    assert_eq!(executed.outcomes.len(), 1);
    assert!(executed.gas_used > 0);
});
