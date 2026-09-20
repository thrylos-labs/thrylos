#![no_main]

use chain_consensus::wire::{
    decode_commit_record, decode_message, decode_timeout, encode_commit_record, encode_message,
    encode_timeout,
};
use chain_engine_api::Block;
use chain_state::{StateKey, StateValue};
use chain_types::{decode_exact, Decode, Encode, Transaction, TransactionBody};
use libfuzzer_sys::fuzz_target;

fn require_canonical<T>(input: &[u8])
where
    T: Decode + Encode,
{
    if let Ok(value) = decode_exact::<T>(input) {
        let mut encoded = Vec::new();
        value.encode(&mut encoded);
        assert_eq!(encoded, input, "decoder accepted a non-canonical encoding");
    }
}

fuzz_target!(|input: &[u8]| {
    // These are the concrete untrusted and durable boundaries used by the
    // node. A successful strict decode must round-trip byte for byte; any
    // malformed input must return an error rather than panic.
    require_canonical::<TransactionBody>(input);
    require_canonical::<Transaction>(input);
    require_canonical::<Block>(input);
    require_canonical::<StateKey>(input);
    require_canonical::<StateValue>(input);

    if let Ok(message) = decode_message(input) {
        assert_eq!(encode_message(&message), input);
    }
    if let Ok(timeout) = decode_timeout(input) {
        assert_eq!(encode_timeout(timeout), input);
    }
    if let Ok(record) = decode_commit_record(input) {
        assert_eq!(encode_commit_record(&record), input);
    }
});
