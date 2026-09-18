//! Round-trip property tests for the canonical codec (`docs/spec.md`,
//! "Verification plan": "Codec round-trips" under `proptest`).
//! `decode_exact(encode(x)) == x`, byte-for-byte, for arbitrary values —
//! not just the hand-picked cases in `codec.rs`'s unit tests.

#![allow(clippy::unwrap_used)]

use chain_types::collections::BTreeMap;
use chain_types::{decode_exact, BlockHeight, ChainId, Encode, Hash, Round};
use proptest::prelude::*;

fn round_trips<T: Encode + chain_types::Decode + PartialEq + std::fmt::Debug>(value: T) {
    let mut buf = Vec::new();
    value.encode(&mut buf);
    let decoded: T = decode_exact(&buf).unwrap();
    assert_eq!(decoded, value);
}

proptest! {
    #[test]
    fn u8_round_trips(v: u8) { round_trips(v); }

    #[test]
    fn u32_round_trips(v: u32) { round_trips(v); }

    #[test]
    fn u64_round_trips(v: u64) { round_trips(v); }

    #[test]
    fn u128_round_trips(v: u128) { round_trips(v); }

    #[test]
    fn bool_round_trips(v: bool) { round_trips(v); }

    #[test]
    fn vec_u32_round_trips(v: Vec<u32>) { round_trips(v); }

    #[test]
    fn vec_of_vec_round_trips(v: Vec<Vec<u8>>) { round_trips(v); }

    #[test]
    fn btreemap_round_trips(entries: Vec<(u32, u64)>) {
        let map: BTreeMap<u32, u64> = entries.into_iter().collect();
        round_trips(map);
    }

    #[test]
    fn hash_round_trips(bytes: [u8; 32]) { round_trips(Hash::from_bytes(bytes)); }

    #[test]
    fn chain_id_round_trips(v: u64) { round_trips(ChainId(v)); }

    #[test]
    fn block_height_round_trips(v: u64) { round_trips(BlockHeight(v)); }

    #[test]
    fn round_round_trips(v: u64) { round_trips(Round(v)); }

    /// Truncating a valid encoding by any nonzero amount must be rejected,
    /// never produce a different-but-valid value.
    #[test]
    fn truncated_u64_is_rejected_not_misdecoded(v: u64, keep in 0usize..8) {
        let mut buf = Vec::new();
        v.encode(&mut buf);
        buf.truncate(keep);
        prop_assert!(decode_exact::<u64>(&buf).is_err());
    }

    /// Appending extra bytes after a valid encoding must be rejected.
    #[test]
    fn trailing_byte_is_rejected(v: u32, extra: u8) {
        let mut buf = Vec::new();
        v.encode(&mut buf);
        buf.push(extra);
        prop_assert!(decode_exact::<u32>(&buf).is_err());
    }
}
