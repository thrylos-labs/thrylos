//! The randomness beacon behind proposer selection.
//!
//! `docs/spec.md`, "Consensus": "Proposer selection uses a VRF seeded by
//! the previous block's certificate: each validator can verify the winner
//! after the fact, but nobody can compute the schedule ahead of time."
//!
//! The spec asks for a VRF and its principle 1 is "reuse rather than
//! invent", so this uses what the chain already has: BLS12-381
//! signatures are *unique* — a key has exactly one valid signature on a
//! message — so a signature is a verifiable, unpredictable value only its
//! key's holder could have produced, which is what a VRF output is. No new
//! scheme, no new dependency, no new key.
//!
//! # How the chain of seeds runs
//!
//! - The seed for the first height is derived from the genesis hash
//!   ([`genesis_seed`]).
//! - The proposer of a block signs its height and the seed in force
//!   ([`beacon_message`], under [`DST_BEACON`]): its *reveal*. Nobody can
//!   compute another validator's reveal, and a validator has no freedom in
//!   its own.
//! - The seed for the next height is the hash of the seed and the decided
//!   block's reveal ([`next_seed`]).
//!
//! So the schedule for height `h` is unknown to everyone until block
//! `h - 1` is decided, and cannot be steered by choosing block contents —
//! the reveal does not depend on them. A proposer's one lever is not
//! proposing at all (one bit, at the price of its round), the same lever
//! any leader has.
//!
//! What a reveal is *not*: a vote or a proposal. It is signed under its own
//! domain-separation tag and its own message layout, so it can never be
//! mistaken for something a validator is slashed for, and it needs no
//! high-water-mark protection: signing it twice yields the same bytes.

use crate::bls::{verify_aggregate, BlsPublicKey, BlsSignature, BlsSignatureError, DST_BEACON};
use crate::codec::Encode;
use crate::hash::{hash_with_domain, DomainTag, Hash};
use crate::ids::BlockHeight;

/// Leading byte of a reveal's message. Votes lead with
/// [`crate::vote::VOTE_SIGNING_TAG`] (`0`) and proposals with `1`; a
/// reveal's is distinct from both as well as being signed under its own
/// DST.
pub const BEACON_SIGNING_TAG: u8 = 2;
const _: () = assert!(BEACON_SIGNING_TAG != crate::vote::VOTE_SIGNING_TAG);

/// What a proposer signs to reveal its share of the beacon for `height`,
/// given the `seed` in force for that height.
pub fn beacon_message(height: BlockHeight, seed: &Hash) -> Vec<u8> {
    let mut out = Vec::new();
    BEACON_SIGNING_TAG.encode(&mut out);
    height.encode(&mut out);
    seed.encode(&mut out);
    out
}

/// The seed for the first height, from the genesis hash.
pub fn genesis_seed(genesis_hash: &Hash) -> Hash {
    let mut payload = vec![0u8];
    payload.extend_from_slice(genesis_hash.as_bytes());
    hash_with_domain(DomainTag::BeaconSeedV1, &payload)
}

/// The seed for the height after one whose seed was `seed` and whose
/// decided block carried `reveal`.
pub fn next_seed(seed: &Hash, reveal: &BlsSignature) -> Hash {
    let mut payload = vec![1u8];
    payload.extend_from_slice(seed.as_bytes());
    payload.extend_from_slice(&reveal.to_bytes());
    hash_with_domain(DomainTag::BeaconSeedV1, &payload)
}

/// Checks that `reveal` is `key`'s reveal for `height` under `seed`.
pub fn verify_reveal(
    key: &BlsPublicKey,
    height: BlockHeight,
    seed: &Hash,
    reveal: &BlsSignature,
) -> Result<(), BlsSignatureError> {
    verify_aggregate(&[key], &beacon_message(height, seed), DST_BEACON, reveal)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::bls::DST_VOTE;
    use blst::min_pk::SecretKey;

    fn keypair(seed: u8) -> (SecretKey, BlsPublicKey) {
        let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
        let pk = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
        (sk, pk)
    }

    fn reveal(sk: &SecretKey, height: u64, seed: &Hash) -> BlsSignature {
        BlsSignature::from_bytes(
            sk.sign(&beacon_message(BlockHeight(height), seed), DST_BEACON, &[])
                .to_bytes(),
        )
        .unwrap()
    }

    fn seed(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    #[test]
    fn a_reveal_verifies_for_its_key_height_and_seed_and_nothing_else() {
        let (sk, pk) = keypair(1);
        let (_, other_pk) = keypair(2);
        let r = reveal(&sk, 7, &seed(9));

        assert!(verify_reveal(&pk, BlockHeight(7), &seed(9), &r).is_ok());
        assert!(
            verify_reveal(&other_pk, BlockHeight(7), &seed(9), &r).is_err(),
            "key"
        );
        assert!(
            verify_reveal(&pk, BlockHeight(8), &seed(9), &r).is_err(),
            "height"
        );
        assert!(
            verify_reveal(&pk, BlockHeight(7), &seed(10), &r).is_err(),
            "seed"
        );
    }

    #[test]
    fn a_reveal_is_unique_so_it_cannot_be_ground() {
        // The same key, height and seed give the same bytes every time:
        // there is no second valid reveal to choose between.
        let (sk, _) = keypair(1);
        assert_eq!(reveal(&sk, 7, &seed(9)), reveal(&sk, 7, &seed(9)));
        assert_ne!(reveal(&sk, 7, &seed(9)), reveal(&sk, 7, &seed(10)));
        assert_ne!(reveal(&sk, 7, &seed(9)), reveal(&sk, 8, &seed(9)));
    }

    #[test]
    fn a_reveal_is_not_a_vote_and_a_vote_is_not_a_reveal() {
        let (sk, pk) = keypair(1);
        let message = beacon_message(BlockHeight(7), &seed(9));
        // The reveal's bytes signed as if they were a vote: wrong domain.
        let as_vote =
            BlsSignature::from_bytes(sk.sign(&message, DST_VOTE, &[]).to_bytes()).unwrap();
        assert!(verify_reveal(&pk, BlockHeight(7), &seed(9), &as_vote).is_err());
        // And a genuine reveal does not verify under the vote domain.
        let r = reveal(&sk, 7, &seed(9));
        assert!(verify_aggregate(&[&pk], &message, DST_VOTE, &r).is_err());
    }

    #[test]
    fn the_message_leads_with_its_own_tag_distinct_from_votes_and_proposals() {
        assert_eq!(
            beacon_message(BlockHeight(1), &seed(0)).first(),
            Some(&BEACON_SIGNING_TAG)
        );
        assert_ne!(BEACON_SIGNING_TAG, crate::vote::VOTE_SIGNING_TAG);
        assert_ne!(BEACON_SIGNING_TAG, 1, "proposals lead with 1");
    }

    #[test]
    fn the_seed_chain_depends_on_every_link() {
        let (sk_a, _) = keypair(1);
        let (sk_b, _) = keypair(2);
        let genesis = genesis_seed(&seed(0xAA));
        assert_ne!(genesis, genesis_seed(&seed(0xAB)));

        let a = next_seed(&genesis, &reveal(&sk_a, 1, &genesis));
        let b = next_seed(&genesis, &reveal(&sk_b, 1, &genesis));
        assert_ne!(a, b, "a different proposer's reveal gives a different seed");
        assert_ne!(a, genesis);
        // Order matters: the seed after two blocks is not symmetric in them.
        let ab = next_seed(&a, &reveal(&sk_b, 2, &a));
        let ba = next_seed(&b, &reveal(&sk_a, 2, &b));
        assert_ne!(ab, ba);
    }

    #[test]
    fn the_genesis_seed_and_a_next_seed_are_in_different_domains() {
        // A `genesis_seed` payload is 33 bytes and a `next_seed` one 129, and
        // they lead with different bytes, so neither can stand in for the other.
        let (sk, _) = keypair(1);
        let g = seed(3);
        let r = reveal(&sk, 1, &g);
        assert_ne!(genesis_seed(&g), next_seed(&g, &r));
    }
}
