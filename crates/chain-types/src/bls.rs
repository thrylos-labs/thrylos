//! BLS12-381 validator keys and signatures, for consensus (`docs/spec.md`,
//! "Consensus": "Signatures are BLS12-381 with proof-of-possession,
//! aggregated per round"). Built on `blst`'s min-pk variant — 48-byte
//! compressed public keys in G1, 96-byte compressed signatures in G2 —
//! the convention used by essentially every production BLS-based
//! consensus implementation, so this is the well-trodden path rather
//! than a bespoke one.
//!
//! Unlike the account-layer [`crate::keys`] module, there is no scheme
//! byte here: the scheme is fixed at genesis and changes only by a fork
//! (`docs/spec.md`, "Native module boundary": "changed only by a fork").
//!
//! Every [`BlsPublicKey`] and [`BlsSignature`] in this crate is checked
//! (on-curve, correct subgroup, and — for individually-registered keys —
//! not the identity element) at the moment it's constructed from bytes,
//! never at the moment it's used. That's what makes it safe for
//! [`verify_aggregate`] to trust its `signers` slice without re-checking
//! group membership per call, matching `docs/spec.md`'s "checked for
//! subgroup membership on registration ... never against a set the
//! message itself supplies".
//!
//! No signing lives here: consensus keys are held only by `chain-signer`,
//! isolated from everything else (`docs/spec.md`, "Keys, signing and
//! slashing safety"). This module parses, validates, and verifies.

use blst::min_pk::{AggregateSignature, PublicKey as BlstPublicKey, Signature as BlstSignature};
use blst::BLST_ERROR;

use crate::codec::{CodecError, Decode, Encode};

pub const BLS_PUBLIC_KEY_LEN: usize = 48;
pub const BLS_SIGNATURE_LEN: usize = 96;

/// Domain-separation tags. Each is fixed forever once shipped: a new
/// signing context gets a new tag, an existing tag's meaning never
/// changes.
pub const DST_VOTE: &[u8] = b"THRYLOS-BLS-VOTE-V1";
pub const DST_PROOF_OF_POSSESSION: &[u8] = b"THRYLOS-BLS-POP-V1";

/// A verification failure. Deliberately opaque, like
/// [`crate::keys::SignatureError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsSignatureError;

impl core::fmt::Display for BlsSignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BLS signature verification failed")
    }
}

impl std::error::Error for BlsSignatureError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsPublicKey(BlstPublicKey);

impl BlsPublicKey {
    /// Parse and fully validate: on-curve, in the correct subgroup, and
    /// not the identity element. This is the "registration" check from
    /// `docs/spec.md`'s Consensus section — the intent is to call it once
    /// per key, when it's registered, not on every message it signs.
    pub fn from_bytes(bytes: [u8; BLS_PUBLIC_KEY_LEN]) -> Result<Self, CodecError> {
        BlstPublicKey::key_validate(&bytes)
            .map(Self)
            .map_err(|_| CodecError::InvalidValue)
    }

    pub fn to_bytes(&self) -> [u8; BLS_PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verify a proof of possession: this key signing its own encoded
    /// bytes under [`DST_PROOF_OF_POSSESSION`]. Requiring this at
    /// registration is what makes trusting already-registered keys in
    /// [`verify_aggregate`] safe against rogue-key attacks.
    pub fn verify_proof_of_possession(&self, pop: &BlsSignature) -> Result<(), BlsSignatureError> {
        verify_one(self, &self.to_bytes(), DST_PROOF_OF_POSSESSION, pop)
    }
}

impl Encode for BlsPublicKey {
    fn encode(&self, out: &mut Vec<u8>) {
        self.to_bytes().encode(out);
    }
}

impl Decode for BlsPublicKey {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = <[u8; BLS_PUBLIC_KEY_LEN]>::decode(input)?;
        let key = Self::from_bytes(bytes)?;
        Ok((key, used))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsSignature(BlstSignature);

/// Ordered by compressed byte encoding. `blst`'s own type has no
/// ordering; this exists only so `BlsSignature` can satisfy trait
/// bounds (e.g. Malachite's `SigningScheme::Signature: Ord`) that need
/// *some* total order, not a specific one.
impl PartialOrd for BlsSignature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlsSignature {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl BlsSignature {
    /// Parse and validate: on-curve and in the correct subgroup. Does
    /// not reject the identity element here — that's only meaningful for
    /// an individual signature, and the degenerate all-zero-signers case
    /// is better rejected at the "at least one signer" check in
    /// [`verify_aggregate`] than baked into every decode.
    pub fn from_bytes(bytes: [u8; BLS_SIGNATURE_LEN]) -> Result<Self, CodecError> {
        let sig = BlstSignature::from_bytes(&bytes).map_err(|_| CodecError::InvalidValue)?;
        sig.validate(false).map_err(|_| CodecError::InvalidValue)?;
        Ok(Self(sig))
    }

    pub fn to_bytes(&self) -> [u8; BLS_SIGNATURE_LEN] {
        self.0.to_bytes()
    }

    /// Combine already-validated signatures into one aggregate. Every
    /// `BlsSignature` reaching here was already subgroup-checked at
    /// construction (via [`Self::from_bytes`] or a prior `aggregate`
    /// call), and the sum of in-subgroup points stays in-subgroup, so
    /// this doesn't re-check.
    pub fn aggregate(signatures: &[&BlsSignature]) -> Result<Self, BlsSignatureError> {
        let raw: Vec<&BlstSignature> = signatures.iter().map(|s| &s.0).collect();
        AggregateSignature::aggregate(&raw, false)
            .map(|agg| Self(agg.to_signature()))
            .map_err(|_| BlsSignatureError)
    }
}

impl Encode for BlsSignature {
    fn encode(&self, out: &mut Vec<u8>) {
        self.to_bytes().encode(out);
    }
}

impl Decode for BlsSignature {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = <[u8; BLS_SIGNATURE_LEN]>::decode(input)?;
        let sig = Self::from_bytes(bytes)?;
        Ok((sig, used))
    }
}

fn verify_one(
    key: &BlsPublicKey,
    message: &[u8],
    dst: &[u8],
    signature: &BlsSignature,
) -> Result<(), BlsSignatureError> {
    // `pk_validate: false` — our `BlsPublicKey` is already validated at
    // construction, so re-checking on every verify would be redundant.
    let err = signature.0.verify(true, message, dst, &[], &key.0, false);
    match err {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(BlsSignatureError),
    }
}

/// Verify an aggregate signature against a fixed set of already-validated
/// public keys, all signing the same message. Callers select `signers`
/// from the canonical, already-registered validator set via the round's
/// participation bitfield — never from anything the message itself
/// supplies (`docs/spec.md`, "Consensus": "the aggregate is verified
/// against the canonical participation bitfield, never against a set the
/// message itself supplies").
pub fn verify_aggregate(
    signers: &[&BlsPublicKey],
    message: &[u8],
    dst: &[u8],
    aggregate_signature: &BlsSignature,
) -> Result<(), BlsSignatureError> {
    if signers.is_empty() {
        return Err(BlsSignatureError);
    }
    let raw: Vec<&BlstPublicKey> = signers.iter().map(|key| &key.0).collect();
    let err = aggregate_signature
        .0
        .fast_aggregate_verify(true, message, dst, &raw);
    match err {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(BlsSignatureError),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use crate::codec::decode_exact;
    use blst::min_pk::SecretKey;

    /// Deterministic key material — no RNG needed, matching this
    /// crate's "no ambient randomness" rule even in test code.
    fn test_secret_key(seed_byte: u8) -> SecretKey {
        let ikm = [seed_byte; 32];
        SecretKey::key_gen(&ikm, &[]).unwrap()
    }

    fn test_keypair(seed_byte: u8) -> (SecretKey, BlsPublicKey) {
        let sk = test_secret_key(seed_byte);
        let pk = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
        (sk, pk)
    }

    fn sign(sk: &SecretKey, message: &[u8], dst: &[u8]) -> BlsSignature {
        BlsSignature::from_bytes(sk.sign(message, dst, &[]).to_bytes()).unwrap()
    }

    #[test]
    fn public_key_round_trips() {
        let (_, pk) = test_keypair(1);
        let mut buf = Vec::new();
        pk.encode(&mut buf);
        let decoded: BlsPublicKey = decode_exact(&buf).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn signature_round_trips() {
        let (sk, _) = test_keypair(1);
        let sig = sign(&sk, b"round trip me", DST_VOTE);
        let mut buf = Vec::new();
        sig.encode(&mut buf);
        let decoded: BlsSignature = decode_exact(&buf).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn identity_public_key_is_rejected() {
        // The compressed encoding of the point at infinity: compression
        // flag and infinity flag set, every other bit zero.
        let mut bytes = [0u8; BLS_PUBLIC_KEY_LEN];
        bytes[0] = 0xc0;
        assert_eq!(
            BlsPublicKey::from_bytes(bytes),
            Err(CodecError::InvalidValue)
        );
    }

    #[test]
    fn garbage_bytes_are_rejected_not_misparsed() {
        let bytes = [0xAAu8; BLS_PUBLIC_KEY_LEN];
        assert_eq!(
            BlsPublicKey::from_bytes(bytes),
            Err(CodecError::InvalidValue)
        );
    }

    #[test]
    fn verify_succeeds_on_correct_message_and_fails_on_tampered_one() {
        let (sk, pk) = test_keypair(2);
        let sig = sign(&sk, b"hello thrylos", DST_VOTE);
        assert!(verify_one(&pk, b"hello thrylos", DST_VOTE, &sig).is_ok());
        assert!(verify_one(&pk, b"tampered", DST_VOTE, &sig).is_err());
    }

    #[test]
    fn verify_fails_across_domain_tags() {
        // The same key signing the same bytes under a different DST must
        // not verify — that's the entire point of domain separation.
        let (sk, pk) = test_keypair(3);
        let sig = sign(&sk, b"shared bytes", DST_VOTE);
        assert!(verify_one(&pk, b"shared bytes", DST_PROOF_OF_POSSESSION, &sig).is_err());
    }

    #[test]
    fn proof_of_possession_round_trips_through_the_public_api() {
        let (sk, pk) = test_keypair(4);
        let pop = sign(&sk, &pk.to_bytes(), DST_PROOF_OF_POSSESSION);
        assert!(pk.verify_proof_of_possession(&pop).is_ok());

        let (_, other_pk) = test_keypair(5);
        assert!(other_pk.verify_proof_of_possession(&pop).is_err());
    }

    #[test]
    fn aggregate_verifies_against_exactly_its_signers() {
        let (sk_a, pk_a) = test_keypair(10);
        let (sk_b, pk_b) = test_keypair(11);
        let (sk_c, pk_c) = test_keypair(12);
        let message = b"block certificate for round 7";

        let sig_a = sign(&sk_a, message, DST_VOTE);
        let sig_b = sign(&sk_b, message, DST_VOTE);
        let sig_c = sign(&sk_c, message, DST_VOTE);

        let aggregate = BlsSignature::aggregate(&[&sig_a, &sig_b, &sig_c]).unwrap();

        assert!(verify_aggregate(&[&pk_a, &pk_b, &pk_c], message, DST_VOTE, &aggregate).is_ok());

        // Dropping a signer from the participation set must not verify —
        // an aggregate is only valid against exactly the keys that
        // contributed to it.
        assert!(verify_aggregate(&[&pk_a, &pk_b], message, DST_VOTE, &aggregate).is_err());

        // A key that never signed must not be smuggled into a valid set.
        let (_, pk_outsider) = test_keypair(13);
        assert!(
            verify_aggregate(&[&pk_a, &pk_b, &pk_outsider], message, DST_VOTE, &aggregate).is_err()
        );
    }

    #[test]
    fn verify_aggregate_rejects_empty_signer_set() {
        let (sk, _) = test_keypair(20);
        let sig = sign(&sk, b"message", DST_VOTE);
        assert!(verify_aggregate(&[], b"message", DST_VOTE, &sig).is_err());
    }
}
