//! Account-layer public keys and signatures.
//!
//! Every key and signature carries a leading scheme byte (`docs/spec.md`,
//! "Transaction validity": "Scheme byte ... Names the signature algorithm,
//! in the signed payload and on every registered key"). Ed25519 is the
//! only scheme accepted at launch; the byte exists purely so a second
//! scheme can be added later without changing the wire format of
//! anything already signed. Decoding an unrecognised scheme byte is a
//! hard decode error, never a silent fallback.
//!
//! This module does not cover the BLS12-381 keys used for consensus
//! (validator signing and aggregation) — those need a pairing-library
//! choice first and belong in their own module once that's picked.

use ed25519_dalek::Verifier;

use crate::codec::{checked_add, slice_from, CodecError, Decode, Encode};

/// A signature algorithm identifier. Currently only [`Scheme::Ed25519`]
/// exists; see `docs/spec.md`'s paragraph beneath the transaction
/// validity table for why a post-quantum scheme isn't added yet (FN-DSA
/// is still a draft and needs float-based sampling that tier A bans; no
/// PQ scheme aggregates the way BLS does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Scheme {
    Ed25519 = 0,
}

impl Scheme {
    fn from_byte(byte: u8) -> Result<Self, CodecError> {
        match byte {
            0 => Ok(Scheme::Ed25519),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

/// A verification failure. Deliberately opaque: callers learn that
/// verification failed, not why, so failure handling can't accidentally
/// branch on a cryptographic error's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureError;

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("signature verification failed")
    }
}

impl std::error::Error for SignatureError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    scheme: Scheme,
    inner: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    /// Parse a compressed Ed25519 public key. Rejects anything that
    /// isn't a valid curve point rather than accepting it and failing
    /// later at verify time.
    pub fn from_ed25519_bytes(bytes: [u8; 32]) -> Result<Self, CodecError> {
        let inner = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| CodecError::InvalidValue)?;
        Ok(Self {
            scheme: Scheme::Ed25519,
            inner,
        })
    }

    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| SignatureError)
    }
}

impl Encode for PublicKey {
    fn encode(&self, out: &mut Vec<u8>) {
        (self.scheme as u8).encode(out);
        self.inner.to_bytes().encode(out);
    }
}

impl Decode for PublicKey {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (scheme_byte, offset) = u8::decode(input)?;
        match Scheme::from_byte(scheme_byte)? {
            Scheme::Ed25519 => {
                let (bytes, used) = <[u8; 32]>::decode(slice_from(input, offset)?)?;
                let key = Self::from_ed25519_bytes(bytes)?;
                Ok((key, checked_add(offset, used)?))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    scheme: Scheme,
    inner: ed25519_dalek::Signature,
}

impl Signature {
    pub fn from_ed25519_bytes(bytes: [u8; 64]) -> Self {
        Self {
            scheme: Scheme::Ed25519,
            inner: ed25519_dalek::Signature::from_bytes(&bytes),
        }
    }

    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }
}

impl Encode for Signature {
    fn encode(&self, out: &mut Vec<u8>) {
        (self.scheme as u8).encode(out);
        self.inner.to_bytes().encode(out);
    }
}

impl Decode for Signature {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (scheme_byte, offset) = u8::decode(input)?;
        match Scheme::from_byte(scheme_byte)? {
            Scheme::Ed25519 => {
                let (bytes, used) = <[u8; 64]>::decode(slice_from(input, offset)?)?;
                let sig = Self::from_ed25519_bytes(bytes);
                Ok((sig, checked_add(offset, used)?))
            }
        }
    }
}

/// Signing helper for this crate's own tests only — production signing
/// happens in `chain-signer`, isolated from everything else
/// (`docs/spec.md`, "Keys, signing and slashing safety").
#[cfg(test)]
fn sign_for_tests(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> Signature {
    use ed25519_dalek::Signer;
    Signature {
        scheme: Scheme::Ed25519,
        inner: signing_key.sign(message),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::codec::decode_exact;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> (SigningKey, PublicKey) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        (
            signing,
            PublicKey {
                scheme: Scheme::Ed25519,
                inner: verifying,
            },
        )
    }

    #[test]
    fn public_key_round_trips() {
        let (_, pk) = test_keypair();
        let mut buf = Vec::new();
        pk.encode(&mut buf);
        let decoded: PublicKey = decode_exact(&buf).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn signature_round_trips() {
        let (signing, _) = test_keypair();
        let sig = sign_for_tests(&signing, b"round trip me");
        let mut buf = Vec::new();
        sig.encode(&mut buf);
        let decoded: Signature = decode_exact(&buf).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn unknown_scheme_byte_is_rejected_not_misparsed() {
        let mut buf = vec![0xFFu8];
        buf.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            decode_exact::<PublicKey>(&buf),
            Err(CodecError::InvalidValue)
        );
    }

    #[test]
    fn invalid_curve_point_is_rejected() {
        // About half of all 32-byte strings aren't valid compressed
        // Edwards points; search rather than assume a specific pattern is
        // one of them (e.g. all-0xFF turns out to decompress just fine).
        let invalid_bytes = (0u16..256)
            .flat_map(|hi| (0u16..256).map(move |lo| (hi as u8, lo as u8)))
            .map(|(hi, lo)| {
                let mut bytes = [0u8; 32];
                bytes[0] = lo;
                bytes[31] = hi;
                bytes
            })
            .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
            .expect("some 32-byte string in this small search space must be an invalid point");

        let mut buf = vec![0u8]; // Scheme::Ed25519
        buf.extend_from_slice(&invalid_bytes);
        assert_eq!(
            decode_exact::<PublicKey>(&buf),
            Err(CodecError::InvalidValue)
        );
    }

    #[test]
    fn verify_succeeds_on_correct_message_and_fails_on_tampered_one() {
        let (signing, pk) = test_keypair();
        let sig = sign_for_tests(&signing, b"hello thrylos");
        assert!(pk.verify(b"hello thrylos", &sig).is_ok());
        assert!(pk.verify(b"tampered", &sig).is_err());
    }
}
