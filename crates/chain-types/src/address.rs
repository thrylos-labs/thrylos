//! Account addresses.

use crate::codec::{CodecError, Decode, Encode};
use crate::hash::{hash_with_domain, DomainTag};
use crate::keys::PublicKey;

pub const ADDRESS_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    pub const fn from_bytes(bytes: [u8; ADDRESS_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }

    /// The address a public key signs for: BLAKE3 of the key's own
    /// canonical encoding (scheme byte included), domain-separated so no
    /// other structure can ever hash to the same address.
    pub fn from_public_key(key: &PublicKey) -> Self {
        let mut encoded = Vec::new();
        key.encode(&mut encoded);
        let hash = hash_with_domain(DomainTag::AddressV1, &encoded);
        Self(*hash.as_bytes())
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Encode for Address {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for Address {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = <[u8; ADDRESS_LEN]>::decode(input)?;
        Ok((Self(bytes), used))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::codec::decode_exact;
    use ed25519_dalek::SigningKey;

    fn a_key() -> PublicKey {
        PublicKey::from_ed25519_bytes(
            SigningKey::from_bytes(&[3u8; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn address_derivation_is_deterministic() {
        let key = a_key();
        assert_eq!(
            Address::from_public_key(&key),
            Address::from_public_key(&key)
        );
    }

    #[test]
    fn different_keys_give_different_addresses() {
        let key_a = a_key();
        let key_b = PublicKey::from_ed25519_bytes(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        assert_ne!(
            Address::from_public_key(&key_a),
            Address::from_public_key(&key_b)
        );
    }

    #[test]
    fn address_round_trips() {
        let addr = Address::from_public_key(&a_key());
        let mut buf = Vec::new();
        addr.encode(&mut buf);
        let decoded: Address = decode_exact(&buf).unwrap();
        assert_eq!(decoded, addr);
    }
}
