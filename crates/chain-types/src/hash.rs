//! BLAKE3 hashing with a versioned, per-node-type domain-separation
//! prefix mixed into every hash, so two differently-shaped structures can
//! never produce the same digest. See `docs/spec.md`, "State, storage and
//! sync": "Hashing is BLAKE3 throughout, with a single, versioned
//! domain-separation prefix per node type".

use crate::codec::{CodecError, Decode, Encode};

pub const HASH_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Encode for Hash {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for Hash {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = <[u8; HASH_LEN]>::decode(input)?;
        Ok((Self(bytes), used))
    }
}

/// A node type's domain-separation tag. Each variant is fixed and
/// versioned: once shipped, its numeric value is never reused for a
/// different structure, and a genuinely new structure gets a new
/// variant rather than reusing an old tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DomainTag {
    TrieLeafV1 = 0,
    TrieBranchV1 = 1,
    BlockHeaderV1 = 2,
    TransactionV1 = 3,
    AddressV1 = 4,
    /// Hashing a state key down to its 256-bit trie routing path —
    /// distinct from `TrieLeafV1`, which hashes a key *and* its value as
    /// the content stored at that path.
    TrieKeyPathV1 = 5,
}

/// Hash `payload` under `tag`'s domain-separation prefix.
pub fn hash_with_domain(tag: DomainTag, payload: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[tag as u8]);
    hasher.update(payload);
    Hash(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_domain_tags_never_collide_on_the_same_payload() {
        let payload = b"same bytes either way";
        let leaf = hash_with_domain(DomainTag::TrieLeafV1, payload);
        let branch = hash_with_domain(DomainTag::TrieBranchV1, payload);
        assert_ne!(leaf, branch);
    }
}
