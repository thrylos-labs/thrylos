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
    /// A genesis configuration's canonical encoding: what a chain's first
    /// block's parent hash commits to, so two networks that differ in any
    /// allocation, validator or parameter cannot share a block.
    GenesisConfigV1 = 6,
    /// The randomness beacon's seed, at genesis and after each block
    /// ([`crate::beacon`]).
    BeaconSeedV1 = 7,
    /// The draw that picks a round's proposer from the seed
    /// (`chain-consensus`).
    ProposerDrawV1 = 8,
    /// Trie commitment v2 leaf. Its payload is the canonical encoding
    /// of a state key followed by the canonical encoding of its value,
    /// so the key/value boundary is unambiguous.
    TrieLeafV2 = 9,
    /// Trie commitment v2 internal branch.
    TrieBranchV2 = 10,
    /// Trie commitment v2 state-key routing path.
    TrieKeyPathV2 = 11,
    /// The outer commitment to a complete trie root. This binds every
    /// published state root to the v2 trie construction rather than only
    /// to whichever node happens to occur at the top of the tree.
    TrieRootV2 = 12,
    /// The address of a published Move package: derived from the publisher
    /// and the sequence number of the publishing transaction, so it cannot
    /// be chosen and cannot repeat.
    MovePackageV1 = 13,
    /// The part of a Move drawer's state key that stands for its type: a
    /// fixed-size stand-in for a type's canonical name of any length.
    MoveDrawerTypeV1 = 14,
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
    fn domain_tag_numbers_are_append_only() {
        assert_eq!(DomainTag::TrieLeafV1 as u8, 0);
        assert_eq!(DomainTag::TrieBranchV1 as u8, 1);
        assert_eq!(DomainTag::BlockHeaderV1 as u8, 2);
        assert_eq!(DomainTag::TransactionV1 as u8, 3);
        assert_eq!(DomainTag::AddressV1 as u8, 4);
        assert_eq!(DomainTag::TrieKeyPathV1 as u8, 5);
        assert_eq!(DomainTag::GenesisConfigV1 as u8, 6);
        assert_eq!(DomainTag::BeaconSeedV1 as u8, 7);
        assert_eq!(DomainTag::ProposerDrawV1 as u8, 8);
        assert_eq!(DomainTag::TrieLeafV2 as u8, 9);
        assert_eq!(DomainTag::TrieBranchV2 as u8, 10);
        assert_eq!(DomainTag::TrieKeyPathV2 as u8, 11);
        assert_eq!(DomainTag::TrieRootV2 as u8, 12);
        assert_eq!(DomainTag::MovePackageV1 as u8, 13);
        assert_eq!(DomainTag::MoveDrawerTypeV1 as u8, 14);
    }

    #[test]
    fn every_domain_tag_hashes_the_same_payload_differently() {
        let payload = b"one payload, every domain";
        let tags = [
            DomainTag::TrieLeafV1,
            DomainTag::TrieBranchV1,
            DomainTag::BlockHeaderV1,
            DomainTag::TransactionV1,
            DomainTag::AddressV1,
            DomainTag::TrieKeyPathV1,
            DomainTag::GenesisConfigV1,
            DomainTag::BeaconSeedV1,
            DomainTag::ProposerDrawV1,
            DomainTag::TrieLeafV2,
            DomainTag::TrieBranchV2,
            DomainTag::TrieKeyPathV2,
            DomainTag::TrieRootV2,
            DomainTag::MovePackageV1,
            DomainTag::MoveDrawerTypeV1,
        ];
        let hashes: std::collections::BTreeSet<Hash> = tags
            .into_iter()
            .map(|tag| hash_with_domain(tag, payload))
            .collect();
        assert_eq!(hashes.len(), tags.len());
    }

    #[test]
    fn different_domain_tags_never_collide_on_the_same_payload() {
        let payload = b"same bytes either way";
        let leaf = hash_with_domain(DomainTag::TrieLeafV1, payload);
        let branch = hash_with_domain(DomainTag::TrieBranchV1, payload);
        assert_ne!(leaf, branch);
    }
}
