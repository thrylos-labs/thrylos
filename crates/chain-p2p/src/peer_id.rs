//! A peer's identity on the gossip network. Opaque and local to this
//! crate: it may end up derived from a peer's public key once real
//! transport/discovery exists, but nothing here needs to know that.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
