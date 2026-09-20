//! Errors this crate's own API can return: an MDBX failure, or a
//! decode failure on bytes this crate itself wrote (which would mean
//! on-disk corruption or a schema change, not a normal runtime path).

use chain_types::codec::CodecError;
use chain_types::BlockHeight;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    Mdbx(libmdbx::MdbxError),
    Decode(CodecError),
    /// A `TableObject` decode failed inside `libmdbx` itself (its
    /// `ReadError::Decoding`, boxed as `dyn Error`). This crate's own
    /// `TableObject` usage is always `Vec<u8>`, whose decode step is
    /// an infallible copy, so this is not expected to be reachable —
    /// kept as a real variant rather than a panic because "not
    /// expected" is not the same guarantee as "impossible".
    Decoding(String),
    /// Block commits are append-only and contiguous. Replacing a committed
    /// height or leaving a gap would make replay ambiguous.
    NonSequentialCommit {
        expected: BlockHeight,
        actual: BlockHeight,
    },
    /// [`crate::Db::initialise`] found a chain already here: either an
    /// earlier initialisation or blocks that were committed without one.
    /// It never overwrites, since replacing a chain's starting point would
    /// change what every stored root means.
    AlreadyInitialised,
    /// A state key is longer than [`crate::schema::MAX_KEY_BYTES`]. Refused
    /// before anything is written, since the store library panics on a key
    /// it cannot hold.
    KeyTooLarge {
        length: usize,
    },
}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mdbx(err) => write!(f, "mdbx error: {err}"),
            Self::Decode(err) => write!(f, "decode error: {err}"),
            Self::Decoding(msg) => write!(f, "mdbx table decode error: {msg}"),
            Self::NonSequentialCommit { expected, actual } => write!(
                f,
                "non-sequential block commit: expected height {expected}, got {actual}"
            ),
            Self::AlreadyInitialised => {
                f.write_str("the database already holds a chain: it is never initialised over")
            }
            Self::KeyTooLarge { length } => write!(
                f,
                "a state key of {length} bytes is over the {}-byte limit",
                crate::schema::MAX_KEY_BYTES
            ),
        }
    }
}

impl std::error::Error for DbError {}

impl From<libmdbx::MdbxError> for DbError {
    fn from(err: libmdbx::MdbxError) -> Self {
        Self::Mdbx(err)
    }
}

impl From<CodecError> for DbError {
    fn from(err: CodecError) -> Self {
        Self::Decode(err)
    }
}

impl From<libmdbx::ReadError> for DbError {
    fn from(err: libmdbx::ReadError) -> Self {
        match err {
            libmdbx::ReadError::Mdbx(err) => Self::Mdbx(err),
            libmdbx::ReadError::Decoding(err) => Self::Decoding(err.to_string()),
        }
    }
}
