//! Errors this crate's own API can return: an MDBX failure, or a
//! decode failure on bytes this crate itself wrote (which would mean
//! on-disk corruption or a schema change, not a normal runtime path).

use chain_types::codec::CodecError;

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
}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mdbx(err) => write!(f, "mdbx error: {err}"),
            Self::Decode(err) => write!(f, "decode error: {err}"),
            Self::Decoding(msg) => write!(f, "mdbx table decode error: {msg}"),
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
