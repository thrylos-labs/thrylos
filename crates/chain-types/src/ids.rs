//! Small newtypes around consensus-critical integers, so e.g. a block
//! height can never be passed where a round number was expected.

use crate::codec::{CodecError, Decode, Encode};

macro_rules! u64_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u64);

        impl Encode for $name {
            fn encode(&self, out: &mut Vec<u8>) {
                self.0.encode(out);
            }
        }

        impl Decode for $name {
            fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
                let (value, used) = u64::decode(input)?;
                Ok((Self(value), used))
            }
        }
    };
}

u64_newtype!(
    /// Identifies which chain a signed payload belongs to. See
    /// `docs/spec.md`, "Transaction validity": absent it, "signatures
    /// replay across forks and testnets".
    ChainId
);

u64_newtype!(
    /// Block height, counted from genesis at 0.
    BlockHeight
);

u64_newtype!(
    /// Consensus round within a height.
    Round
);
