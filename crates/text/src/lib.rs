//! How people read and write chain values: addresses that catch typos, and
//! amounts in tokens rather than raw integers.
//!
//! Tier C, and presentation only. The chain itself deals in 32 raw address
//! bytes and whole numbers of base units; nothing here feeds consensus, and
//! no tier A crate depends on it. It is for the edges: the command-line
//! tools, and RPC once there is one.
//!
//! Two conventions are fixed here, and both become public the moment anyone
//! writes them down, so they are chosen once and explained:
//!
//! - **Addresses** are [`bech32m`](address) with the prefix
//!   [`ADDRESS_PREFIX`] (`thry1…`, 63 characters). One mistyped character is
//!   always caught, so an address that parses is one that was copied
//!   correctly, rather than merely one that happens to be 64 hex digits.
//! - **Amounts** are shown in [`TICKER`] with [`DECIMALS`] decimal places
//!   ([`amount`]), so `1000000000` base units is `1 THRY`.
//!
//! Neither is enforced by the protocol. Changing either later changes what
//! people type and read, not what the chain does.

#![forbid(unsafe_code)]

pub mod address;
pub mod amount;

pub use address::{format_address, parse_address, AddressError, ADDRESS_PREFIX};
pub use amount::{
    format_amount, parse_amount, AmountError, BASE_UNITS_PER_TOKEN, DECIMALS, TICKER,
};
