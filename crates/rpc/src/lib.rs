//! JSON-RPC, tracing.
//!
//! Tier C. Failure if wrong: Local only.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! The interface a node offers to the machine it runs on: six JSON-RPC 2.0
//! methods over a small, bounded, loopback-only HTTP server. [`call`] is the
//! protocol (what may be asked, how it is read and answered) and [`server`] is
//! the transport. Nothing here knows about a chain: a request becomes a
//! [`Call`], the node answers it from its own thread through the [`Inbox`], and
//! the answer goes back as JSON. That keeps everything that can touch the node's
//! state on the one thread that owns it.
//!
//! What is deliberately not here, because the spec's gates do not need it:
//! subscriptions, batches, a transaction index, receipts, tracing, and any
//! authentication (the server is local only; a proxy in front of it is the
//! operator's).

#![forbid(unsafe_code)]

pub mod call;
pub mod hex;
pub mod server;

pub use call::{Call, Reply, Request, RpcError, MAX_TRANSACTION_BYTES};
pub use server::{Inbox, Pending, Server, ServerConfig, ServerError};
