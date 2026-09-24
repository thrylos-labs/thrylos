//! What the small hand-written HTTP servers (the faucet's Discord endpoint
//! and the explorer) share to stay up under slow or numerous clients.
//!
//! They used to serve one connection at a time with only a per-read timeout,
//! so one silent client held the server for that timeout, and one that sent a
//! byte inside every timeout held it indefinitely: a slowloris. Two limits fix
//! that: a deadline for the *whole* request, and a cap on connections served
//! at once, past which a new connection is closed at once.

// Wall-clock timing on a local socket; nothing here reaches the state
// transition the `Instant::now` ban protects (see `clippy.toml`).
#![allow(clippy::disallowed_methods)]

use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a client has to send a whole request, however steadily.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// Connections served at the same time.
pub const MAX_CONCURRENT: usize = 16;

/// When the request now beginning must be complete.
pub fn deadline() -> Option<Instant> {
    Instant::now().checked_add(REQUEST_DEADLINE)
}

/// The whole-request deadline passed (or the socket refused a timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlinePassed;

/// Cuts `stream`'s read timeout to what is left of `deadline` (never more than
/// `per_read`). `Err` once the deadline has passed. Call before every read.
pub fn budget(
    stream: &TcpStream,
    deadline: Option<Instant>,
    per_read: Duration,
) -> Result<(), DeadlinePassed> {
    let Some(deadline) = deadline else {
        return Ok(());
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(DeadlinePassed);
    }
    stream
        .set_read_timeout(Some(left.min(per_read)))
        .map_err(|_| DeadlinePassed)
}

/// A count of connections being served, so there can be a limit.
#[derive(Clone, Default)]
pub struct Slots(Arc<AtomicUsize>);

/// One connection's place; dropping it frees the place.
pub struct Slot(Arc<AtomicUsize>);

impl Slots {
    /// A place for one more connection, or `None` if `max` are being served.
    pub fn take(&self, max: usize) -> Option<Slot> {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            if current >= max {
                return None;
            }
            match self.0.compare_exchange(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Slot(Arc::clone(&self.0))),
                Err(actual) => current = actual,
            }
        }
    }

    pub fn in_use(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn places_are_limited_and_freed_when_dropped() {
        let slots = Slots::default();
        let first = slots.take(2).unwrap();
        let second = slots.take(2).unwrap();
        assert!(slots.take(2).is_none(), "full");
        drop(first);
        assert_eq!(slots.in_use(), 1);
        assert!(slots.take(2).is_some(), "a freed place is reusable");
        drop(second);
    }
}
