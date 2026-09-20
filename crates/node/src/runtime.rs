//! The node's driver: what to do when something happens, with no sockets and
//! no threads.
//!
//! [`NodeRuntime`] owns a consensus [`Host`] and the timers it asks for. It is
//! fed the things that happen (a message from a peer, time passing) and hands
//! back [`Actions`]: the messages to send and to whom, the blocks committed,
//! the equivocation witnessed, and the timer changes it applied. Whatever
//! moves the bytes (real sockets, or the in-process simulation the tests run)
//! does that part and nothing else; everything in between is here, once.
//!
//! Time is always the caller's: every call that needs it takes `now_ms`, on
//! the same clock the host reads, and the runtime never looks at a clock of its
//! own. So the runtime is deterministic, and a test can run a whole network in
//! virtual time.
//!
//! What it does for the host:
//!
//! - **Routes the outbox.** A message the host wants sent to everyone is
//!   [`Recipient::All`]; one for a single validator (a sync request or its
//!   answer) is [`Recipient::Validator`], named by address, since which
//!   connection that is belongs to the layer that owns connections.
//! - **Keeps the timers.** The host asks for a timeout to be scheduled after
//!   some delay, cancelled, or all cancelled; the runtime keeps them ([`Timers`])
//!   and fires them, one at a time, in the order they fall due.
//! - **Wakes the host for what it does on its own.** A node that has fallen
//!   behind asks a peer for what it missed once it has been behind long enough;
//!   the host says when ([`Host::next_wake_ms`]) and the runtime calls
//!   [`Host::tick`] then.
//!
//! The runtime dereferences to its host, so a caller can read anything the host
//! exposes (`halted()`, `chain()`, `height()`). Mutating calls made that way
//! leave their outbox in the host until the next [`NodeRuntime::collect`].

use std::ops::{Deref, DerefMut};

use chain_consensus::host::{
    Clock, Committed, Host, Message, SignedLog, Storage, TimerCommand, TransactionSource,
};
use chain_engine_api::{ChainView, Engine};
use chain_signer::ConsensusSigner;
use chain_types::{Address, DuplicateVoteEvidence};
use malachite_core_types::Timeout;

/// The most timers the runtime will hold at once.
///
/// The host schedules a handful per height (one per step per round) and
/// cancels them all when the height ends, and asking again for a timeout
/// replaces it, so this is never reached in practice. It exists so that a
/// misbehaving host cannot grow the table without bound: past it, the oldest
/// timer is dropped, the least useful one, being the stalest round's.
pub const MAX_TIMERS: usize = 256;

/// The most timers or wake-ups [`NodeRuntime::on_time`] will fire in one call.
/// A caller that is behind by more simply calls it again.
pub const MAX_FIRINGS_PER_CALL: usize = 1_024;

/// Who a message is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// Every other validator.
    All,
    /// One validator, by address.
    Validator(Address),
}

/// A message the host wants sent.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub to: Recipient,
    pub message: Message,
}

/// What the host wanted done, collected since the last time.
#[derive(Debug, Default)]
pub struct Actions {
    /// To send, in the order the host produced them.
    pub outgoing: Vec<Outgoing>,
    /// Blocks committed, in order.
    pub committed: Vec<Committed>,
    /// Equivocation witnessed, ready to be submitted for slashing.
    pub evidence: Vec<DuplicateVoteEvidence>,
    /// The timer changes the host asked for, which the runtime has applied.
    pub timers: Vec<TimerCommand>,
}

impl Actions {
    /// Adds `other`'s actions after these.
    pub fn append(&mut self, mut other: Self) {
        self.outgoing.append(&mut other.outgoing);
        self.committed.append(&mut other.committed);
        self.evidence.append(&mut other.evidence);
        self.timers.append(&mut other.timers);
    }

    /// Whether there is nothing to do.
    pub fn is_empty(&self) -> bool {
        self.outgoing.is_empty()
            && self.committed.is_empty()
            && self.evidence.is_empty()
            && self.timers.is_empty()
    }
}

/// The timers the host has asked for: each a [`Timeout`] and the time it falls
/// due. Asking for a timeout that is already there replaces it.
#[derive(Debug, Default)]
pub struct Timers {
    entries: Vec<(Timeout, u64)>,
}

impl Timers {
    /// Schedules `timeout` for `due_ms`, replacing an earlier one for the same
    /// timeout. At [`MAX_TIMERS`], the oldest is dropped to make room.
    pub fn schedule(&mut self, timeout: Timeout, due_ms: u64) {
        self.entries.retain(|(held, _)| *held != timeout);
        if self.entries.len() >= MAX_TIMERS {
            self.entries.remove(0);
        }
        self.entries.push((timeout, due_ms));
    }

    /// Applies one request the host made, relative to `now_ms`: a timeout to
    /// schedule after a delay, one to cancel, or all of them to cancel. A
    /// delay too long to count in milliseconds saturates.
    pub fn apply(&mut self, command: &TimerCommand, now_ms: u64) {
        match *command {
            TimerCommand::Schedule { timeout, after } => {
                let after = u64::try_from(after.as_millis()).unwrap_or(u64::MAX);
                self.schedule(timeout, now_ms.saturating_add(after));
            }
            TimerCommand::Cancel(timeout) => self.cancel(timeout),
            TimerCommand::CancelAll => self.clear(),
        }
    }

    /// Forgets `timeout`, if it is held.
    pub fn cancel(&mut self, timeout: Timeout) {
        self.entries.retain(|(held, _)| *held != timeout);
    }

    /// Forgets every timer.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// The timer that falls due first, and when. Of several due at the same
    /// time, the one scheduled first.
    pub fn earliest(&self) -> Option<(Timeout, u64)> {
        self.entries.iter().min_by_key(|(_, due)| *due).copied()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A consensus host and its timers. See the module docs.
pub struct NodeRuntime<X, T, C, K: ConsensusSigner, L, D> {
    host: Host<X, T, C, K, L, D>,
    timers: Timers,
}

impl<X, T, C, K, L, D> NodeRuntime<X, T, C, K, L, D>
where
    X: Engine + ChainView,
    T: TransactionSource,
    C: Clock,
    K: ConsensusSigner,
    L: SignedLog,
    D: Storage,
{
    /// A runtime driving `host`, which has not been started.
    pub fn new(host: Host<X, T, C, K, L, D>) -> Self {
        Self {
            host,
            timers: Timers::default(),
        }
    }

    /// Starts the host at the height after its chain's head (replaying its
    /// log if it stopped in the middle of one), and returns what it wants
    /// done.
    pub fn start(&mut self, now_ms: u64) -> Actions {
        self.host.start();
        self.collect(now_ms)
    }

    /// Gives the host a message from a peer, and returns what it wants done.
    pub fn on_message(&mut self, message: Message, now_ms: u64) -> Actions {
        self.host.handle_message(message);
        self.collect(now_ms)
    }

    /// Takes what the host wants done since the last call, applying its timer
    /// requests relative to `now_ms`.
    pub fn collect(&mut self, now_ms: u64) -> Actions {
        let outbox = self.host.take_outbox();
        let mut outgoing =
            Vec::with_capacity(outbox.messages.len().saturating_add(outbox.directed.len()));
        outgoing.extend(outbox.messages.into_iter().map(|message| Outgoing {
            to: Recipient::All,
            message,
        }));
        outgoing.extend(
            outbox
                .directed
                .into_iter()
                .map(|(address, message)| Outgoing {
                    to: Recipient::Validator(address),
                    message,
                }),
        );
        for command in &outbox.timers {
            self.timers.apply(command, now_ms);
        }
        Actions {
            outgoing,
            committed: outbox.committed,
            evidence: outbox.evidence,
            timers: outbox.timers,
        }
    }

    /// When something next needs doing: the earliest of the timers and the
    /// host's own wake-up. `None` when nothing is pending.
    pub fn next_due_ms(&self) -> Option<u64> {
        let timer = self.timers.earliest().map(|(_, due)| due);
        match (timer, self.host.next_wake_ms()) {
            (Some(timer), Some(wake)) => Some(timer.min(wake)),
            (timer, wake) => timer.or(wake),
        }
    }

    /// Fires the one thing that fell due first, if it is due by `now_ms`:
    /// hands the host its timeout, or ticks it. Returns whether anything
    /// fired. What the host does about it stays in its outbox until
    /// [`Self::collect`], so a caller can act between the two.
    ///
    /// A timer wins a tie with the host's wake-up.
    pub fn fire_next(&mut self, now_ms: u64) -> bool {
        let wake = self.host.next_wake_ms();
        if let Some((timeout, due)) = self.timers.earliest() {
            if due <= now_ms && wake.is_none_or(|wake| due <= wake) {
                self.timers.cancel(timeout);
                self.host.handle_timeout(timeout);
                return true;
            }
        }
        if wake.is_some_and(|wake| wake <= now_ms) {
            self.host.tick();
            return true;
        }
        false
    }

    /// Fires everything due by `now_ms`, in order, and returns what the host
    /// wants done about all of it. At most [`MAX_FIRINGS_PER_CALL`] things
    /// fire in one call; call again if the time is still due.
    pub fn on_time(&mut self, now_ms: u64) -> Actions {
        let mut actions = Actions::default();
        for _ in 0..MAX_FIRINGS_PER_CALL {
            if !self.fire_next(now_ms) {
                break;
            }
            actions.append(self.collect(now_ms));
        }
        actions
    }

    /// The timers held.
    pub const fn timers(&self) -> &Timers {
        &self.timers
    }

    /// Stops driving, and gives the host back.
    pub fn into_host(self) -> Host<X, T, C, K, L, D> {
        self.host
    }
}

impl<X, T, C, K: ConsensusSigner, L, D> Deref for NodeRuntime<X, T, C, K, L, D> {
    type Target = Host<X, T, C, K, L, D>;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}

impl<X, T, C, K: ConsensusSigner, L, D> DerefMut for NodeRuntime<X, T, C, K, L, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.host
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use malachite_core_types::Round;

    use super::*;

    fn propose(round: u32) -> Timeout {
        Timeout::propose(Round::new(round))
    }

    fn prevote(round: u32) -> Timeout {
        Timeout::prevote(Round::new(round))
    }

    #[test]
    fn the_earliest_timer_is_the_one_due_first() {
        let mut timers = Timers::default();
        assert_eq!(timers.earliest(), None);
        timers.schedule(propose(0), 300);
        timers.schedule(prevote(0), 100);
        timers.schedule(propose(1), 200);
        assert_eq!(timers.earliest(), Some((prevote(0), 100)));
        timers.cancel(prevote(0));
        assert_eq!(timers.earliest(), Some((propose(1), 200)));
    }

    #[test]
    fn of_timers_due_together_the_one_scheduled_first_comes_first() {
        let mut timers = Timers::default();
        timers.schedule(propose(0), 500);
        timers.schedule(prevote(0), 500);
        timers.schedule(propose(1), 500);
        assert_eq!(timers.earliest(), Some((propose(0), 500)));
        timers.cancel(propose(0));
        assert_eq!(timers.earliest(), Some((prevote(0), 500)));
    }

    #[test]
    fn asking_for_a_timeout_again_replaces_it_and_it_counts_as_scheduled_last() {
        let mut timers = Timers::default();
        timers.schedule(propose(0), 900);
        timers.schedule(prevote(0), 900);
        timers.schedule(propose(0), 900);
        assert_eq!(timers.len(), 2, "one timer per timeout");
        assert_eq!(timers.earliest(), Some((prevote(0), 900)));

        timers.schedule(prevote(0), 50);
        assert_eq!(timers.earliest(), Some((prevote(0), 50)), "the new time");
        assert_eq!(timers.len(), 2);
    }

    #[test]
    fn cancelling_one_leaves_the_rest_and_clearing_leaves_none() {
        let mut timers = Timers::default();
        timers.schedule(propose(0), 1);
        timers.schedule(prevote(0), 2);
        timers.cancel(propose(9));
        assert_eq!(timers.len(), 2, "cancelling what is not there does nothing");
        timers.cancel(propose(0));
        assert_eq!(timers.len(), 1);
        timers.clear();
        assert!(timers.is_empty());
        assert_eq!(timers.earliest(), None);
    }

    #[test]
    fn the_table_is_bounded_and_drops_the_oldest_first() {
        let mut timers = Timers::default();
        let extra = 44;
        for round in 0..u32::try_from(MAX_TIMERS + extra).unwrap() {
            timers.schedule(propose(round), u64::from(round));
        }
        assert_eq!(timers.len(), MAX_TIMERS);
        // The oldest are gone, the newest are held.
        assert_eq!(timers.earliest(), Some((propose(44), 44)));
        let newest = u32::try_from(MAX_TIMERS + extra - 1).unwrap();
        timers.cancel(propose(newest));
        assert_eq!(timers.len(), MAX_TIMERS - 1, "the newest was held");
    }

    #[test]
    fn a_schedule_request_falls_due_a_delay_after_now() {
        use std::time::Duration;

        let mut timers = Timers::default();
        timers.apply(
            &TimerCommand::Schedule {
                timeout: propose(0),
                after: Duration::from_millis(3_000),
            },
            10_000,
        );
        assert_eq!(timers.earliest(), Some((propose(0), 13_000)));
        // Sub-millisecond parts do not count, and later requests use their
        // own "now".
        timers.apply(
            &TimerCommand::Schedule {
                timeout: prevote(0),
                after: Duration::from_micros(2_900),
            },
            20_000,
        );
        assert_eq!(timers.len(), 2);
        timers.cancel(propose(0));
        assert_eq!(timers.earliest(), Some((prevote(0), 20_002)));
    }

    #[test]
    fn a_delay_too_long_to_count_and_a_time_near_the_end_both_saturate() {
        use std::time::Duration;

        let mut timers = Timers::default();
        timers.apply(
            &TimerCommand::Schedule {
                timeout: propose(0),
                after: Duration::MAX,
            },
            5,
        );
        assert_eq!(timers.earliest(), Some((propose(0), u64::MAX)));
        timers.apply(
            &TimerCommand::Schedule {
                timeout: prevote(0),
                after: Duration::from_millis(10),
            },
            u64::MAX - 3,
        );
        // Both saturate to the same instant, so the first scheduled still
        // comes first; with it gone, the other is due then too.
        assert_eq!(timers.earliest(), Some((propose(0), u64::MAX)));
        timers.cancel(propose(0));
        assert_eq!(timers.earliest(), Some((prevote(0), u64::MAX)));
    }

    #[test]
    fn a_cancel_request_removes_that_timer_only_and_cancel_all_removes_every_timer() {
        use std::time::Duration;

        let after = Duration::from_millis(1);
        let mut timers = Timers::default();
        for timeout in [propose(0), prevote(0), propose(1)] {
            timers.apply(&TimerCommand::Schedule { timeout, after }, 0);
        }
        timers.apply(&TimerCommand::Cancel(prevote(0)), 0);
        assert_eq!(timers.len(), 2);
        timers.apply(&TimerCommand::Cancel(prevote(0)), 0);
        assert_eq!(timers.len(), 2, "cancelling what is gone changes nothing");
        timers.apply(&TimerCommand::Cancel(propose(0)), 0);
        assert_eq!(
            timers.earliest().map(|(timeout, _)| timeout),
            Some(propose(1))
        );
        timers.apply(
            &TimerCommand::Schedule {
                timeout: prevote(1),
                after,
            },
            0,
        );
        timers.apply(&TimerCommand::CancelAll, 0);
        assert!(timers.is_empty());
    }

    #[test]
    fn actions_append_in_order_and_know_when_they_are_empty() {
        let mut actions = Actions::default();
        assert!(actions.is_empty());
        let mut later = Actions::default();
        later.timers.push(TimerCommand::CancelAll);
        later.timers.push(TimerCommand::Cancel(propose(0)));
        actions.append(later);
        assert!(!actions.is_empty());
        assert_eq!(
            actions.timers,
            vec![TimerCommand::CancelAll, TimerCommand::Cancel(propose(0))]
        );
        let mut more = Actions::default();
        more.timers.push(TimerCommand::Cancel(propose(1)));
        actions.append(more);
        assert_eq!(actions.timers.len(), 3);
        assert_eq!(actions.timers[2], TimerCommand::Cancel(propose(1)));
    }
}
