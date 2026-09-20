//! The node's event loop: what joins the peer network to the driver.
//!
//! [`EventLoop`] takes a [`NodeRuntime`] (the consensus host and its timers)
//! and a [`PeerNetwork`] (the connections) and runs them together in one
//! thread: it feeds the runtime what arrives, fires what has fallen due, and
//! sends what the runtime wants sent. It is deliberately thin. What each
//! message means is the host's business, the timers are the runtime's, and
//! moving bytes is the network's; the loop only decides *when* each of them
//! gets to run.
//!
//! One thread does all the consensus work, so the host never has to be safe to
//! share, and the order in which things are handled is the order they were
//! taken from the queue.
//!
//! **Fairness.** After a wait it handles up to [`MAX_BATCH`] messages before it
//! looks at the clock again, so a flood of messages cannot starve a timer, and
//! a timer cannot starve the messages. It never waits longer than
//! [`MAX_WAIT`], so it notices a stop request promptly.
//!
//! **When it stops.** When asked to, when the host halts (which it reports and
//! returns as an error: a validator that cannot be sure of its own state must
//! not keep running), or, if configured, once the chain reaches a height.
//! Nothing here is needed for the node to be crash-safe; killing the process is
//! always safe, and this is only the orderly way out.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chain_consensus::host::{
    Clock, CommitRecord, HaltReason, SignedLog, Storage, TransactionSource,
};
use chain_engine_api::{ChainView, Engine};
use chain_p2p::NetworkMessage;
use chain_signer::ConsensusSigner;
use chain_types::{Address, BlockHeight, Transaction};

use crate::peer_network::PeerNetwork;
use crate::runtime::{Actions, NodeRuntime, Recipient};

/// The most messages handled between looks at the clock.
pub const MAX_BATCH: usize = 64;

/// The longest the loop waits for a message before looking at the clock and
/// the stop flag again.
pub const MAX_WAIT: Duration = Duration::from_millis(50);

/// Where transactions from peers go: the node's mempool, or
/// [`DiscardTransactions`].
pub trait TransactionIntake {
    /// Offers a transaction that arrived from a peer. Returns it if it was new
    /// and should be passed on to the node's other peers, `None` if it was
    /// refused or already held (which is what stops it going round for ever).
    fn submit(&mut self, transaction: Transaction, now_ms: u64) -> Option<Transaction>;
}

/// Drops every transaction: a node with no mempool yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardTransactions;

impl TransactionIntake for DiscardTransactions {
    fn submit(&mut self, _transaction: Transaction, _now_ms: u64) -> Option<Transaction> {
        None
    }
}

/// What the RPC may learn from, and ask of, the loop it is answered in.
pub trait NodeFacts {
    /// How many peers are connected now.
    fn connected_peers(&self) -> usize;
    /// Why the host stopped, if it has.
    fn halted(&self) -> Option<String>;
    /// The commit record held for `height`, if any.
    fn commit_record(&self, height: BlockHeight) -> Option<CommitRecord>;
    /// Passes a transaction on to every peer.
    fn relay(&self, transaction: &Transaction);
}

/// The node's RPC, from the loop's side: given the chance, between the other
/// things the loop does, it answers what clients have asked.
pub trait RpcPort {
    fn serve(&mut self, facts: &dyn NodeFacts);
}

/// [`NodeFacts`] for a loop: borrows its driver and its network for one pass.
struct LoopFacts<'a, X, T, C, K: ConsensusSigner, L, D> {
    runtime: &'a NodeRuntime<X, T, C, K, L, D>,
    network: &'a PeerNetwork,
}

impl<X, T, C, K, L, D> NodeFacts for LoopFacts<'_, X, T, C, K, L, D>
where
    X: Engine + ChainView,
    T: TransactionSource,
    C: Clock,
    K: ConsensusSigner,
    L: SignedLog,
    D: Storage,
{
    fn connected_peers(&self) -> usize {
        self.network.connected_peers().len()
    }

    fn halted(&self) -> Option<String> {
        self.runtime.halted().map(ToString::to_string)
    }

    fn commit_record(&self, height: BlockHeight) -> Option<CommitRecord> {
        self.runtime.commit_record(height)
    }

    fn relay(&self, transaction: &Transaction) {
        let _ = self.network.send(
            &Recipient::All,
            &NetworkMessage::Transaction(transaction.clone()),
        );
    }
}

/// Something the loop tells its owner about, as it happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// A block was committed.
    Committed {
        height: BlockHeight,
        transactions: usize,
    },
    /// This node witnessed a validator sign two conflicting votes.
    Equivocation { validator: Address },
    /// The host stopped, and with it the node.
    Halted(HaltReason),
}

/// The peer network and the driver, run together. See the module docs.
pub struct EventLoop<X, T, C, K: ConsensusSigner, L, D, I, N> {
    runtime: NodeRuntime<X, T, C, K, L, D>,
    network: PeerNetwork,
    intake: I,
    now: N,
    stop_at: Option<BlockHeight>,
    rpc: Option<Box<dyn RpcPort>>,
}

impl<X, T, C, K, L, D, I, N> EventLoop<X, T, C, K, L, D, I, N>
where
    X: Engine + ChainView,
    T: TransactionSource,
    C: Clock,
    K: ConsensusSigner,
    L: SignedLog,
    D: Storage,
    I: TransactionIntake,
    N: FnMut() -> u64,
{
    /// A loop over `runtime` and `network`. `now` reads the same clock the
    /// host reads, in milliseconds.
    pub fn new(
        runtime: NodeRuntime<X, T, C, K, L, D>,
        network: PeerNetwork,
        intake: I,
        now: N,
    ) -> Self {
        Self {
            runtime,
            network,
            intake,
            now,
            stop_at: None,
            rpc: None,
        }
    }

    /// Answers `rpc`'s clients from this loop, between everything else it does.
    #[must_use]
    pub fn with_rpc(mut self, rpc: Box<dyn RpcPort>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Stop, successfully, once a block at or past `height` is committed.
    #[must_use]
    pub const fn stopping_at(mut self, height: BlockHeight) -> Self {
        self.stop_at = Some(height);
        self
    }

    /// The driver, for reading the chain and the host.
    pub const fn runtime(&self) -> &NodeRuntime<X, T, C, K, L, D> {
        &self.runtime
    }

    /// The peer network, for its counters and connections.
    pub const fn network(&self) -> &PeerNetwork {
        &self.network
    }

    /// Gives back the driver and the network, for a caller that is taking the
    /// node apart.
    pub fn into_parts(self) -> (NodeRuntime<X, T, C, K, L, D>, PeerNetwork) {
        (self.runtime, self.network)
    }

    /// Runs the node until `stop` is set, the host halts, or the configured
    /// height is reached. `report` is told of what happens on the way.
    ///
    /// `Ok` is a stop that was asked for; `Err` is a halt.
    pub fn run(
        &mut self,
        stop: &AtomicBool,
        report: &mut dyn FnMut(NodeEvent),
    ) -> Result<(), HaltReason> {
        let now = (self.now)();
        let started = self.runtime.start(now);
        if self.apply(started, report) {
            return Ok(());
        }
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(reason) = self.runtime.halted() {
                let reason = reason.clone();
                report(NodeEvent::Halted(reason.clone()));
                return Err(reason);
            }

            if let Some(rpc) = self.rpc.as_mut() {
                rpc.serve(&LoopFacts {
                    runtime: &self.runtime,
                    network: &self.network,
                });
            }

            let now = (self.now)();
            let due = self.runtime.on_time(now);
            if self.apply(due, report) {
                return Ok(());
            }

            let wait = self.wait_from(now);
            let mut next = self.network.recv_timeout(wait);
            let mut handled = 0usize;
            while let Some(inbound) = next {
                let now = (self.now)();
                let actions = match inbound.message {
                    NetworkMessage::Consensus(message) => self.runtime.on_message(message, now),
                    NetworkMessage::Transaction(transaction) => {
                        // New to this node: on to everyone else, so it reaches
                        // whichever validator proposes next, not only the one
                        // it was handed to.
                        if let Some(relay) = self.intake.submit(transaction, now) {
                            let _ = self
                                .network
                                .send_except(inbound.from, &NetworkMessage::Transaction(relay));
                        }
                        Actions::default()
                    }
                };
                if self.apply(actions, report) {
                    return Ok(());
                }
                handled = handled.saturating_add(1);
                next = if handled < MAX_BATCH {
                    self.network.recv_timeout(Duration::ZERO)
                } else {
                    None
                };
            }
        }
    }

    /// How long to wait for a message: until the next thing is due, but at
    /// least a millisecond and at most [`MAX_WAIT`].
    fn wait_from(&self, now_ms: u64) -> Duration {
        let until_due = self.runtime.next_due_ms().map_or(MAX_WAIT, |due| {
            Duration::from_millis(due.saturating_sub(now_ms))
        });
        until_due.clamp(Duration::from_millis(1), MAX_WAIT)
    }

    /// Sends what the runtime wants sent and reports what it wants known.
    /// Returns whether the configured stop height was reached.
    fn apply(&mut self, actions: Actions, report: &mut dyn FnMut(NodeEvent)) -> bool {
        for outgoing in actions.outgoing {
            // A message that could not be sent (nobody connected, a full queue)
            // is counted by the network; consensus and sync tolerate the loss.
            let _ = self
                .network
                .send(&outgoing.to, &NetworkMessage::Consensus(outgoing.message));
        }
        let mut reached = false;
        for committed in &actions.committed {
            report(NodeEvent::Committed {
                height: committed.height,
                transactions: committed.block.transactions.len(),
            });
            if self.stop_at.is_some_and(|stop| committed.height >= stop) {
                reached = true;
            }
        }
        for evidence in &actions.evidence {
            report(NodeEvent::Equivocation {
                validator: evidence.validator(),
            });
        }
        reached
    }
}

/// What a node's log line for a committed block starts with. `chain-node` writes
/// the line and the launcher reads the height back out of it, so both go through
/// [`committed_line`] and [`committed_height`].
const COMMITTED: &str = "committed block ";

/// The log line for a committed block.
pub fn committed_line(height: BlockHeight, transactions: usize) -> String {
    format!("{COMMITTED}{height} ({transactions} transactions)")
}

/// The height in a line [`committed_line`] wrote, or `None` for any other line.
pub fn committed_height(line: &str) -> Option<u64> {
    line.strip_prefix(COMMITTED)?
        .split(' ')
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_committed_line_gives_its_height_back() {
        for (height, transactions) in [(1, 0), (7, 3), (u64::MAX, 12_345)] {
            let line = committed_line(BlockHeight(height), transactions);
            assert_eq!(committed_height(&line), Some(height), "{line}");
        }
    }

    #[test]
    fn no_other_line_is_taken_for_one() {
        for line in [
            "",
            "starting validator thry1abc on 127.0.0.1:1 with 3 peers",
            "halted: the signer refused",
            " committed block 5 (0 transactions)",
            "committed block ",
            "committed block five (0 transactions)",
            "committed block -5 (0 transactions)",
            "witnessed equivocation by thry1abc",
        ] {
            assert_eq!(committed_height(line), None, "{line:?}");
        }
    }
}
