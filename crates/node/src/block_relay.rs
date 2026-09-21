//! Announcing blocks in compact form, and putting them back together.
//!
//! The host deals in whole blocks and knows nothing of this: it hands out a
//! [`Message::Block`] to broadcast and is handed one to receive, as it always
//! did. This sits between it and the network. On the way out, a block with
//! transactions in it is announced as a [`CompactBlock`] (its header, its hash and
//! a short identifier for each transaction) instead of being sent whole to every
//! peer; on the way in, a compact block is put back together from the
//! transactions this node already holds, and only what it cannot find is asked
//! for, of the peer that announced it. What comes out is an ordinary full block,
//! checked against the hash the announcement carried, and it goes to the host as
//! one received whole would, so nothing the host checks is skipped.
//!
//! **Bounded.** Everything a peer can make this node hold or do is capped: how
//! many announced blocks it remembers to answer requests for, how many
//! reconstructions it keeps waiting, how many compact blocks it will take from one
//! peer at one height, how many times it will answer one peer about one block, and
//! which heights it will look at. Only a validator may announce (and it must be the
//! proposer it names), and only a validator is answered.
//!
//! **Never in the way.** A reconstruction that goes wrong for any reason (a
//! collision, a stale pool, a lying announcement) costs a request for the whole
//! block, then nothing more; the host's own timeouts and catch-up take over, as
//! they would for a block that never arrived.

use std::collections::{BTreeMap, VecDeque};

use chain_consensus::host::{Message, ProposedBlock};
use chain_p2p::relay::{short_id, BlockTransactions, CompactBlock, ShortId, TransactionRequest};
use chain_p2p::{NetworkMessage, PeerId};
use chain_types::{Address, Hash, Transaction};

/// Announced blocks remembered, to answer requests about.
pub const MAX_ANNOUNCED: usize = 4;
/// Compact blocks kept waiting for what they were missing.
pub const MAX_WAITING: usize = 8;
/// How many heights past its own a node will look at a compact block for, as
/// far as the host holds blocks for.
pub const MAX_HEIGHTS_AHEAD: u64 = 2;
/// Compact blocks taken from one peer at one height: a proposer announces one
/// per round it proposes in.
pub const MAX_COMPACT_PER_PEER_HEIGHT: u8 = 4;
/// Answers given to one peer about one block.
pub const MAX_ANSWERS_PER_PEER_BLOCK: u8 = 2;

/// The transactions a node holds, that a compact block is looked up in.
pub trait PendingTransactions {
    /// Calls `visit` on each pending transaction.
    fn for_each_pending(&self, visit: &mut dyn FnMut(&Transaction));
}

/// What the relay has done, for whoever watches how well it is working.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// Blocks announced in compact form.
    pub announced_compact: u64,
    /// Blocks sent whole, because they had nothing to leave out.
    pub announced_whole: u64,
    /// Compact blocks put back together from what this node already held.
    pub rebuilt_from_pool: u64,
    /// Requests made for what was missing.
    pub requests_made: u64,
    /// Transactions asked for in all.
    pub transactions_requested: u64,
    /// Compact blocks put back together after the missing part came.
    pub rebuilt_after_request: u64,
    /// Requests answered.
    pub requests_answered: u64,
    /// Compact blocks, requests and answers set aside as unwanted or wrong.
    pub set_aside: u64,
}

/// What became of something received.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// A whole block, for the host.
    Block(Box<ProposedBlock>),
    /// A request to send, to `peer`.
    Ask {
        peer: PeerId,
        request: TransactionRequest,
    },
    /// Nothing more to do with it.
    Nothing,
}

/// A compact block waiting for the transactions it lacked.
struct Waiting {
    compact: CompactBlock,
    from: PeerId,
    /// What has been found so far, by position.
    found: Vec<Option<Transaction>>,
    /// The positions asked for, in the order asked.
    missing: Vec<u32>,
    /// Whether the whole block has been asked for, which is the last resort.
    asked_for_all: bool,
}

/// The relay's memory. See the module docs.
#[derive(Default)]
pub struct BlockRelay {
    announced: VecDeque<(Hash, Vec<Transaction>)>,
    waiting: Vec<Waiting>,
    compact_seen: BTreeMap<(PeerId, u64), u8>,
    answers: BTreeMap<(PeerId, Hash), u8>,
    stats: RelayStats,
}

impl BlockRelay {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn stats(&self) -> RelayStats {
        self.stats
    }

    fn set_aside(&mut self) -> Received {
        self.stats.set_aside = self.stats.set_aside.saturating_add(1);
        Received::Nothing
    }

    /// The message to broadcast for `proposed`: a compact block if it has
    /// transactions to leave out, the block itself if not.
    pub fn announce(&mut self, proposed: &ProposedBlock) -> NetworkMessage {
        let mut nonce = [0u8; 8];
        if proposed.block.transactions.is_empty() || getrandom::fill(&mut nonce).is_err() {
            self.stats.announced_whole = self.stats.announced_whole.saturating_add(1);
            return NetworkMessage::Consensus(Message::Block(proposed.clone()));
        }
        let compact = CompactBlock::announce(proposed, nonce);
        if self.announced.len() >= MAX_ANNOUNCED {
            if let Some((forgotten, _)) = self.announced.pop_front() {
                self.answers.retain(|(_, hash), _| *hash != forgotten);
            }
        }
        self.announced
            .push_back((compact.block_hash, proposed.block.transactions.clone()));
        self.stats.announced_compact = self.stats.announced_compact.saturating_add(1);
        NetworkMessage::CompactBlock(compact)
    }

    /// Drops what is about heights the node has passed.
    fn prune(&mut self, host_height: u64) {
        self.waiting
            .retain(|waiting| waiting.compact.height.0 >= host_height);
        self.compact_seen
            .retain(|(_, height), _| *height >= host_height);
    }

    /// A compact block from `from`, which is the validator `from_validator` if
    /// it is one. `host_height` is the height the host is running.
    pub fn receive_compact(
        &mut self,
        compact: CompactBlock,
        from: PeerId,
        from_validator: Option<Address>,
        pending: &dyn PendingTransactions,
        host_height: u64,
    ) -> Received {
        // Only a validator announces, and only its own blocks.
        if from_validator != Some(compact.proposer) {
            return self.set_aside();
        }
        let height = compact.height.0;
        if height < host_height || height > host_height.saturating_add(MAX_HEIGHTS_AHEAD) {
            return self.set_aside();
        }
        self.prune(host_height);
        if self
            .waiting
            .iter()
            .any(|waiting| waiting.compact.block_hash == compact.block_hash)
        {
            return Received::Nothing;
        }
        let seen = self.compact_seen.entry((from, height)).or_default();
        if *seen >= MAX_COMPACT_PER_PEER_HEIGHT {
            return self.set_aside();
        }
        *seen = seen.saturating_add(1);

        let found = find(&compact, pending);
        self.settle(compact, from, found, false)
    }

    /// With what has been found, either the block, or a request for the rest.
    fn settle(
        &mut self,
        compact: CompactBlock,
        from: PeerId,
        found: Vec<Option<Transaction>>,
        asked_for_all: bool,
    ) -> Received {
        let missing: Vec<u32> = found
            .iter()
            .enumerate()
            .filter(|(_, transaction)| transaction.is_none())
            .map(|(index, _)| u32::try_from(index).unwrap_or(u32::MAX))
            .collect();
        if missing.is_empty() {
            let transactions: Vec<Transaction> = found.into_iter().flatten().collect();
            return match compact.assemble(transactions) {
                Some(block) => {
                    self.stats.rebuilt_from_pool = self.stats.rebuilt_from_pool.saturating_add(1);
                    Received::Block(Box::new(block))
                }
                // Everything matched and it is still not the block: a collision,
                // or a held transaction that is not the one meant. Ask for all.
                None if !asked_for_all => self.ask_for_all(compact, from),
                None => self.set_aside(),
            };
        }
        let request = TransactionRequest {
            block_hash: compact.block_hash,
            indexes: missing.clone(),
        };
        self.stats.requests_made = self.stats.requests_made.saturating_add(1);
        self.stats.transactions_requested = self
            .stats
            .transactions_requested
            .saturating_add(u64::try_from(missing.len()).unwrap_or(u64::MAX));
        if self.waiting.len() >= MAX_WAITING {
            // The oldest height goes: its block has the least time left.
            if let Some(oldest) = self
                .waiting
                .iter()
                .enumerate()
                .min_by_key(|(_, waiting)| waiting.compact.height.0)
                .map(|(index, _)| index)
            {
                self.waiting.remove(oldest);
            }
        }
        self.waiting.push(Waiting {
            compact,
            from,
            found,
            missing,
            asked_for_all,
        });
        Received::Ask {
            peer: from,
            request,
        }
    }

    fn ask_for_all(&mut self, compact: CompactBlock, from: PeerId) -> Received {
        let count = compact.short_ids.len();
        self.settle(compact, from, vec![None; count], true)
    }

    /// The answer to a request this node made, from `from`.
    pub fn receive_answer(&mut self, answer: BlockTransactions, from: PeerId) -> Received {
        let Some(position) = self.waiting.iter().position(|waiting| {
            waiting.compact.block_hash == answer.block_hash && waiting.from == from
        }) else {
            // Not asked for, or not of that peer.
            return self.set_aside();
        };
        let waiting = self.waiting.remove(position);
        if answer.transactions.len() != waiting.missing.len() {
            return self.set_aside();
        }
        let mut found = waiting.found;
        for (index, transaction) in waiting.missing.iter().zip(answer.transactions) {
            if let Some(slot) = usize::try_from(*index).ok().and_then(|i| found.get_mut(i)) {
                *slot = Some(transaction);
            }
        }
        if found.iter().any(Option::is_none) {
            return self.set_aside();
        }
        let transactions: Vec<Transaction> = found.into_iter().flatten().collect();
        match waiting.compact.assemble(transactions) {
            Some(block) => {
                self.stats.rebuilt_after_request =
                    self.stats.rebuilt_after_request.saturating_add(1);
                Received::Block(Box::new(block))
            }
            None if !waiting.asked_for_all => self.ask_for_all(waiting.compact, from),
            None => self.set_aside(),
        }
    }

    /// The answer to a request from `from`, for a block this node announced.
    pub fn serve(
        &mut self,
        request: &TransactionRequest,
        from: PeerId,
        from_validator: Option<Address>,
    ) -> Option<BlockTransactions> {
        from_validator?;
        let (_, transactions) = self
            .announced
            .iter()
            .find(|(hash, _)| *hash == request.block_hash)?;
        let answer: Vec<Transaction> = request
            .indexes
            .iter()
            .map(|index| {
                usize::try_from(*index)
                    .ok()
                    .and_then(|i| transactions.get(i))
                    .cloned()
            })
            .collect::<Option<_>>()?;
        let answered = self.answers.entry((from, request.block_hash)).or_default();
        if *answered >= MAX_ANSWERS_PER_PEER_BLOCK {
            return None;
        }
        *answered = answered.saturating_add(1);
        self.stats.requests_answered = self.stats.requests_answered.saturating_add(1);
        Some(BlockTransactions {
            block_hash: request.block_hash,
            transactions: answer,
        })
    }
}

/// What a node holds, matched to a compact block's identifiers by position. An
/// identifier that the announcement lists twice, or that two held transactions
/// share, cannot be told apart, and is left as missing.
fn find(compact: &CompactBlock, pending: &dyn PendingTransactions) -> Vec<Option<Transaction>> {
    let key = compact.key();
    let mut wanted: BTreeMap<ShortId, (usize, Vec<Transaction>)> = BTreeMap::new();
    for id in &compact.short_ids {
        let entry = wanted.entry(*id).or_default();
        entry.0 = entry.0.saturating_add(1);
    }
    pending.for_each_pending(&mut |transaction| {
        if let Some((_, candidates)) = wanted.get_mut(&short_id(&key, transaction)) {
            if candidates.len() < 2 {
                candidates.push(transaction.clone());
            }
        }
    });
    compact
        .short_ids
        .iter()
        .map(|id| match wanted.get(id) {
            Some((1, candidates)) if candidates.len() == 1 => candidates.first().cloned(),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::panic
    )]

    use chain_engine_api::Block;
    use chain_types::bls::BlsSignature;
    use chain_types::BlockHeight;

    use super::*;
    use crate::txpool::testing::{bump, DEVNET_CHAIN};

    struct Pool(Vec<Transaction>);

    impl PendingTransactions for Pool {
        fn for_each_pending(&self, visit: &mut dyn FnMut(&Transaction)) {
            self.0.iter().for_each(visit);
        }
    }

    fn tx(n: u64) -> Transaction {
        bump(101 + (n % 4) as u8, DEVNET_CHAIN, n / 4, 1)
    }

    fn proposer() -> Address {
        Address::from_bytes([7; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    fn block(height: u64, count: u64) -> ProposedBlock {
        let secret = blst::min_pk::SecretKey::key_gen(&[5; 32], &[]).unwrap();
        ProposedBlock {
            proposer: proposer(),
            block: Block {
                parent_block_hash: Hash::from_bytes([3; 32]),
                height: BlockHeight(height),
                timestamp_millis: 1_700_000_000_000 + height,
                transactions: (0..count).map(tx).collect(),
            },
            reveal: BlsSignature::from_bytes(
                secret
                    .sign(b"r", chain_types::bls::DST_VOTE, &[])
                    .to_bytes(),
            )
            .unwrap(),
        }
    }

    fn compact_of(relay: &mut BlockRelay, proposed: &ProposedBlock) -> CompactBlock {
        match relay.announce(proposed) {
            NetworkMessage::CompactBlock(compact) => compact,
            other => panic!("{other:?}"),
        }
    }

    fn receive(relay: &mut BlockRelay, compact: CompactBlock, pool: &Pool) -> Received {
        relay.receive_compact(compact, peer(1), Some(proposer()), pool, 5)
    }

    #[test]
    fn a_block_with_nothing_to_leave_out_goes_whole_and_one_with_transactions_goes_compact() {
        let mut relay = BlockRelay::new();
        assert!(matches!(
            relay.announce(&block(5, 0)),
            NetworkMessage::Consensus(Message::Block(_))
        ));
        let compact = compact_of(&mut relay, &block(5, 3));
        assert_eq!(compact.short_ids.len(), 3);
        let stats = relay.stats();
        assert_eq!((stats.announced_whole, stats.announced_compact), (1, 1));
    }

    #[test]
    fn a_block_whose_transactions_are_all_held_is_put_back_together_without_asking() {
        let proposed = block(5, 40);
        let mut sender = BlockRelay::new();
        let compact = compact_of(&mut sender, &proposed);
        // The pool holds those and others besides.
        let pool = Pool((0..60).map(tx).collect());
        let mut receiver = BlockRelay::new();
        assert_eq!(
            receive(&mut receiver, compact, &pool),
            Received::Block(Box::new(proposed))
        );
        assert_eq!(receiver.stats().rebuilt_from_pool, 1);
        assert_eq!(receiver.stats().requests_made, 0);
    }

    #[test]
    fn what_is_not_held_is_asked_for_by_position_of_the_announcer_and_the_answer_completes_it() {
        let proposed = block(5, 10);
        let mut sender = BlockRelay::new();
        let compact = compact_of(&mut sender, &proposed);
        // Held: all but positions 2, 3 and 8.
        let pool = Pool(
            proposed
                .block
                .transactions
                .iter()
                .enumerate()
                .filter(|(i, _)| ![2, 3, 8].contains(i))
                .map(|(_, t)| t.clone())
                .collect(),
        );
        let mut receiver = BlockRelay::new();
        let Received::Ask {
            peer: asked,
            request,
        } = receive(&mut receiver, compact.clone(), &pool)
        else {
            panic!("it should ask");
        };
        assert_eq!(asked, peer(1), "the one that announced it");
        assert_eq!(request.indexes, vec![2, 3, 8]);
        assert_eq!(request.block_hash, compact.block_hash);

        // The announcer answers, in the order asked.
        let answer = sender
            .serve(&request, peer(2), Some(Address::from_bytes([8; 32])))
            .unwrap();
        assert_eq!(answer.transactions.len(), 3);
        assert_eq!(answer.transactions[0], proposed.block.transactions[2]);
        assert_eq!(
            receiver.receive_answer(answer, peer(1)),
            Received::Block(Box::new(proposed))
        );
        let stats = receiver.stats();
        assert_eq!((stats.requests_made, stats.transactions_requested), (1, 3));
        assert_eq!(stats.rebuilt_after_request, 1);
        assert!(receiver.waiting.is_empty());
    }

    #[test]
    fn a_node_that_holds_nothing_asks_for_everything_and_still_ends_with_the_block() {
        let proposed = block(5, 7);
        let mut sender = BlockRelay::new();
        let compact = compact_of(&mut sender, &proposed);
        let mut receiver = BlockRelay::new();
        let Received::Ask { request, .. } = receive(&mut receiver, compact, &Pool(Vec::new()))
        else {
            panic!();
        };
        assert_eq!(request.indexes, (0..7).collect::<Vec<u32>>());
        let answer = sender.serve(&request, peer(1), Some(proposer())).unwrap();
        assert_eq!(
            receiver.receive_answer(answer, peer(1)),
            Received::Block(Box::new(proposed))
        );
    }

    #[test]
    fn a_pool_that_holds_the_wrong_transaction_under_a_matching_id_falls_back_to_the_whole_block() {
        // Ambiguity is what a collision looks like: the same identifier twice in
        // the pool. It cannot be told which is meant, so it is asked for.
        let proposed = block(5, 5);
        let mut sender = BlockRelay::new();
        let compact = compact_of(&mut sender, &proposed);
        let mut held = proposed.block.transactions.clone();
        held.push(proposed.block.transactions[2].clone());
        let mut receiver = BlockRelay::new();
        let Received::Ask { request, .. } = receive(&mut receiver, compact, &Pool(held)) else {
            panic!();
        };
        assert_eq!(
            request.indexes,
            vec![2],
            "only the one that could not be told apart"
        );

        // And an announcement that lists an identifier twice cannot be matched
        // for either position.
        let mut doubled = compact_of(&mut BlockRelay::new(), &proposed);
        doubled.short_ids[4] = doubled.short_ids[1];
        let mut receiver = BlockRelay::new();
        let Received::Ask { request, .. } = receive(
            &mut receiver,
            doubled,
            &Pool(proposed.block.transactions.clone()),
        ) else {
            panic!();
        };
        assert_eq!(request.indexes, vec![1, 4]);
    }

    #[test]
    fn an_answer_that_does_not_make_the_announced_block_is_tried_once_more_for_all_of_it_then_given_up(
    ) {
        let proposed = block(5, 4);
        let mut sender = BlockRelay::new();
        let compact = compact_of(&mut sender, &proposed);
        let mut receiver = BlockRelay::new();
        let Received::Ask { request, .. } = receive(&mut receiver, compact, &Pool(Vec::new()))
        else {
            panic!();
        };
        // A lie: the right number of transactions, and not the block's.
        let lie = BlockTransactions {
            block_hash: request.block_hash,
            transactions: (100..104).map(tx).collect(),
        };
        let Received::Ask { request: again, .. } = receiver.receive_answer(lie.clone(), peer(1))
        else {
            panic!("it should ask once more");
        };
        assert_eq!(again.indexes.len(), 4);
        assert_eq!(receiver.receive_answer(lie, peer(1)), Received::Nothing);
        assert!(receiver.waiting.is_empty());
        assert_eq!(receiver.stats().set_aside, 1);
    }

    #[test]
    fn only_the_proposer_a_validator_may_announce_and_only_for_heights_the_host_can_use() {
        let proposed = block(5, 3);
        let compact = compact_of(&mut BlockRelay::new(), &proposed);
        let pool = Pool(proposed.block.transactions.clone());
        for (from_validator, host_height) in [
            (None, 5),                               // not a validator
            (Some(Address::from_bytes([9; 32])), 5), // a validator, but not its block
            (Some(proposer()), 6),                   // a height already passed
            (Some(proposer()), 1),                   // too far ahead
        ] {
            let mut relay = BlockRelay::new();
            let got =
                relay.receive_compact(compact.clone(), peer(1), from_validator, &pool, host_height);
            assert_eq!(
                got,
                Received::Nothing,
                "{from_validator:?} at {host_height}"
            );
            assert_eq!(relay.stats().set_aside, 1);
        }
        // The window is the host's height and the two after it.
        for host_height in [3, 4, 5] {
            let mut relay = BlockRelay::new();
            assert!(matches!(
                relay.receive_compact(
                    compact.clone(),
                    peer(1),
                    Some(proposer()),
                    &pool,
                    host_height
                ),
                Received::Block(_)
            ));
        }
    }

    #[test]
    fn a_peer_is_taken_from_only_so_often_at_a_height_and_a_block_is_not_awaited_twice() {
        let mut relay = BlockRelay::new();
        let pool = Pool(Vec::new());
        // The same announcement again while its transactions are awaited: nothing.
        let one = compact_of(&mut BlockRelay::new(), &block(5, 3));
        assert!(matches!(
            receive(&mut relay, one.clone(), &pool),
            Received::Ask { .. }
        ));
        assert_eq!(receive(&mut relay, one, &pool), Received::Nothing);
        assert_eq!(relay.waiting.len(), 1);

        // Different blocks at one height, from one peer: the fifth is set aside.
        let mut results = Vec::new();
        for n in 0..6 {
            let other = compact_of(&mut BlockRelay::new(), &block(5, 4 + n));
            results.push(receive(&mut relay, other, &pool));
        }
        let asked = results
            .iter()
            .filter(|r| matches!(r, Received::Ask { .. }))
            .count();
        assert_eq!(
            asked,
            usize::from(MAX_COMPACT_PER_PEER_HEIGHT) - 1,
            "one was used above"
        );
        assert!(relay.stats().set_aside >= 2);
    }

    #[test]
    fn only_so_many_reconstructions_wait_and_the_oldest_height_goes_first() {
        let mut relay = BlockRelay::new();
        let pool = Pool(Vec::new());
        for n in 0..u8::try_from(MAX_WAITING + 3).unwrap() {
            // Distinct peers, so the per-peer limit is not what stops it.
            let height = 5 + u64::from(n % 3);
            let compact = compact_of(&mut BlockRelay::new(), &block(height, 3 + u64::from(n)));
            let _ = relay.receive_compact(compact, peer(n), Some(proposer()), &pool, 5);
        }
        assert_eq!(relay.waiting.len(), MAX_WAITING);
        // What was dropped to make room was the lowest heights, not the newest.
        let lowest = relay
            .waiting
            .iter()
            .map(|w| w.compact.height.0)
            .min()
            .unwrap();
        assert!(lowest >= 5);
    }

    #[test]
    fn what_is_waiting_for_a_height_that_has_passed_is_forgotten() {
        let mut relay = BlockRelay::new();
        let compact = compact_of(&mut BlockRelay::new(), &block(5, 3));
        let _ = relay.receive_compact(compact, peer(1), Some(proposer()), &Pool(Vec::new()), 5);
        assert_eq!(relay.waiting.len(), 1);
        let later = compact_of(&mut BlockRelay::new(), &block(8, 3));
        let _ = relay.receive_compact(later, peer(1), Some(proposer()), &Pool(Vec::new()), 7);
        assert!(
            relay.waiting.iter().all(|w| w.compact.height.0 >= 7),
            "height 5 is behind"
        );
    }

    #[test]
    fn an_answer_nobody_asked_for_or_from_the_wrong_peer_or_the_wrong_size_is_set_aside() {
        let proposed = block(5, 6);
        let mut sender = BlockRelay::new();
        let compact = compact_of(&mut sender, &proposed);
        let mut receiver = BlockRelay::new();
        // Nothing asked yet.
        let stray = BlockTransactions {
            block_hash: compact.block_hash,
            transactions: vec![tx(1)],
        };
        assert_eq!(
            receiver.receive_answer(stray.clone(), peer(1)),
            Received::Nothing
        );

        let Received::Ask { request, .. } = receive(&mut receiver, compact, &Pool(Vec::new()))
        else {
            panic!();
        };
        let right = sender.serve(&request, peer(1), Some(proposer())).unwrap();
        // From someone else: not taken, and the wait is undisturbed.
        assert_eq!(
            receiver.receive_answer(right.clone(), peer(9)),
            Received::Nothing
        );
        assert_eq!(receiver.waiting.len(), 1);
        // The wrong number of transactions from the right peer: dropped.
        assert_eq!(receiver.receive_answer(stray, peer(1)), Received::Nothing);
        assert!(receiver.waiting.is_empty());
        assert!(receiver.stats().set_aside >= 3);
    }

    #[test]
    fn a_request_is_answered_only_for_a_block_this_node_announced_to_a_validator_and_only_so_often()
    {
        let proposed = block(5, 6);
        let mut relay = BlockRelay::new();
        let compact = compact_of(&mut relay, &proposed);
        let ask = |indexes: Vec<u32>| TransactionRequest {
            block_hash: compact.block_hash,
            indexes,
        };
        let validator = Some(Address::from_bytes([8; 32]));

        assert!(
            relay.serve(&ask(vec![0]), peer(2), None).is_none(),
            "a stranger is not answered"
        );
        assert!(
            relay
                .serve(
                    &TransactionRequest {
                        block_hash: Hash::from_bytes([1; 32]),
                        indexes: vec![0]
                    },
                    peer(2),
                    validator
                )
                .is_none(),
            "not a block announced here"
        );
        assert!(
            relay.serve(&ask(vec![0, 6]), peer(2), validator).is_none(),
            "a position past the end"
        );

        let answer = relay.serve(&ask(vec![5, 0]), peer(2), validator).unwrap();
        assert_eq!(
            answer.transactions,
            vec![tx(5), tx(0)],
            "in the order asked"
        );
        assert!(relay.serve(&ask(vec![1]), peer(2), validator).is_some());
        assert!(
            relay.serve(&ask(vec![2]), peer(2), validator).is_none(),
            "not a third time to one peer"
        );
        assert!(
            relay.serve(&ask(vec![2]), peer(3), validator).is_some(),
            "another peer is another count"
        );
        assert_eq!(relay.stats().requests_answered, 3);
    }

    #[test]
    fn only_the_last_few_announced_blocks_can_still_be_asked_about() {
        let mut relay = BlockRelay::new();
        let first = compact_of(&mut relay, &block(5, 3));
        for n in 1..=MAX_ANNOUNCED as u64 {
            compact_of(&mut relay, &block(5 + n, 3));
        }
        let request = TransactionRequest {
            block_hash: first.block_hash,
            indexes: vec![0],
        };
        assert!(
            relay.serve(&request, peer(2), Some(proposer())).is_none(),
            "forgotten"
        );
        assert_eq!(relay.announced.len(), MAX_ANNOUNCED);
    }
}
