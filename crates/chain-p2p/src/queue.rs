//! A fixed-capacity queue with an explicit drop policy. `docs/spec.md`,
//! "P2P and mempool": "Every queue is fixed-capacity with an explicit
//! drop policy. No `Vec::push` in a loop driven by remote input."

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropPolicy {
    /// Reject the incoming item; whatever is already queued stays.
    DropNewest,
    /// Evict the oldest queued item to make room for the incoming one.
    DropOldest,
}

pub struct BoundedQueue<T> {
    capacity: usize,
    policy: DropPolicy,
    items: VecDeque<T>,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize, policy: DropPolicy) -> Self {
        Self {
            capacity,
            policy,
            items: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Enqueues `item`. Returns the item that had to be dropped to
    /// make room for it, if any: `item` itself under
    /// [`DropPolicy::DropNewest`] when already full, or the previous
    /// front under [`DropPolicy::DropOldest`].
    pub fn push(&mut self, item: T) -> Option<T> {
        if self.items.len() < self.capacity {
            self.items.push_back(item);
            return None;
        }
        match self.policy {
            DropPolicy::DropNewest => Some(item),
            DropPolicy::DropOldest => {
                let evicted = self.items.pop_front();
                self.items.push_back(item);
                evicted
            }
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queues_up_to_capacity_without_dropping() {
        let mut queue = BoundedQueue::new(2, DropPolicy::DropNewest);
        assert_eq!(queue.push(1), None);
        assert_eq!(queue.push(2), None);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn drop_newest_rejects_the_incoming_item_when_full() {
        let mut queue = BoundedQueue::new(1, DropPolicy::DropNewest);
        assert_eq!(queue.push(1), None);
        assert_eq!(
            queue.push(2),
            Some(2),
            "the newest item is what gets dropped"
        );
        assert_eq!(queue.pop(), Some(1), "the original item is still queued");
    }

    #[test]
    fn drop_oldest_evicts_the_front_to_admit_the_incoming_item() {
        let mut queue = BoundedQueue::new(1, DropPolicy::DropOldest);
        assert_eq!(queue.push(1), None);
        assert_eq!(
            queue.push(2),
            Some(1),
            "the oldest item is what gets evicted"
        );
        assert_eq!(queue.pop(), Some(2), "the incoming item is now queued");
        assert!(queue.is_empty());
    }

    #[test]
    fn never_exceeds_its_declared_capacity() {
        let mut queue = BoundedQueue::new(3, DropPolicy::DropOldest);
        for i in 0..100 {
            queue.push(i);
            assert!(queue.len() <= queue.capacity());
        }
    }
}
