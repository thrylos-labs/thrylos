//! `devnet check`: is the network committing, and do its nodes agree on where it
//! is? The first two steps of the spec's halt runbook ("Halt recovery"), and no
//! more.
//!
//! 1. **Detect.** "Validators observe no commit for 10 consecutive round
//!    timeouts": a node whose newest block is older than [`HALT_AFTER`] has not
//!    committed for that long.
//! 2. **Diagnose.** "The last committed height and state root are canonical.
//!    Every node publishes its last commit certificate; agreement on that
//!    certificate defines the recovery point." Each node's certificate is asked for
//!    at the lowest height they all have, and they must be the same block with the
//!    same state root.
//!
//! It only asks the nodes' RPCs, so it needs their processes running. A node that
//! cannot be reached is a finding, not something it works around. What it does
//! *not* do: check the certificates' signatures (it compares what the nodes say),
//! or roll a node back. A network whose nodes disagree is reported, and stops
//! there.

// Indexing a `serde_json::Value` by a name never panics: what is missing reads as
// `null`. The lint cannot know that.
#![allow(clippy::indexing_slicing)]
// The age of a block is against the wall clock, which nothing consensus reads.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::client::{ClientError, RpcClient};
use crate::config::NodeConfig;
use crate::devnet::nodes_in;

/// Ten round timeouts of two seconds: the spec's rule for calling a stall a halt.
pub const HALT_AFTER: Duration = Duration::from_secs(20);

/// The block a commit certificate is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

/// What one node said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeState {
    pub number: usize,
    /// Where this node's RPC listens.
    pub rpc: SocketAddr,
    /// Why it could not be asked, if it could not.
    pub unreachable: Option<String>,
    /// When its newest block was made, in milliseconds since the Unix epoch.
    pub block_time_ms: u64,
    /// Why its host stopped, if it has.
    pub halted: Option<String>,
    /// Its newest commit certificate, if it holds one.
    pub latest: Option<Certificate>,
    /// Its certificate at the recovery point, when that is not its newest.
    pub at_recovery_point: Option<Certificate>,
}

/// What the check found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Assessment {
    /// What was seen, node by node, and the recovery point if there is one.
    pub notes: Vec<String>,
    /// What is wrong. The network is healthy when there is nothing here.
    pub problems: Vec<String>,
    /// No node could be reached at all, which usually means the network is not
    /// running (or not up yet) and is worth saying how to start.
    pub nobody_answered: bool,
}

impl Assessment {
    /// The whole finding in one line: `healthy`, or how many things are wrong.
    pub fn verdict(&self) -> String {
        match self.problems.len() {
            0 => "healthy".to_owned(),
            1 => "unhealthy: 1 problem".to_owned(),
            count => format!("unhealthy: {count} problems"),
        }
    }
}

/// The height every reachable node has a certificate for: the lowest of the
/// newest each holds.
pub fn recovery_height(states: &[NodeState]) -> Option<u64> {
    states
        .iter()
        .filter(|state| state.unreachable.is_none())
        .filter_map(|state| state.latest.as_ref().map(|cert| cert.height))
        .min()
}

/// What the states amount to at time `now_ms`. See the module docs.
pub fn assess(states: &[NodeState], now_ms: u64) -> Assessment {
    let mut found = Assessment {
        nobody_answered: !states.is_empty() && states.iter().all(|s| s.unreachable.is_some()),
        ..Assessment::default()
    };
    for state in states {
        let number = state.number;
        if let Some(why) = &state.unreachable {
            found.problems.push(format!(
                "node {number} is unreachable (RPC {}): {why}",
                state.rpc
            ));
            continue;
        }
        let age = Duration::from_millis(now_ms.saturating_sub(state.block_time_ms));
        let height = state.latest.as_ref().map_or(0, |cert| cert.height);
        found.notes.push(format!(
            "node {number} (RPC {}): height {height}, newest block {}s old",
            state.rpc,
            age.as_secs()
        ));
        if let Some(reason) = &state.halted {
            found
                .problems
                .push(format!("node {number} has halted: {reason}"));
        }
        if age > HALT_AFTER {
            found.problems.push(format!(
                "node {number} has committed nothing for {}s (the runbook calls {}s a halt)",
                age.as_secs(),
                HALT_AFTER.as_secs()
            ));
        }
        if state.latest.is_none() {
            found
                .problems
                .push(format!("node {number} holds no commit certificate"));
        }
    }

    let Some(height) = recovery_height(states) else {
        return found;
    };
    // Each reachable node's certificate at that height, grouped by what it says.
    let mut claims: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
    for state in states.iter().filter(|s| s.unreachable.is_none()) {
        let held = state
            .at_recovery_point
            .as_ref()
            .or(state.latest.as_ref().filter(|cert| cert.height == height));
        match held {
            Some(cert) => claims
                .entry((&cert.block_hash, &cert.state_root))
                .or_default()
                .push(state.number),
            None => found.problems.push(format!(
                "node {} does not hold the certificate at height {height}",
                state.number
            )),
        }
    }
    match claims.iter().collect::<Vec<_>>().as_slice() {
        [] => {}
        [((block, root), nodes)] => found.notes.push(format!(
            "recovery point: height {height}, block {block}, state root {root}, agreed by {} \
             of {} nodes",
            nodes.len(),
            states.len()
        )),
        several => {
            let says: Vec<String> = several
                .iter()
                .map(|((block, root), nodes)| {
                    format!("nodes {nodes:?} say block {block} with state root {root}")
                })
                .collect();
            found.problems.push(format!(
                "the certificates at height {height} disagree: {}",
                says.join("; ")
            ));
        }
    }
    found
}

fn certificate(commit: &Value) -> Option<Certificate> {
    Some(Certificate {
        height: commit["height"].as_u64()?,
        block_hash: commit["blockHash"].as_str()?.to_owned(),
        state_root: commit["stateRoot"].as_str().unwrap_or("unknown").to_owned(),
    })
}

fn read(number: usize, client: &RpcClient) -> NodeState {
    let mut state = NodeState {
        number,
        rpc: client.address,
        unreachable: None,
        block_time_ms: 0,
        halted: None,
        latest: None,
        at_recovery_point: None,
    };
    match client.call("status", &json!({})) {
        Err(error) => state.unreachable = Some(error.to_string()),
        Ok(status) => {
            state.block_time_ms = status["latest"]["timestampMs"].as_u64().unwrap_or(0);
            state.halted = status["halted"].as_str().map(str::to_owned);
            state.latest = client
                .call("commit", &json!({}))
                .ok()
                .and_then(|commit| certificate(&commit));
        }
    }
    state
}

/// Asks every node of the network in `network`, and assesses what they say.
pub fn check(network: &Path) -> Result<Assessment, ClientError> {
    let nodes = nodes_in(network)?;
    let mut clients = Vec::new();
    for node in &nodes {
        let config =
            NodeConfig::load(&node.config()).map_err(|e| ClientError::Setup(e.to_string()))?;
        let address = config.rpc_listen.ok_or_else(|| {
            ClientError::Setup(format!(
                "node {}'s configuration has no `rpc` section",
                node.number
            ))
        })?;
        clients.push((node.number, RpcClient { address }));
    }

    let mut states: Vec<NodeState> = clients
        .iter()
        .map(|(number, client)| read(*number, client))
        .collect();
    if let Some(height) = recovery_height(&states) {
        for (state, (_, client)) in states.iter_mut().zip(&clients) {
            if state
                .latest
                .as_ref()
                .is_some_and(|cert| cert.height > height)
            {
                state.at_recovery_point = client
                    .call("commit", &json!({ "height": height }))
                    .ok()
                    .and_then(|commit| certificate(&commit));
            }
        }
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    Ok(assess(&states, now_ms))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;

    const NOW: u64 = 1_000_000;

    fn cert(height: u64, block: &str, root: &str) -> Certificate {
        Certificate {
            height,
            block_hash: block.into(),
            state_root: root.into(),
        }
    }

    /// A node that committed `height` `age_s` seconds ago, the block and root
    /// being named for the height.
    fn node(number: usize, height: u64, age_s: u64) -> NodeState {
        NodeState {
            number,
            rpc: format!("127.0.0.1:{}", 30_000 + number).parse().unwrap(),
            unreachable: None,
            block_time_ms: NOW - age_s * 1000,
            halted: None,
            latest: Some(cert(height, &format!("b{height}"), &format!("r{height}"))),
            at_recovery_point: None,
        }
    }

    #[test]
    fn a_network_that_is_committing_and_agrees_is_healthy_and_names_its_recovery_point() {
        let found = assess(&[node(1, 12, 1), node(2, 12, 1), node(3, 12, 2)], NOW);
        assert_eq!(found.problems, Vec::<String>::new());
        assert_eq!(found.notes.len(), 4);
        assert!(
            found.notes[0].contains("node 1 (RPC 127.0.0.1:30001)"),
            "{:?}",
            found.notes
        );
        assert!(
            found.notes[3].contains("recovery point: height 12, block b12, state root r12")
                && found.notes[3].contains("agreed by 3 of 3"),
            "{:?}",
            found.notes
        );
    }

    #[test]
    fn a_node_that_has_committed_nothing_for_over_ten_round_timeouts_is_a_halt() {
        let just_inside = assess(&[node(1, 12, HALT_AFTER.as_secs())], NOW);
        assert!(
            just_inside.problems.is_empty(),
            "{:?}",
            just_inside.problems
        );
        let over = assess(&[node(1, 12, HALT_AFTER.as_secs() + 1)], NOW);
        assert_eq!(over.problems.len(), 1);
        assert!(
            over.problems[0].contains("nothing for 21s"),
            "{:?}",
            over.problems
        );
    }

    #[test]
    fn a_node_that_cannot_be_asked_is_a_finding_and_the_rest_are_still_compared() {
        let mut gone = node(3, 0, 0);
        gone.unreachable = Some("connection refused".into());
        let found = assess(&[node(1, 12, 1), node(2, 12, 1), gone], NOW);
        assert_eq!(found.problems.len(), 1);
        assert!(found.problems[0]
            .contains("node 3 is unreachable (RPC 127.0.0.1:30003): connection refused"));
        assert!(
            found.notes.iter().any(|n| n.contains("agreed by 2 of 3")),
            "{:?}",
            found.notes
        );
    }

    #[test]
    fn the_verdict_is_one_line_that_says_healthy_or_how_many_things_are_wrong() {
        assert_eq!(assess(&[node(1, 12, 1)], NOW).verdict(), "healthy");
        assert_eq!(assess(&[], NOW).verdict(), "healthy", "nothing to be wrong");
        let mut gone = node(2, 0, 0);
        gone.unreachable = Some("refused".into());
        assert_eq!(
            assess(&[node(1, 12, 1), gone.clone()], NOW).verdict(),
            "unhealthy: 1 problem"
        );
        let mut gone_too = gone.clone();
        gone_too.number = 3;
        assert_eq!(
            assess(&[node(1, 12, 1), gone, gone_too], NOW).verdict(),
            "unhealthy: 2 problems"
        );
    }

    #[test]
    fn nobody_answered_is_only_when_every_node_is_unreachable() {
        let down = |number| NodeState {
            unreachable: Some("refused".into()),
            ..node(number, 0, 0)
        };
        assert!(assess(&[down(1), down(2)], NOW).nobody_answered);
        assert!(!assess(&[down(1), node(2, 12, 1)], NOW).nobody_answered);
        assert!(!assess(&[node(1, 12, 1)], NOW).nobody_answered);
        assert!(
            !assess(&[], NOW).nobody_answered,
            "no nodes is not no answers"
        );
    }

    #[test]
    fn a_host_that_has_stopped_says_why() {
        let mut stopped = node(2, 12, 1);
        stopped.halted = Some("the signer refused".into());
        let found = assess(&[node(1, 12, 1), stopped], NOW);
        assert_eq!(found.problems.len(), 1);
        assert!(found.problems[0].contains("node 2 has halted: the signer refused"));
    }

    #[test]
    fn nodes_a_block_apart_are_compared_at_the_height_they_all_have() {
        let mut behind = node(2, 11, 1);
        behind.at_recovery_point = None;
        let mut ahead = node(1, 12, 1);
        // The one that is ahead reports its certificate at 11 as well.
        ahead.at_recovery_point = Some(cert(11, "b11", "r11"));
        let found = assess(&[ahead, behind], NOW);
        assert!(found.problems.is_empty(), "{:?}", found.problems);
        assert!(found
            .notes
            .iter()
            .any(|n| n.contains("height 11") && n.contains("agreed by 2 of 2")));
    }

    #[test]
    fn certificates_for_different_blocks_at_the_recovery_point_are_a_disagreement() {
        let mut other = node(2, 12, 1);
        other.latest = Some(cert(12, "b12", "DIFFERENT"));
        let found = assess(&[node(1, 12, 1), other], NOW);
        assert_eq!(found.problems.len(), 1);
        assert!(
            found.problems[0].contains("disagree"),
            "{:?}",
            found.problems
        );
        assert!(found.problems[0].contains("r12") && found.problems[0].contains("DIFFERENT"));
        assert!(!found.notes.iter().any(|n| n.contains("agreed by")));

        // A different block, the same root: still not the same certificate.
        let mut forked = node(2, 12, 1);
        forked.latest = Some(cert(12, "OTHER", "r12"));
        assert_eq!(assess(&[node(1, 12, 1), forked], NOW).problems.len(), 1);
    }

    #[test]
    fn a_node_ahead_that_no_longer_holds_the_recovery_point_is_a_finding() {
        let ahead = node(1, 15, 1); // no `at_recovery_point`: it could not give it
        let found = assess(&[ahead, node(2, 12, 1)], NOW);
        assert_eq!(found.problems.len(), 1);
        assert!(found.problems[0].contains("node 1 does not hold the certificate at height 12"));
    }

    #[test]
    fn a_node_with_no_certificate_is_a_finding_and_nothing_is_agreed() {
        let mut empty = node(1, 0, 1);
        empty.latest = None;
        let found = assess(&[empty], NOW);
        assert_eq!(found.problems.len(), 1);
        assert!(found.problems[0].contains("holds no commit certificate"));
        assert!(found.notes.iter().all(|n| !n.contains("recovery point")));
        assert_eq!(assess(&[], NOW), Assessment::default());
    }
}
