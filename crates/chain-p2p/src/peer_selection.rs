//! Eclipse-resistant outbound peer selection. `docs/spec.md`, "P2P and
//! mempool": "outbound peers are selected with diversity requirements
//! across IP subnets and ASNs, a fraction of slots is reserved for
//! long-lived peers, and validators additionally hold a configured set
//! of trusted peers."
//!
//! Subnet grouping uses a /24 prefix for IPv4 and a /64 prefix for
//! IPv6 — a deliberate, documented default (a /64 is the smallest
//! block most IPv6 deployments actually allocate, so anything narrower
//! groups nothing; /24 is the common IPv4 eclipse-defense choice),
//! not a value the spec pins down itself. Retune here if it turns out
//! wrong.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::peer_id::PeerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Asn(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidatePeer {
    pub peer: PeerId,
    pub ip: IpAddr,
    pub asn: Asn,
    /// Validator-configured trusted peers: always selected, and never
    /// excluded by a diversity cap (`docs/spec.md`: "validators
    /// additionally hold a configured set of trusted peers").
    pub is_trusted: bool,
    /// How long this peer has been connected, if it's currently
    /// connected at all. `None` — never connected, or not currently —
    /// can never count as long-lived.
    pub connected_for: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionConfig {
    pub target_outbound: usize,
    pub max_per_subnet: usize,
    pub max_per_asn: usize,
    /// How many of `target_outbound`'s non-trusted slots are filled
    /// preferentially from long-lived peers before falling back to
    /// everyone else.
    pub reserved_long_lived_slots: usize,
    pub long_lived_threshold: Duration,
}

fn subnet_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            IpAddr::V4(Ipv4Addr::new(a, b, c, 0))
        }
        IpAddr::V6(v6) => {
            let [a, b, c, d, ..] = v6.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
    }
}

#[derive(Default)]
struct DiversityCounts {
    by_subnet: BTreeMap<IpAddr, usize>,
    by_asn: BTreeMap<u32, usize>,
}

impl DiversityCounts {
    /// Admits `candidate` if doing so would stay within both diversity
    /// caps, recording it if so.
    fn try_admit(&mut self, candidate: &CandidatePeer, config: &SelectionConfig) -> bool {
        let subnet = subnet_key(candidate.ip);
        let subnet_count = self.by_subnet.get(&subnet).copied().unwrap_or(0);
        let asn_count = self.by_asn.get(&candidate.asn.0).copied().unwrap_or(0);
        if subnet_count >= config.max_per_subnet || asn_count >= config.max_per_asn {
            return false;
        }
        *self.by_subnet.entry(subnet).or_insert(0) += 1;
        *self.by_asn.entry(candidate.asn.0).or_insert(0) += 1;
        true
    }
}

fn is_long_lived(candidate: &CandidatePeer, config: &SelectionConfig) -> bool {
    candidate
        .connected_for
        .is_some_and(|duration| duration >= config.long_lived_threshold)
}

/// Selects outbound peers: every trusted peer unconditionally, then
/// long-lived peers up to the reserved fraction, then everyone else —
/// all subject to the subnet/ASN diversity caps except trusted peers.
/// Deterministic given the same `candidates` and `config`: candidates
/// within each tier are considered in `PeerId` order, not connection
/// order, so this is reproducible in tests and doesn't depend on
/// caller-supplied ordering.
pub fn select_outbound_peers(
    candidates: &[CandidatePeer],
    config: &SelectionConfig,
) -> Vec<PeerId> {
    let mut selected = Vec::new();
    let mut counts = DiversityCounts::default();

    let mut trusted: Vec<&CandidatePeer> = candidates.iter().filter(|c| c.is_trusted).collect();
    trusted.sort_by_key(|c| c.peer);
    for candidate in trusted {
        counts.try_admit(candidate, config);
        selected.push(candidate.peer);
    }

    let mut long_lived: Vec<&CandidatePeer> = candidates
        .iter()
        .filter(|c| !c.is_trusted && is_long_lived(c, config))
        .collect();
    long_lived.sort_by_key(|c| c.peer);
    let mut long_lived_admitted = 0usize;
    for candidate in long_lived {
        if selected.len() >= config.target_outbound
            || long_lived_admitted >= config.reserved_long_lived_slots
        {
            break;
        }
        if counts.try_admit(candidate, config) {
            selected.push(candidate.peer);
            long_lived_admitted += 1;
        }
    }

    let mut rest: Vec<&CandidatePeer> = candidates
        .iter()
        .filter(|c| !c.is_trusted && !selected.contains(&c.peer))
        .collect();
    rest.sort_by_key(|c| c.peer);
    for candidate in rest {
        if selected.len() >= config.target_outbound {
            break;
        }
        if counts.try_admit(candidate, config) {
            selected.push(candidate.peer);
        }
    }

    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn candidate(
        byte: u8,
        ip: [u8; 4],
        asn: u32,
        trusted: bool,
        connected_for: Option<Duration>,
    ) -> CandidatePeer {
        CandidatePeer {
            peer: peer(byte),
            ip: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            asn: Asn(asn),
            is_trusted: trusted,
            connected_for,
        }
    }

    fn config() -> SelectionConfig {
        SelectionConfig {
            target_outbound: 8,
            max_per_subnet: 1,
            max_per_asn: 2,
            reserved_long_lived_slots: 2,
            long_lived_threshold: Duration::from_secs(3600),
        }
    }

    #[test]
    fn trusted_peers_are_always_selected() {
        let candidates = vec![candidate(1, [10, 0, 0, 1], 100, true, None)];
        let selected = select_outbound_peers(&candidates, &config());
        assert_eq!(selected, vec![peer(1)]);
    }

    #[test]
    fn a_diversity_cap_excludes_a_second_peer_from_the_same_subnet() {
        let candidates = vec![
            candidate(1, [10, 0, 0, 1], 100, false, None),
            candidate(2, [10, 0, 0, 2], 200, false, None), // same /24 as peer 1
        ];
        let selected = select_outbound_peers(&candidates, &config());
        assert_eq!(
            selected.len(),
            1,
            "max_per_subnet=1 must exclude the second /24 peer"
        );
    }

    #[test]
    fn a_diversity_cap_excludes_a_peer_exceeding_the_asn_limit() {
        let mut cfg = config();
        cfg.max_per_subnet = 10;
        let candidates = vec![
            candidate(1, [10, 0, 0, 1], 100, false, None),
            candidate(2, [10, 0, 1, 1], 100, false, None),
            candidate(3, [10, 0, 2, 1], 100, false, None), // third peer in ASN 100, cap is 2
        ];
        let selected = select_outbound_peers(&candidates, &cfg);
        assert_eq!(
            selected.len(),
            2,
            "max_per_asn=2 must exclude the third same-ASN peer"
        );
    }

    #[test]
    fn trusted_peers_are_not_excluded_by_diversity_caps_but_still_count_toward_them() {
        let candidates = vec![
            candidate(1, [10, 0, 0, 1], 100, true, None),
            candidate(2, [10, 0, 0, 2], 200, true, None), // same /24, but both trusted
            candidate(3, [10, 0, 0, 3], 300, false, None), // same /24 as the trusted pair
        ];
        let selected = select_outbound_peers(&candidates, &config());
        assert!(selected.contains(&peer(1)));
        assert!(
            selected.contains(&peer(2)),
            "trusted peers are never excluded by the cap"
        );
        assert!(
            !selected.contains(&peer(3)),
            "the subnet is already at its cap from the trusted peers"
        );
    }

    #[test]
    fn long_lived_peers_fill_their_reserved_slots_before_everyone_else() {
        let mut cfg = config();
        cfg.max_per_subnet = 10;
        cfg.max_per_asn = 10;
        cfg.target_outbound = 2;
        cfg.reserved_long_lived_slots = 1;
        let candidates = vec![
            candidate(1, [10, 0, 0, 1], 100, false, None), // ordinary
            candidate(
                2,
                [10, 0, 0, 2],
                200,
                false,
                Some(Duration::from_secs(7200)),
            ), // long-lived
        ];
        let selected = select_outbound_peers(&candidates, &cfg);
        assert!(
            selected.contains(&peer(2)),
            "the long-lived peer must be selected"
        );
    }

    #[test]
    fn selection_never_exceeds_target_outbound() {
        let mut cfg = config();
        cfg.target_outbound = 3;
        cfg.max_per_subnet = 100;
        cfg.max_per_asn = 100;
        let candidates: Vec<CandidatePeer> = (0..20)
            .map(|i| candidate(i, [10, 0, i, 1], u32::from(i), false, None))
            .collect();
        let selected = select_outbound_peers(&candidates, &cfg);
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn selection_is_deterministic_regardless_of_input_order() {
        let cfg = config();
        let a = candidate(1, [10, 0, 0, 1], 100, false, None);
        let b = candidate(2, [10, 0, 1, 1], 200, false, None);

        let forward = select_outbound_peers(&[a, b], &cfg);
        let reversed = select_outbound_peers(&[b, a], &cfg);
        assert_eq!(forward, reversed);
    }
}
