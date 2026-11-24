//! Upstream resolver list shared by the DNS forwarders

use ipnet::Ipv4Net;
use rand::seq::SliceRandom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const NORD_DNS_RANGE: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(103, 86, 96, 0), 22);

/// Upstream resolver list with a generation counter to detect changes
#[derive(Clone, Debug, Default)]
pub(crate) struct UpstreamList {
    addrs: Vec<SocketAddr>,
    generation: u64,
}

impl UpstreamList {
    /// Upstream resolvers in the order they are tried
    pub(crate) fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Replace the upstream list if it changed
    ///
    /// A list of Nord resolvers is shuffled.
    /// Any other list keeps its order as priority.
    pub(crate) fn set(&mut self, mut addrs: Vec<SocketAddr>) {
        if addrs.iter().all(is_nord_dns) {
            if sorted(&addrs) == sorted(&self.addrs) {
                return;
            }
            addrs.shuffle(&mut rand::rng());
        } else if addrs == self.addrs {
            return;
        }
        self.addrs = addrs;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Create new upstream cursor for current generation
    pub(crate) fn new_cursor(&self) -> UpstreamCursor {
        UpstreamCursor {
            index: 0,
            generation: self.generation,
        }
    }
}

fn is_nord_dns(addr: &SocketAddr) -> bool {
    matches!(addr.ip(), IpAddr::V4(ip) if NORD_DNS_RANGE.contains(&ip))
}

fn sorted(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut sorted = addrs.to_vec();
    sorted.sort_unstable();
    sorted
}

/// Cursor over the upstream list for one query attempt
#[derive(Clone, Debug)]
pub(crate) struct UpstreamCursor {
    index: usize,
    generation: u64,
}

/// Outcome of one `UpstreamCursor::advance` step
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CursorAdvanced {
    pub(crate) next: Option<SocketAddr>,
    pub(crate) restarted: bool,
}

impl UpstreamCursor {
    /// Pick the next upstream to try, restarting if the upstream list changed
    pub(crate) fn advance(&mut self, current_upstream: &UpstreamList) -> CursorAdvanced {
        let restarted = if self.generation != current_upstream.generation {
            self.index = 0;
            self.generation = current_upstream.generation;
            true
        } else {
            false
        };

        let next = current_upstream.addrs.get(self.index).copied();
        self.index = self.index.saturating_add(1);
        CursorAdvanced { next, restarted }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn upstream_list(addrs: Vec<SocketAddr>, generation: u64) -> UpstreamList {
        UpstreamList { addrs, generation }
    }

    fn step(next: Option<SocketAddr>, restarted: bool) -> CursorAdvanced {
        CursorAdvanced { next, restarted }
    }

    fn nord_addr(last_octet: u8) -> SocketAddr {
        SocketAddr::from(([103, 86, 99, last_octet], 53))
    }

    #[test]
    fn set_replaces_addrs_and_increments_generation() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:53".parse().unwrap();
        let a3: SocketAddr = "10.0.0.3:53".parse().unwrap();
        let mut state = UpstreamList::default();
        assert_eq!(state.generation, 0);
        assert!(state.addrs().is_empty());

        state.set(vec![a1]);
        assert_eq!(state.addrs(), [a1]);
        assert_eq!(state.generation, 1);

        state.set(vec![a2, a1]);
        assert_eq!(state.addrs(), [a2, a1]);
        assert_eq!(state.generation, 2);

        state.set(vec![a2, a1, a3]);
        assert_eq!(state.addrs(), [a2, a1, a3]);
        assert_eq!(state.generation, 3);
    }

    #[test]
    fn set_same_list_keeps_generation_and_cursor() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:53".parse().unwrap();
        let mut state = upstream_list(vec![a1, a2], 7);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(Some(a1), false));

        state.set(vec![a1, a2]);
        assert_eq!(state.generation, 7);
        assert_eq!(state.addrs(), [a1, a2]);
        assert_eq!(
            cursor.advance(&state),
            step(Some(a2), false),
            "not restarted"
        );
    }

    #[test]
    fn set_same_addrs_in_different_order_bumps_generation() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:53".parse().unwrap();
        let mut state = upstream_list(vec![a1, a2], 0);

        state.set(vec![a2, a1]);
        assert_eq!(state.generation, 1);
        assert_eq!(state.addrs(), [a2, a1]);
    }

    #[test]
    fn set_same_nord_addrs_in_different_order_keeps_generation_and_cursor() {
        let (a1, a2) = (nord_addr(1), nord_addr(2));
        let mut state = upstream_list(vec![a1, a2], 0);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(Some(a1), false));

        state.set(vec![a2, a1]);
        assert_eq!(state.generation, 0);
        assert_eq!(state.addrs(), [a1, a2]);
        assert_eq!(cursor.advance(&state), step(Some(a2), false));
    }

    #[test]
    fn set_same_nord_list_does_not_reshuffle() {
        let addrs: Vec<_> = (1..=8).map(nord_addr).collect();
        let mut state = UpstreamList::default();
        state.set(addrs.clone());
        let shuffled = state.addrs().to_vec();

        state.set(addrs);
        assert_eq!(state.addrs(), shuffled);
        assert_eq!(state.generation, 1);
    }

    #[test]
    fn set_shuffles_new_nord_list() {
        let (a1, a2) = (nord_addr(1), nord_addr(2));
        let firsts: HashSet<_> = (0..64)
            .map(|_| {
                let mut state = UpstreamList::default();
                state.set(vec![a1, a2]);
                state.addrs()[0]
            })
            .collect();
        assert_eq!(firsts, HashSet::from([a1, a2]));
    }

    #[test]
    fn set_keeps_order_of_mixed_list() {
        let mut addrs: Vec<_> = (1..=4).map(nord_addr).collect();
        addrs.push("10.0.0.1:53".parse().unwrap());
        let mut state = UpstreamList::default();
        state.set(addrs.clone());
        assert_eq!(state.addrs(), addrs);
    }

    #[test]
    fn nord_dns_range_bounds() {
        let is_nord = |s: &str| is_nord_dns(&s.parse().unwrap());
        assert!(is_nord("103.86.96.0:53"));
        assert!(is_nord("103.86.99.255:53"));
        assert!(!is_nord("103.86.95.255:53"));
        assert!(!is_nord("103.86.100.0:53"));
        assert!(!is_nord("[2001:db8::1]:53"));
    }

    #[test]
    fn generation_wraps_around() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let mut state = upstream_list(vec![], u64::MAX);
        let mut cursor = state.new_cursor();

        state.set(vec![a1]);
        assert_eq!(state.generation, 0);
        assert_eq!(cursor.advance(&state), step(Some(a1), true));
    }

    #[test]
    fn advance_walks_list_in_order() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:53".parse().unwrap();
        let a3: SocketAddr = "10.0.0.3:53".parse().unwrap();
        let state = upstream_list(vec![a1, a2, a3], 0);
        let mut cursor = state.new_cursor();

        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(Some(a2), false));
        assert_eq!(cursor.advance(&state), step(Some(a3), false));
        assert_eq!(cursor.advance(&state), step(None, false), "exhausted");
    }

    #[test]
    fn advance_restarts_on_generation_change() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let a2: SocketAddr = "10.0.0.2:53".parse().unwrap();
        let a3: SocketAddr = "10.0.0.3:53".parse().unwrap();
        let b1: SocketAddr = "10.0.0.11:53".parse().unwrap();
        let b2: SocketAddr = "10.0.0.12:53".parse().unwrap();

        let mut state = upstream_list(vec![a1, a2, a3], 0);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(Some(a2), false));

        state.set(vec![b1, b2]);
        assert_eq!(state.generation, 1);
        assert_eq!(cursor.advance(&state), step(Some(b1), true));
        assert_eq!(cursor.advance(&state), step(Some(b2), false));
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn advance_restarts_onto_empty_list() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let mut state = upstream_list(vec![a1], 0);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(Some(a1), false));

        state.set(vec![]);
        assert_eq!(cursor.advance(&state), step(None, true));
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn exhausted_cursor_restarts_on_generation_change() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let b1: SocketAddr = "10.0.0.11:53".parse().unwrap();
        let mut state = upstream_list(vec![a1], 0);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(None, false));

        state.set(vec![b1]);
        assert_eq!(cursor.advance(&state), step(Some(b1), true));
    }

    #[test]
    fn advance_index_saturates_past_list_end() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let state = upstream_list(vec![a1], 0);
        let mut cursor = UpstreamCursor {
            index: usize::MAX,
            generation: 0,
        };

        assert_eq!(cursor.advance(&state), step(None, false));
        assert_eq!(cursor.advance(&state), step(None, false));
        assert_eq!(cursor.index, usize::MAX);
    }

    #[test]
    fn fresh_cursor_binds_to_any_generation_without_restart() {
        let a1: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let state = upstream_list(vec![a1], 42);
        let mut cursor = state.new_cursor();

        assert_eq!(cursor.advance(&state), step(Some(a1), false));
    }

    #[test]
    fn advance_empty_list_returns_none() {
        let state = upstream_list(vec![], 0);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(None, false));
    }
}
