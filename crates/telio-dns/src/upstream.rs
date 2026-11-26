//! Upstream resolver list shared by the DNS forwarders

use ipnet::Ipv4Net;
use rand::{seq::SliceRandom, Rng};
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
    pub(crate) fn set(&mut self, addrs: Vec<SocketAddr>) {
        self.set_with_rng(addrs, &mut rand::rng());
    }

    fn set_with_rng<R: Rng + ?Sized>(&mut self, mut addrs: Vec<SocketAddr>, rng: &mut R) {
        if addrs.iter().all(is_nord_dns) {
            if sorted(&addrs) == sorted(&self.addrs) {
                return;
            }
            addrs.shuffle(rng);
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
pub(crate) mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
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

    pub(crate) fn upstream_addr(last_octet: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last_octet], 53))
    }

    #[test]
    fn set_replaces_addrs_and_increments_generation() {
        let a1 = upstream_addr(1);
        let a2 = upstream_addr(2);
        let a3 = upstream_addr(3);
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
        let a1 = upstream_addr(1);
        let a2 = upstream_addr(2);
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
        let a1 = upstream_addr(1);
        let a2 = upstream_addr(2);
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
        let addrs: Vec<_> = (1..=4).map(nord_addr).collect();
        let mut rng = StdRng::seed_from_u64(0);
        // in 256 runs, each shuffled nord_addr should appear first at least once
        let firsts: HashSet<_> = (0..256)
            .map(|_| {
                let mut state = UpstreamList::default();
                state.set_with_rng(addrs.clone(), &mut rng);
                state.addrs()[0]
            })
            .collect();
        assert_eq!(firsts, addrs.iter().copied().collect());
    }

    #[test]
    fn set_keeps_order_of_mixed_list() {
        let mut addrs: Vec<_> = (1..=4).map(nord_addr).collect();
        addrs.push(upstream_addr(1));
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
        let a1 = upstream_addr(1);
        let mut state = upstream_list(vec![], u64::MAX);
        let mut cursor = state.new_cursor();

        state.set(vec![a1]);
        assert_eq!(state.generation, 0);
        assert_eq!(cursor.advance(&state), step(Some(a1), true));
    }

    #[test]
    fn advance_walks_list_in_order() {
        let a1 = upstream_addr(1);
        let a2 = upstream_addr(2);
        let a3 = upstream_addr(3);
        let state = upstream_list(vec![a1, a2, a3], 0);
        let mut cursor = state.new_cursor();

        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(Some(a2), false));
        assert_eq!(cursor.advance(&state), step(Some(a3), false));
        assert_eq!(cursor.advance(&state), step(None, false), "exhausted");
    }

    #[test]
    fn advance_restarts_on_generation_change() {
        let a1 = upstream_addr(1);
        let a2 = upstream_addr(2);
        let a3 = upstream_addr(3);
        let b1 = upstream_addr(11);
        let b2 = upstream_addr(12);

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
        let a1 = upstream_addr(1);
        let mut state = upstream_list(vec![a1], 0);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(Some(a1), false));

        state.set(vec![]);
        assert_eq!(cursor.advance(&state), step(None, true));
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn exhausted_cursor_restarts_on_generation_change() {
        let a1 = upstream_addr(1);
        let b1 = upstream_addr(11);
        let mut state = upstream_list(vec![a1], 0);
        let mut cursor = state.new_cursor();
        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(None, false));

        state.set(vec![b1]);
        assert_eq!(cursor.advance(&state), step(Some(b1), true));
    }

    #[test]
    fn advance_index_saturates_past_list_end() {
        let a1 = upstream_addr(1);
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
        let a1 = upstream_addr(1);
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
