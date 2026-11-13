//! Upstream resolver list shared by the DNS forwarders

use std::net::SocketAddr;

use rand::RngExt;

/// Upstream resolver list with a generation counter to detect changes
#[derive(Clone, Debug, Default)]
pub(crate) struct UpstreamList {
    addrs: Vec<SocketAddr>,
    generation: u64,
}

impl UpstreamList {
    /// Upstream resolvers as configured
    pub(crate) fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Replace the upstream list and bump the generation
    pub(crate) fn set(&mut self, addrs: Vec<SocketAddr>) {
        if addrs != self.addrs {
            self.generation = self.generation.wrapping_add(1);
            self.addrs = addrs;
        }
    }

    /// Create new upstream cursor for current generation, starting at a random upstream
    pub(crate) fn new_cursor(&self) -> UpstreamCursor {
        UpstreamCursor {
            seed: rand::rng().random_range(0..=usize::MAX),
            tried: 0,
            generation: self.generation,
        }
    }
}

/// Round robin cursor over the upstream list for one query
#[derive(Clone, Debug)]
pub(crate) struct UpstreamCursor {
    seed: usize,
    tried: usize,
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
            self.tried = 0;
            self.generation = current_upstream.generation;
            true
        } else {
            false
        };

        let addrs = &current_upstream.addrs;
        let next = (self.tried < addrs.len())
            .then(|| {
                let start = self.seed % addrs.len();
                addrs.get((start + self.tried) % addrs.len()).copied()
            })
            .flatten();
        self.tried = self.tried.saturating_add(1);
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

    fn cursor(seed: usize, generation: u64) -> UpstreamCursor {
        UpstreamCursor {
            seed,
            tried: 0,
            generation,
        }
    }

    fn step(next: Option<SocketAddr>, restarted: bool) -> CursorAdvanced {
        CursorAdvanced { next, restarted }
    }

    fn addr(last_octet: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last_octet], 53))
    }

    #[test]
    fn set_replaces_addrs_and_increments_generation() {
        let (a1, a2, a3) = (addr(1), addr(2), addr(3));
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
        let (a1, a2) = (addr(1), addr(2));
        let mut state = upstream_list(vec![a1, a2], 7);
        let mut cursor = cursor(0, 7);
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
        let (a1, a2) = (addr(1), addr(2));
        let mut state = upstream_list(vec![a1, a2], 0);

        state.set(vec![a2, a1]);
        assert_eq!(state.generation, 1);
        assert_eq!(state.addrs(), [a2, a1]);
    }

    #[test]
    fn generation_wraps_around() {
        let a1 = addr(1);
        let mut state = upstream_list(vec![], u64::MAX);
        let mut cursor = state.new_cursor();

        state.set(vec![a1]);
        assert_eq!(state.generation, 0);
        assert_eq!(cursor.advance(&state), step(Some(a1), true));
    }

    #[test]
    fn advance_walks_list_from_seed_and_wraps() {
        let (a1, a2, a3) = (addr(1), addr(2), addr(3));
        let state = upstream_list(vec![a1, a2, a3], 0);
        let mut cursor = cursor(1, 0);

        assert_eq!(cursor.advance(&state), step(Some(a2), false));
        assert_eq!(cursor.advance(&state), step(Some(a3), false));
        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(None, false), "exhausted");
    }

    #[test]
    fn advance_seed_past_list_len_wraps_start() {
        let (a1, a2, a3) = (addr(1), addr(2), addr(3));
        let state = upstream_list(vec![a1, a2, a3], 0);
        let mut cursor = cursor(5, 0);

        assert_eq!(cursor.advance(&state), step(Some(a3), false));
        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(Some(a2), false));
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn advance_max_seed_does_not_overflow() {
        let (a1, a2, a3) = (addr(1), addr(2), addr(3));
        let state = upstream_list(vec![a1, a2, a3], 0);
        let mut cursor = cursor(usize::MAX, 0);
        let start = usize::MAX % 3;

        for i in 0..3 {
            let expected = state.addrs()[(start + i) % 3];
            assert_eq!(cursor.advance(&state), step(Some(expected), false));
        }
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn advance_restarts_on_generation_change() {
        let (a1, a2, a3) = (addr(1), addr(2), addr(3));
        let (b1, b2) = (addr(11), addr(12));

        let mut state = upstream_list(vec![a1, a2, a3], 0);
        let mut cursor = cursor(1, 0);
        assert_eq!(cursor.advance(&state), step(Some(a2), false));
        assert_eq!(cursor.advance(&state), step(Some(a3), false));

        state.set(vec![b1, b2]);
        assert_eq!(state.generation, 1);
        assert_eq!(cursor.advance(&state), step(Some(b2), true));
        assert_eq!(cursor.advance(&state), step(Some(b1), false));
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn advance_restarts_onto_empty_list() {
        let a1 = addr(1);
        let mut state = upstream_list(vec![a1], 0);
        let mut cursor = cursor(0, 0);
        assert_eq!(cursor.advance(&state), step(Some(a1), false));

        state.set(vec![]);
        assert_eq!(cursor.advance(&state), step(None, true));
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn exhausted_cursor_restarts_on_generation_change() {
        let (a1, b1) = (addr(1), addr(11));
        let mut state = upstream_list(vec![a1], 0);
        let mut cursor = cursor(0, 0);
        assert_eq!(cursor.advance(&state), step(Some(a1), false));
        assert_eq!(cursor.advance(&state), step(None, false));

        state.set(vec![b1]);
        assert_eq!(cursor.advance(&state), step(Some(b1), true));
    }

    #[test]
    fn advance_tried_saturates_past_list_end() {
        let state = upstream_list(vec![addr(1)], 0);
        let mut cursor = UpstreamCursor {
            seed: 0,
            tried: usize::MAX,
            generation: 0,
        };

        assert_eq!(cursor.advance(&state), step(None, false));
        assert_eq!(cursor.advance(&state), step(None, false));
        assert_eq!(cursor.tried, usize::MAX);
    }

    #[test]
    fn fresh_cursor_binds_to_any_generation_without_restart() {
        let a1 = addr(1);
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

    #[test]
    fn fresh_cursor_tries_every_upstream_once() {
        let addrs = vec![addr(1), addr(2), addr(3), addr(4)];
        let state = upstream_list(addrs.clone(), 0);
        let mut cursor = state.new_cursor();

        let tried: HashSet<_> = (0..addrs.len())
            .map(|_| cursor.advance(&state).next.unwrap())
            .collect();
        assert_eq!(tried, addrs.into_iter().collect());
        assert_eq!(cursor.advance(&state), step(None, false));
    }

    #[test]
    fn fresh_cursors_start_at_different_upstreams() {
        let addrs = vec![addr(1), addr(2), addr(3), addr(4)];
        let state = upstream_list(addrs.clone(), 0);

        let firsts: HashSet<_> = (0..200)
            .map(|_| state.new_cursor().advance(&state).next.unwrap())
            .collect();
        assert_eq!(firsts, addrs.into_iter().collect());
    }
}
