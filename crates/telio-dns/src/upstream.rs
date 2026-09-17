//! Upstream resolver list shared by the DNS forwarders

use std::net::SocketAddr;

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

    /// Replace the upstream list and bump the generation
    pub(crate) fn set(&mut self, addrs: Vec<SocketAddr>) {
        if addrs != self.addrs {
            self.generation = self.generation.wrapping_add(1);
            self.addrs = addrs;
        }
    }

    /// Create new upstream cursor for current generation
    pub(crate) fn new_cursor(&self) -> UpstreamCursor {
        UpstreamCursor {
            index: 0,
            generation: self.generation,
        }
    }
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

    fn upstream_list(addrs: Vec<SocketAddr>, generation: u64) -> UpstreamList {
        UpstreamList { addrs, generation }
    }

    fn step(next: Option<SocketAddr>, restarted: bool) -> CursorAdvanced {
        CursorAdvanced { next, restarted }
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
