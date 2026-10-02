pub(crate) mod engine;
pub(crate) mod frame;
pub(crate) mod proxy;
pub(crate) mod syn_backlog;

#[cfg(test)]
pub(crate) mod test_utils;

use std::time::Duration;

/// Timeouts
#[derive(Clone, Copy)]
pub(crate) struct Timeouts {
    /// Time an upstream has to connect and answer a query.
    upstream_reply: Duration,
    /// Time a client may go without progress, or take to close, before it is dropped.
    client_idle: Duration,
}

impl Timeouts {
    pub(crate) fn new(upstream_reply: Duration, client_idle: Duration) -> Self {
        Timeouts {
            upstream_reply,
            client_idle,
        }
    }
}
