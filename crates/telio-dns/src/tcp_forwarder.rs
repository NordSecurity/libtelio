//! DNS-over-TCP ingress forwarder backed by smoltcp.
//!
//! Terminates client TCP connections that arrive as raw IP packets from the
//! WireGuard tunnel and relays DNS messages to an upstream resolver.
//!
//! A request is buffered until its frame is complete before any upstream is
//! contacted, and a response is withheld until its frame is complete before any
//! byte reaches the client.
//!
//! A query for a `.nord` name is never forwarded.

pub(crate) mod frame;
pub(crate) mod proxy;
#[cfg(test)]
pub(crate) mod test_utils;
