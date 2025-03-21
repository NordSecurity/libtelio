//! telio-starcast crate implements multicast support for the meshnet
//!
//! There are three main components to allow this:
//! 1. Starcast peer responsible for intercepting multicast traffic and injecting it on the receiver side.
//! 2. Starcast transport component responsible for multicasting intercepted traffic to the meshnet peers and handling response messages.
//! 3. Nat is transport's utility used to SNAT the packets comming from multiple peers into one multicast peer address.

pub mod nat;
pub mod starcast_peer;
pub mod transport;
pub(crate) mod utils;
