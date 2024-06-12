//! telio-starcast crate implements multicast support for the meshnet
//!
//! There are three main components to allow this:
//! 1. Multicast peer responsible for intercepting multicast traffic and injecting it on the receiver side.
//! 2. Multicaster responsible for multicasting intercepted traffic to the meshnet peers and handling response messages.
//! 3. Nat is multicaster's utility used to SNAT the packets comming from multiple peers into one multicast peer address.

pub mod nat;
pub(crate) mod utils;
