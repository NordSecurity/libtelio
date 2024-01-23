// #![deny(missing_docs)]
//! Telio starcast module
//! Implements virtual peer that handles multicast and
//! broadcast packets. It retransmits them to other peers
//! when received on local machine and sends them to
//! local network when received from other peers.
pub mod multicast_peer;

mod multicaster;
mod receiver;
