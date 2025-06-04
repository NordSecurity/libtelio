#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Telio firewall module.
//! Implements stateful firewall to keep track of
//! initiated connections, and deny inbound packet
//! from an unrecognized source
pub mod firewall;
