#![deny(missing_docs)]
//! Proxy component acts as a middle layer between telio-wg and telio-relay (DERP)
//! It does this by mapping UDP sockets with public keys
mod proxy;
pub use proxy::*;
