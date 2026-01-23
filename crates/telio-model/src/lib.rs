#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Crate containing models of various components
pub mod config;
pub mod constants;
pub mod event;
pub mod features;
pub mod mesh;
pub mod tp_lite_stats;
pub mod validation;

pub use std::collections::HashMap;
pub use std::net::SocketAddr;
pub use telio_crypto::PublicKey;

/// Hashmap of public key of the endpoint with its socket information
pub type EndpointMap = HashMap<PublicKey, Vec<SocketAddr>>;
