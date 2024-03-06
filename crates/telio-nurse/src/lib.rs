#![deny(missing_docs)]

//! Nurse is responsible for collecting various meshnet health data and transmitting it to other nodes
//!
//! The public API of nurse consists of four functions:
//!
//! * `start` - Starts nurse, without listening to any nodes
//! * `stop` - Stops a running nurse
//! * `set_nodes` - Adds and removes nodes from nurse health checks. Useful if nodes were added to or removed from the meshnet
//! * `set_private_key` - To update the private (and public) key for the meshnet
//!
//! The intended workflow would be to first start a nurse and set which nodes it should listen to, and when the application exits stop the nurse. For concrete examples, check `relay.rs` in `telio-traversal`.

/// Nurse configuration module
pub mod config;
/// Nurse data module
pub mod data;
/// Nurse error module
pub mod error;

/// Main nurse module
mod nurse;

/// Connectivity data aggregator module
pub mod aggregator;

mod heartbeat;
mod qos;
mod rtt;

pub use heartbeat::MeshnetEntities;
pub use nurse::Nurse;
pub use nurse::NurseIo;
