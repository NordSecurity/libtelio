//! ENS (Error Notification Service) module
//!
//! This module provides a facade that conditionally includes either the full implementation
//! (when `enable_ens` feature is on) or a stub implementation (when disabled).

use std::time::Duration;

/// Configuration of the keep alive messages sent over the ENS connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveConfig {
    /// Interval between the keep alive messages, `None` disables the keep alives
    pub interval: Option<Duration>,
    /// How long to wait for a keep alive response before considering the connection dead,
    /// `None` leaves the default of the underlying http client in place
    pub timeout: Option<Duration>,
}

#[cfg(feature = "enable_ens")]
mod ens_impl;
#[cfg(feature = "enable_ens")]
pub(crate) use ens_impl::grpc;
#[cfg(feature = "enable_ens")]
pub use ens_impl::{install_default_crypto_provider, Error, ErrorNotificationService};

#[cfg(not(feature = "enable_ens"))]
mod ens_stub;
#[cfg(not(feature = "enable_ens"))]
pub(crate) use ens_stub::grpc;
#[cfg(not(feature = "enable_ens"))]
pub use ens_stub::{install_default_crypto_provider, Error, ErrorNotificationService};
