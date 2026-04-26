//! ENS (Error Notification Service) module
//!
//! This module provides a facade that conditionally includes either the full implementation
//! (when `enable_ens` feature is on) or a stub implementation (when disabled).

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
