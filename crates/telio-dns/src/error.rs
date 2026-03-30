use std::{io, net::AddrParseError};
use thiserror::Error;

/// Result type used by the telio-dns crate
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for the telio-dns crate
///
/// This enum represents all errors in the public interfaces
/// that can occur when configuring or running the DNS resolver
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to bind DNS socket
    #[error("Failed to bind DNS socket: {0}")]
    BindDnsSocket(#[from] io::Error),

    /// Failed to get DNS socket local address
    #[error("Failed to get DNS socket local address: {0}")]
    GetDnsSocketLocalAddr(#[source] io::Error),

    /// Failed to configure tunnel binding
    #[error("Failed to configure tunnel binding: {0}")]
    ConfigureTunnel(#[source] io::Error),

    /// Failed to create WireGuard tunnel
    #[error("Failed to create WireGuard tunnel: {0}")]
    CreateTunnel(String),

    /// Invalid DNS name
    #[error("Invalid DNS name: {0}")]
    InvalidDnsName(#[from] hickory_server::proto::error::ProtoError),

    /// Record does not belong to the specified DNS zone
    #[error("Record '{domain}' does not belong to zone '{zone}'")]
    RecordOutsideZone {
        /// Domain name of the record
        domain: String,
        /// Name of the zone
        zone: String,
    },

    /// Invalid IP address
    #[error("Invalid IP address: {0}")]
    AddrParse(#[from] AddrParseError),

    /// Error during configuration of the forward resolver
    #[error("Forward resolver configuration error: {message}")]
    ForwardConfig {
        /// Error message as description of the failure
        message: String,
    },

    /// Nameserver is stopped
    #[error("Nameserver stopped")]
    Stopped,
}

impl Error {
    /// Create `BindDnsSocket` error
    pub fn bind_dns_socket(err: io::Error) -> Self {
        Self::BindDnsSocket(err)
    }

    /// Creates `GetDnsSocketLocalAddr` error
    pub fn get_dns_socket_local_addr(err: io::Error) -> Self {
        Self::GetDnsSocketLocalAddr(err)
    }

    /// Creates `ConfigureTunnel` error
    pub fn configure_tunnel(err: io::Error) -> Self {
        Self::ConfigureTunnel(err)
    }

    /// Creates `RecordOutsideZone` error
    pub fn record_outside_zone(domain: impl Into<String>, zone: impl Into<String>) -> Self {
        Self::RecordOutsideZone {
            domain: domain.into(),
            zone: zone.into(),
        }
    }

    /// Creates `ForwardConfig` error
    pub fn forward_config(message: impl Into<String>) -> Self {
        Self::ForwardConfig {
            message: message.into(),
        }
    }
}
