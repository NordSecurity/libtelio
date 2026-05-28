use crate::zone::NordZoneError;
use std::{fmt, io, net::AddrParseError};
use thiserror::Error;

/// Result type used by the telio-dns crate
pub type Result<T> = std::result::Result<T, Error>;

/// Describes which IO operation failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsIoContext {
    /// Binding the DNS UDP socket
    BindDnsSocket,
    /// Getting the local address of the DNS socket
    GetSocketAddr,
    /// Configuring tunnel binding for DNS
    ConfigureTunnel,
}

impl fmt::Display for DnsIoContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindDnsSocket => write!(f, "Failed to bind DNS socket"),
            Self::GetSocketAddr => write!(f, "Failed to get DNS socket local address"),
            Self::ConfigureTunnel => write!(f, "Failed to configure tunnel binding"),
        }
    }
}

/// An IO error during DNS operations with context describing which operation failed
#[derive(Debug, Error)]
#[error("{context}: {source}")]
pub struct DnsIoError {
    /// Which operation failed
    pub context: DnsIoContext,
    #[source]
    source: io::Error,
}

// traits to create error from io::Error with context
impl DnsIoError {
    /// Create a new `DnsIoError` for the given context
    pub fn new(context: DnsIoContext, source: io::Error) -> Self {
        Self { context, source }
    }

    /// local helper for `BindDnsSocket` context
    pub(crate) fn bind_socket(source: io::Error) -> Self {
        Self::new(DnsIoContext::BindDnsSocket, source)
    }

    /// local helper for `GetSocketAddr` context
    pub(crate) fn get_socket_addr(source: io::Error) -> Self {
        Self::new(DnsIoContext::GetSocketAddr, source)
    }

    /// local helper for `ConfigureTunnel` context
    pub(crate) fn configure_tunnel(source: io::Error) -> Self {
        Self::new(DnsIoContext::ConfigureTunnel, source)
    }
}

/// Error type for the telio-dns crate
///
/// This enum represents all errors in the public interfaces
/// that can occur when configuring or running the DNS resolver
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An IO error during DNS socket or tunnel operations
    #[error(transparent)]
    Io(#[from] DnsIoError),

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
    AddressParse(#[from] AddrParseError),

    /// Error during configuration of the forward resolver
    #[error("Forward resolver configuration error: {message}")]
    ForwardConfig {
        /// Error message as description of the failure
        message: String,
    },

    /// Failed to upsert a record into a zone
    #[error("Upsert failed: {0}")]
    UpsertFailed(#[from] NordZoneError),

    /// Nameserver is stopped
    #[error("Nameserver stopped")]
    Stopped,
}

impl Error {
    /// Creates `RecordOutsideZone` error
    pub fn record_outside_zone(domain: impl Into<String>, zone: impl Into<String>) -> Self {
        Self::RecordOutsideZone {
            domain: domain.into(),
            zone: zone.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: creates io::Error with given message.
    fn fake_io_error(msg: &str) -> io::Error {
        io::Error::other(msg)
    }

    // Tests DnsIoError display format: "{context}: {source}" from thiserror::Error implementation
    #[test]
    fn dns_io_error_display() {
        let err = DnsIoError::new(DnsIoContext::BindDnsSocket, fake_io_error("port busy"));
        assert_eq!(err.to_string(), "Failed to bind DNS socket: port busy");
    }

    // Tests Error::Io — conversion from DnsIoError via #[from] from thiserror::Error implementation
    #[test]
    fn error_io_from_dns_io_error() {
        let io_err = DnsIoError::new(DnsIoContext::GetSocketAddr, fake_io_error("no address"));
        let err = Error::from(io_err);
        assert!(matches!(err, Error::Io(_)));
        // transparent display should show inner DnsIoError message
        assert_eq!(
            err.to_string(),
            "Failed to get DNS socket local address: no address"
        );
    }
}
