use crate::forwarder::ForwardError;
use crate::zone::NordZoneError;
use std::{io, net::AddrParseError};
use thiserror::Error;

/// Result type used by the telio-dns crate
pub type Result<T> = std::result::Result<T, Error>;

/// An IO error during DNS operations
#[derive(Debug, Error)]
pub enum DnsIoError {
    /// Binding the DNS UDP socket
    #[error("Failed to bind DNS socket: {0}")]
    BindDnsSocket(io::Error),
    /// Getting the local address of the DNS socket
    #[error("Failed to get DNS socket local address: {0}")]
    GetSocketAddr(io::Error),
    /// Configuring tunnel binding for DNS
    #[error("Failed to configure tunnel binding: {0}")]
    ConfigureTunnel(io::Error),
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

    /// Failed to create the raw DNS forwarder
    #[error("Failed to create DNS forwarder: {0}")]
    CreateForwarder(#[from] ForwardError),

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
        let err = DnsIoError::BindDnsSocket(fake_io_error("port busy"));
        assert_eq!(err.to_string(), "Failed to bind DNS socket: port busy");
    }

    // Tests Error::Io — conversion from DnsIoError via #[from] from thiserror::Error implementation
    #[test]
    fn error_io_from_dns_io_error() {
        let io_err = DnsIoError::GetSocketAddr(fake_io_error("no address"));
        let err = Error::from(io_err);
        assert!(matches!(err, Error::Io(_)));
        // transparent display should show inner DnsIoError message
        assert_eq!(
            err.to_string(),
            "Failed to get DNS socket local address: no address"
        );
    }
}
