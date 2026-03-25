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
    #[error("Record '{0}' does not belong to zone '{1}'")]
    RecordOutsideZone(String, String),

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
