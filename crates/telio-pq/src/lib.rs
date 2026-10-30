#![deny(unsafe_code)]
mod conn;
mod entity;
mod proto;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

/// Default IP address of the PQ upgrader service
pub const PQ_UPGRADER_IPV4: Ipv4Addr = telio_model::constants::VPN_EXTERNAL_IPV4;

pub use entity::Entity;
use proto::{PqProtoV1Status, PqProtoV2Status};

/// Post quantum keys retrived from hanshake
#[derive(Clone)]
pub struct Keys {
    /// Kyber shared secret
    pub pq_shared: telio_crypto::PresharedKey,
    /// X25519 secret key
    pub wg_secret: telio_crypto::SecretKey,
}

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
pub trait PostQuantum {
    fn keys(&self) -> Option<Keys>;
    fn is_rotating_keys(&self) -> bool;
}

#[derive(Clone)]
pub enum Event {
    Connecting(telio_crypto::PublicKey),
    Disconnected(telio_crypto::PublicKey),
    KeyFetch(SocketAddr, Keys),
    Rekey(Keys),
}

/// Kind of the PQ module error
#[derive(Debug, thiserror::Error)]
pub enum ErrorVariant {
    /// IO error
    #[error("IO: {0:?}")]
    Io(#[from] io::Error),
    /// Server errors (version 1)
    #[error("Server error v1: {0:?}")]
    ServerV1(PqProtoV1Status),
    /// Server errors (version 2)
    #[error("Server error v2: {0:?}")]
    ServerV2(PqProtoV2Status),
    /// Generic unrecoverable error
    #[error("Generic: {0}")]
    Generic(String),
}

telio_utils::traced_error! {
    /// The PQ module error type, carries the backtrace of the place where it was created
    pub struct Error(ErrorVariant);
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<String> for ErrorVariant {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl From<&str> for ErrorVariant {
    fn from(value: &str) -> Self {
        Self::Generic(value.to_string())
    }
}

/// Public functions exposed for fuzzing framework
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    pub use super::proto::{parse_get_response, parse_response_payload};
    pub use super::PQ_UPGRADER_IPV4;
}
