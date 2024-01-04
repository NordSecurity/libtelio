mod proto;

use std::io;

pub use proto::fetch_keys;

/// Post quantum keys retrived from hanshake
#[derive(Clone, Copy)]
pub struct Keys {
    /// Kyber shared secret
    pub pq_shared: telio_crypto::PresharedKey,
    /// X25519 secret key
    pub wg_secret: telio_crypto::SecretKey,
}

/// The PQ module error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// IO error
    #[error("IO: {0:?}")]
    Io(#[from] io::Error),
    /// Generic unrecoverable error
    #[error("Generic: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::Generic(value.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(value: tokio::time::error::Elapsed) -> Self {
        Self::Io(io::Error::new(io::ErrorKind::TimedOut, value))
    }
}

/// Public functions exposed for fuzzing framework
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    pub use super::proto::parse_get_response;
}
