use telio_crypto::KeyDecodeError;
use telio_model::event::Event;
use telio_utils::map_enum;
use tracing::Level;

use std::{panic::RefUnwindSafe, sync::Arc};

use crate::device::{AdapterType, Error as DevError};

pub trait TelioEventCb: Send + Sync + std::fmt::Debug {
    fn event(&self, payload: Event) -> FFIResult<()>;
}

pub trait TelioLoggerCb: Send + Sync + std::fmt::Debug {
    fn log(&self, log_level: TelioLogLevel, payload: String) -> FFIResult<()>;
}

pub trait TelioProtectCb: Send + Sync + RefUnwindSafe + std::fmt::Debug {
    fn protect(&self, socket_id: i32) -> FFIResult<()>;
}

pub type FFIResult<T> = Result<T, Arc<TelioError>>;

#[derive(Debug, thiserror::Error)]
pub enum TelioError {
    #[error("UnknownError: {0}")]
    UnknownError(anyhow::Error),
    #[error("InvalidKey")]
    InvalidKey,
    #[error("BadConfig")]
    BadConfig,
    #[error("LockError")]
    LockError,
    #[error("InvalidString")]
    InvalidString,
    #[error("AlreadyStarted")]
    AlreadyStarted,
    #[error("NotStarted")]
    NotStarted,
}

impl TelioError {
    pub fn kind(&self) -> String {
        match self {
            TelioError::UnknownError(_) => "UnknownError".to_owned(),
            TelioError::InvalidKey => "InvalidKey".to_owned(),
            TelioError::BadConfig => "BadConfig".to_owned(),
            TelioError::LockError => "LockError".to_owned(),
            TelioError::InvalidString => "InvalidString".to_owned(),
            TelioError::AlreadyStarted => "AlreadyStarted".to_owned(),
            TelioError::NotStarted => "NotStarted".to_owned(),
        }
    }

    pub fn message(&self) -> String {
        match self {
            TelioError::UnknownError(inner) => format!("{}: {}", self.kind(), inner),
            _ => format!("{}: ", self.kind()),
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[allow(clippy::enum_variant_names)] // Otherwise clippy complains about all variants having "Tun" as their suffix
/// Possible adapters.
pub enum TelioAdapterType {
    /// Userland rust implementation.
    BoringTun,
    /// Linux in-kernel WireGuard implementation
    LinuxNativeTun,
    /// WireguardGo implementation
    WireguardGoTun,
    /// WindowsNativeWireguardNt implementation
    WindowsNativeTun,
}

#[derive(Copy, Clone)]
/// Possible log levels.
pub enum TelioLogLevel {
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl From<KeyDecodeError> for TelioError {
    fn from(_: KeyDecodeError) -> Self {
        Self::InvalidKey
    }
}

impl From<&KeyDecodeError> for TelioError {
    fn from(_: &KeyDecodeError) -> Self {
        Self::InvalidKey
    }
}

impl From<serde_json::Error> for TelioError {
    fn from(_: serde_json::Error) -> Self {
        Self::BadConfig
    }
}

impl From<&serde_json::Error> for TelioError {
    fn from(_: &serde_json::Error) -> Self {
        Self::BadConfig
    }
}

impl From<DevError> for TelioError {
    fn from(err: DevError) -> Self {
        // TODO: Map more error types.
        match err {
            DevError::AlreadyStarted => Self::AlreadyStarted,
            DevError::BadPublicKey => Self::InvalidKey,
            _ => Self::UnknownError(anyhow::anyhow!(err)),
        }
    }
}

impl From<&DevError> for TelioError {
    fn from(err: &DevError) -> Self {
        // TODO: Map more error types.
        match err {
            DevError::AlreadyStarted => Self::AlreadyStarted,
            DevError::BadPublicKey => Self::InvalidKey,
            _ => Self::UnknownError(anyhow::anyhow!(err.to_string())),
        }
    }
}

map_enum! {
    AdapterType <=> TelioAdapterType,
    BoringTun = BoringTun,
    WireguardGo = WireguardGoTun,
    LinuxNativeWg = LinuxNativeTun,
    WindowsNativeWg = WindowsNativeTun
}

// Deprecated slog crate had 6 levels
// but log crate has 5, hence reusing top
// 2 levels
map_enum! {
    Level -> TelioLogLevel,
    ERROR = Error,
    WARN = Warning,
    INFO = Info,
    DEBUG = Debug,
    TRACE = Trace,
}

map_enum! {
    TelioLogLevel -> Level,
    Error = ERROR,
    Warning = WARN,
    Info = INFO,
    Debug = DEBUG,
    Trace = TRACE,
}
