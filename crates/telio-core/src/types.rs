use telio_crypto::KeyDecodeError;
use telio_model::event::Event;
pub use telio_utils::backtrace::{Backtrace, Location};
use telio_utils::map_enum;
use tracing::Level;

use std::{convert::TryFrom, panic::RefUnwindSafe};

use crate::device::{AdapterType, ErrorVariant as DevErrorVariant};

pub trait TelioEventCb: Send + Sync + std::fmt::Debug {
    fn event(&self, payload: Event) -> Result<(), TelioErrorVariant>;
}

pub trait TelioLoggerCb: Send + Sync + std::fmt::Debug {
    fn log(&self, log_level: TelioLogLevel, payload: String) -> Result<(), TelioErrorVariant>;
}

pub trait TelioProtectCb: Send + Sync + RefUnwindSafe + std::fmt::Debug {
    fn protect(&self, socket_id: i32) -> Result<(), TelioErrorVariant>;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum TelioErrorVariant {
    #[error("UnknownError: {inner}")]
    UnknownError { inner: String },
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

#[derive(Copy, Clone, Debug)]
#[allow(clippy::enum_variant_names)] // Otherwise clippy complains about all variants having "Tun" as their suffix
/// Possible adapters.
pub enum TelioAdapterType {
    /// Userland rust implementation.
    NepTUN,
    /// Userland rust implementation. (Deprecated alias for NepTUN).
    BoringTun,
    /// Linux in-kernel WireGuard implementation
    LinuxNativeTun,
    /// WindowsNativeWireguardNt implementation
    WindowsNativeTun,
    /// Custom adapter implementation
    Custom,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Possible log levels.
pub enum TelioLogLevel {
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for TelioErrorVariant {
    fn from(err: uniffi::UnexpectedUniFFICallbackError) -> Self {
        let err_string = err.to_string();
        let err_reason = err.reason;
        Self::UnknownError {
            inner: format!("{err_string} - {err_reason}"),
        }
    }
}

impl From<KeyDecodeError> for TelioErrorVariant {
    fn from(_: KeyDecodeError) -> Self {
        Self::InvalidKey
    }
}

impl From<&KeyDecodeError> for TelioErrorVariant {
    fn from(_: &KeyDecodeError) -> Self {
        Self::InvalidKey
    }
}

impl From<serde_json::Error> for TelioErrorVariant {
    fn from(_: serde_json::Error) -> Self {
        Self::BadConfig
    }
}

impl From<&serde_json::Error> for TelioErrorVariant {
    fn from(_: &serde_json::Error) -> Self {
        Self::BadConfig
    }
}

impl From<&DevErrorVariant> for TelioErrorVariant {
    fn from(err: &DevErrorVariant) -> Self {
        // TODO: Map more error types.
        match err {
            DevErrorVariant::AlreadyStarted => Self::AlreadyStarted,
            DevErrorVariant::BadPublicKey => Self::InvalidKey,
            _ => Self::UnknownError {
                inner: format!("{err:?}"),
            },
        }
    }
}

impl From<AdapterType> for TelioAdapterType {
    fn from(value: AdapterType) -> Self {
        match value {
            AdapterType::NepTUN => TelioAdapterType::BoringTun,
            AdapterType::LinuxNativeWg => TelioAdapterType::LinuxNativeTun,
            AdapterType::WindowsNativeWg => TelioAdapterType::WindowsNativeTun,
            AdapterType::Custom(_) => TelioAdapterType::Custom,
        }
    }
}

impl TryFrom<TelioAdapterType> for AdapterType {
    type Error = String;

    fn try_from(value: TelioAdapterType) -> Result<Self, Self::Error> {
        match value {
            TelioAdapterType::NepTUN => Ok(AdapterType::NepTUN),
            TelioAdapterType::BoringTun => Ok(AdapterType::NepTUN),
            TelioAdapterType::LinuxNativeTun => Ok(AdapterType::LinuxNativeWg),
            TelioAdapterType::WindowsNativeTun => Ok(AdapterType::WindowsNativeWg),
            TelioAdapterType::Custom => Err("Unsupported TelioAdapterType::Custom".to_owned()),
        }
    }
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
