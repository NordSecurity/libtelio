use libc::c_char;
use telio_crypto::KeyDecodeError;
use telio_utils::map_enum;
use tracing::Level;

use anyhow::anyhow;

use std::{ffi::c_void, panic::RefUnwindSafe};

use crate::device::{AdapterType, Error as DevError, Result as DevResult};

pub trait TelioEventCb: Send + Sync + std::fmt::Debug {
    fn event(&self, payload: String);
}

pub trait TelioLoggerCb: Send + Sync + std::fmt::Debug {
    fn log(&self, log_level: TelioLogLevel, payload: String);
}

pub trait TelioProtectCb: Send + Sync + RefUnwindSafe + std::fmt::Debug {
    fn protect(&self, payload: i32);
}

pub type FFIResult<T> = Result<T, TelioError>;

#[derive(Debug, thiserror::Error)]
pub enum TelioError {
    #[error("UnknownError: {0}")]
    UnknownError(#[source] anyhow::Error),
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
            _ => Self::UnknownError(anyhow!(err)),
        }
    }
}

impl From<&DevError> for TelioError {
    fn from(err: &DevError) -> Self {
        // TODO: Map more error types.
        match err {
            DevError::AlreadyStarted => Self::AlreadyStarted,
            DevError::BadPublicKey => Self::InvalidKey,
            _ => Self::UnknownError(anyhow!(err.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
pub enum telio_result {
    /// Operation was successful.
    TELIO_RES_OK = 0,
    /// Operation resulted to unknown error.
    TELIO_RES_ERROR = 1,
    /// Cannot parse key as base64 string.
    TELIO_RES_INVALID_KEY = 2,
    /// Cannot parse configuration.
    TELIO_RES_BAD_CONFIG = 3,
    /// Cannot lock a mutex.
    TELIO_RES_LOCK_ERROR = 4,
    /// Cannot parse a string.
    TELIO_RES_INVALID_STRING = 5,
    /// The device is already started.
    TELIO_RES_ALREADY_STARTED = 6,
}
impl std::error::Error for telio_result {}
impl std::fmt::Display for telio_result {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TELIO_RES_ALREADY_STARTED => write!(f, "Device is already started"),
            TELIO_RES_INVALID_KEY => write!(f, "Cannot parse key as base64 string"),
            TELIO_RES_BAD_CONFIG => write!(f, "Cannot Parse Configuration "),
            TELIO_RES_LOCK_ERROR => write!(f, "Cannot lock a mutex"),
            TELIO_RES_INVALID_STRING => write!(f, "Cannot parse a string"),
            TELIO_RES_ERROR => write!(f, "Unknown error"),
            TELIO_RES_OK => write!(f, "Operation was successful"),
        }
    }
}
pub use telio_result::*;

#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[allow(dead_code)]
#[repr(C)]
/// Possible adapters.
pub enum telio_adapter_type {
    /// Userland rust implementation.
    TELIO_ADAPTER_BORING_TUN,
    /// Linux in-kernel WireGuard implementation
    TELIO_ADAPTER_LINUX_NATIVE_TUN,
    /// WireguardGo implementation
    TELIO_ADAPTER_WIREGUARD_GO_TUN,
    /// WindowsNativeWireguardNt implementation
    TELIO_ADAPTER_WINDOWS_NATIVE_TUN,
}

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Possible log levels.
pub enum telio_log_level {
    TELIO_LOG_CRITICAL = 1,
    TELIO_LOG_ERROR = 2,
    TELIO_LOG_WARNING = 3,
    TELIO_LOG_INFO = 4,
    TELIO_LOG_DEBUG = 5,
    TELIO_LOG_TRACE = 6,
}

#[allow(non_camel_case_types)]
pub type telio_event_fn = unsafe extern "C" fn(*mut c_void, *const c_char);

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
/// Event callback
pub struct telio_event_cb {
    /// Context to pass to callback.
    /// User must ensure safe access of this var from multithreaded context.
    pub ctx: *mut c_void,
    /// Function to be called
    pub cb: telio_event_fn,
}

#[allow(non_camel_case_types)]
pub type telio_logger_fn = unsafe extern "C" fn(*mut c_void, telio_log_level, *const c_char);

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
/// Logging callback
pub struct telio_logger_cb {
    /// Context to pass to callback.
    /// User must ensure safe access of this var from multithreaded context.
    pub ctx: *mut c_void,
    /// Function to be called
    pub cb: telio_logger_fn,
}

#[cfg(target_os = "android")]
#[allow(non_camel_case_types)]
pub type telio_protect_fn = unsafe extern "C" fn(*mut c_void, i32);

#[cfg(target_os = "android")]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
/// Android protect fd from VPN callback
pub struct telio_protect_cb {
    /// Context to pass to callback.
    /// User must ensure safe access of this var from multithreaded context.
    pub ctx: *mut c_void,
    /// Function to be called
    pub cb: telio_protect_fn,
}

#[no_mangle]
pub extern "C" fn __telio_force_export(
    _: telio_result,
    _: telio_adapter_type,
    _: telio_event_cb,
    _: telio_logger_cb,
    #[cfg(target_os = "android")] _: telio_protect_cb,
) {
}
// Map library types to C Api types

impl From<&telio_result> for telio_result {
    fn from(r: &telio_result) -> Self {
        *r
    }
}

impl From<KeyDecodeError> for telio_result {
    fn from(_: KeyDecodeError) -> Self {
        TELIO_RES_INVALID_KEY
    }
}

impl From<&KeyDecodeError> for telio_result {
    fn from(_: &KeyDecodeError) -> Self {
        TELIO_RES_INVALID_KEY
    }
}

impl From<serde_json::Error> for telio_result {
    fn from(_: serde_json::Error) -> Self {
        TELIO_RES_BAD_CONFIG
    }
}

impl From<&serde_json::Error> for telio_result {
    fn from(_: &serde_json::Error) -> Self {
        TELIO_RES_BAD_CONFIG
    }
}

impl From<&anyhow::Error> for telio_result {
    fn from(_: &anyhow::Error) -> Self {
        TELIO_RES_ERROR
    }
}

impl From<DevError> for telio_result {
    fn from(_err: DevError) -> Self {
        // TODO: Map more error types.
        match _err {
            DevError::AlreadyStarted => TELIO_RES_ALREADY_STARTED,
            DevError::BadPublicKey => TELIO_RES_INVALID_KEY,
            _ => TELIO_RES_ERROR,
        }
    }
}

impl From<&DevError> for telio_result {
    fn from(_err: &DevError) -> Self {
        // TODO: Map more error types.
        match _err {
            DevError::AlreadyStarted => TELIO_RES_ALREADY_STARTED,
            DevError::BadPublicKey => TELIO_RES_INVALID_KEY,
            _ => TELIO_RES_ERROR,
        }
    }
}

impl From<DevResult> for telio_result {
    fn from(res: DevResult) -> Self {
        use telio_result::*;
        match res {
            Ok(_) => TELIO_RES_OK,
            Err(error) => error.into(),
        }
    }
}

impl From<&DevResult> for telio_result {
    fn from(res: &DevResult) -> Self {
        use telio_result::*;
        match res {
            Ok(_) => TELIO_RES_OK,
            Err(error) => error.into(),
        }
    }
}

map_enum! {
    AdapterType <=> telio_adapter_type,
    BoringTun = TELIO_ADAPTER_BORING_TUN,
    WireguardGo = TELIO_ADAPTER_WIREGUARD_GO_TUN,
    LinuxNativeWg = TELIO_ADAPTER_LINUX_NATIVE_TUN,
    WindowsNativeWg = TELIO_ADAPTER_WINDOWS_NATIVE_TUN
}

map_enum! {
    Level -> telio_log_level,
    ERROR = TELIO_LOG_ERROR,
    WARN = TELIO_LOG_WARNING,
    INFO = TELIO_LOG_INFO,
    DEBUG = TELIO_LOG_DEBUG,
    TRACE = TELIO_LOG_TRACE,
}

map_enum! {
    telio_log_level -> Level,
    TELIO_LOG_CRITICAL = ERROR,
    TELIO_LOG_ERROR = ERROR,
    TELIO_LOG_WARNING = WARN,
    TELIO_LOG_INFO = INFO,
    TELIO_LOG_DEBUG = DEBUG,
    TELIO_LOG_TRACE = TRACE,
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

unsafe impl Sync for telio_event_cb {}
unsafe impl Send for telio_event_cb {}

unsafe impl Sync for telio_logger_cb {}
unsafe impl Send for telio_logger_cb {}

#[cfg(target_os = "android")]
unsafe impl Sync for telio_protect_cb {}
#[cfg(target_os = "android")]
unsafe impl Send for telio_protect_cb {}
