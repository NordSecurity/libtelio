use parking_lot::{lock_api::RawRwLock, RwLock};
use std::{ffi::c_char, fmt::Display};

///
/// Log levels used in LibfwLogCallback
///
#[allow(clippy::enum_variant_names)]
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LibfwLogLevel {
    LibfwLogLevelTrace = 0,
    LibfwLogLevelDebug = 1,
    LibfwLogLevelInfo = 2,
    LibfwLogLevelWarn = 3,
    LibfwLogLevelErr = 4,
}

impl Display for LibfwLogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LibfwLogLevel::LibfwLogLevelTrace => write!(f, "TRACE"),
            LibfwLogLevel::LibfwLogLevelDebug => write!(f, "DEBUG"),
            LibfwLogLevel::LibfwLogLevelInfo => write!(f, "INFO"),
            LibfwLogLevel::LibfwLogLevelWarn => write!(f, "WARN"),
            LibfwLogLevel::LibfwLogLevelErr => write!(f, "ERROR"),
        }
    }
}

///
/// A callback type for providing logs from
/// library into VPN protocol implementation
///
/// @level - log level as defined in @LIBFW_LOG_LEVEL
/// @log_line - zero-terminated log line
///
pub type LibfwLogCallback = Option<extern "C" fn(level: LibfwLogLevel, log_line: *const c_char)>;

pub(crate) static LOG_CALLBACK: RwLock<LibfwLogCallback> = RwLock::const_new(RawRwLock::INIT, None);
pub(crate) static MIN_LOG_LEVEL: RwLock<LibfwLogLevel> =
    RwLock::const_new(RawRwLock::INIT, LibfwLogLevel::LibfwLogLevelInfo);

macro_rules! libfw_log {
    ($level:expr, $text:literal) => {
        {
            use crate::log::{LOG_CALLBACK, MIN_LOG_LEVEL, LibfwLogLevel};
            if *MIN_LOG_LEVEL.read() <= $level {
                if let Some(logger) = LOG_CALLBACK.read().as_ref() {
                    use std::ffi::CString;
                    match CString::new($text) {
                        Ok(message) => {
                            logger($level, message.as_ptr());
                        },
                        Err(err) => if let Ok(message) = CString::new(format!("INVALID LOG MESSAGE: NULL byte on position: {}", err.nul_position())) {
                            // There can't be any NULL characters in this string, so this log won't be skipped anyway, but let's just skip it to have panic-less code
                            logger($level, message.as_ptr());
                        }
                    };
                }
            }
        }
    };
    ($level:expr, $text:literal, $($arg:expr),*) => {
        {
            use crate::log::{LOG_CALLBACK, MIN_LOG_LEVEL, LibfwLogLevel};
            if *MIN_LOG_LEVEL.read() <= $level {
                if let Some(logger) = LOG_CALLBACK.read().as_ref() {
                    use std::ffi::CString;
                    match CString::new(format!($text, $($arg),*)) {
                        Ok(message) => {
                            logger($level, message.as_ptr());
                        },
                        Err(err) => if let Ok(message) = CString::new(format!("INVALID LOG MESSAGE: NULL byte on position: {}", err.nul_position())) {
                            // There can't be any NULL characters in this string, so this log won't be skipped anyway, but let's just skip it to have panic-less code
                            logger($level, message.as_ptr());
                        }
                    };
                }
            }
        }
    };
}

pub(crate) use libfw_log;

macro_rules! libfw_log_trace {
    ($($arg:expr),+) => {
        {
            use crate::log::libfw_log;
            libfw_log!(LibfwLogLevel::LibfwLogLevelTrace, $($arg),+)
        }
    };
}

pub(crate) use libfw_log_trace;

macro_rules! libfw_log_debug {
    ($($arg:expr),+) => {
        {
            use crate::log::libfw_log;
            libfw_log!(LibfwLogLevel::LibfwLogLevelDebug, $($arg),+)
        }
    };
}

pub(crate) use libfw_log_debug;

macro_rules! libfw_log_warn {
    ($($arg:expr),+) => {
        {
            use crate::log::libfw_log;
            libfw_log!(LibfwLogLevel::LibfwLogLevelWarn, $($arg),+)
        }
    };
}

pub(crate) use libfw_log_warn;
