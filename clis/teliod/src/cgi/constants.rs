use const_format::concatcp;

#[cfg(feature = "qnap")]
pub const APP_DIR: &str = "/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet";
#[cfg(not(feature = "qnap"))]
pub const APP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug");

pub const TELIOD_BIN: &str = concatcp!(APP_DIR, "/teliod");
pub const TELIOD_CFG: &str = concatcp!(APP_DIR, "/teliod.cfg");

/// Base directory for the rotating libtelio trace logs
pub const TELIOD_LIB_LOG_DIR: &str = "/var/log";
/// Filename prefix for the rotating libtelio trace logs
pub const TELIOD_LIB_LOG_PREFIX: &str = "teliod_lib.log";
/// Path to the rotating long files (without suffix)
pub const TELIOD_LIB_LOG: &str = concatcp!(TELIOD_LIB_LOG_DIR, "/", TELIOD_LIB_LOG_PREFIX);
/// Path to the redirected STDOUT and STDERR streams
pub const TELIOD_STDOUT_LOG: &str = "/var/log/teliod.log";
/// Path to the redirected STDOUT and STDERR streams before daemonizing
pub const TELIOD_INIT_LOG: &str = "/var/log/teliod_init.log";

#[cfg(debug_assertions)]
pub const CGI_LOG: &str = concatcp!(APP_DIR, "/cgi.log");
