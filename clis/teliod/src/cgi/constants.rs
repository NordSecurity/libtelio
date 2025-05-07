use const_format::concatcp;

#[cfg(feature = "qnap")]
pub const APP_DIR: &str = "/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet";
#[cfg(not(feature = "qnap"))]
pub const APP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug");

pub const TELIOD_BIN: &str = concatcp!(APP_DIR, "/teliod");
pub const TELIOD_CFG: &str = concatcp!(APP_DIR, "/teliod.cfg");
pub const TELIOD_LOG_PATH: &str = "/var/log";
pub const TELIOD_LOG_PREFIX: &str = "teliod_lib.log";
pub const TELIOD_STDOUT: &str = concatcp!(TELIOD_LOG_PATH, "/teliod.log");
#[cfg(debug_assertions)]
pub const CGI_LOG: &str = concatcp!(APP_DIR, "/cgi.log");
