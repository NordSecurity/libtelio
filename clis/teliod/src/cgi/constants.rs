use const_format::concatcp;

#[cfg(feature = "qnap")]
pub const APP_DIR: &str = "/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet";
#[cfg(not(feature = "qnap"))]
pub const APP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/debug");

pub const TELIOD_BIN: &str = concatcp!(APP_DIR, "/teliod");
pub const MESHNET_LOG: &str = concatcp!(APP_DIR, "/meshnet.log");
pub const TELIOD_LOG: &str = "/var/log/teliod.log";

#[cfg(not(test))]
pub const TELIOD_CFG: &str = concatcp!(APP_DIR, "/teliod.cfg");
#[cfg(test)]
pub const TELIOD_CFG: &str = "/tmp/teliod_config.json";