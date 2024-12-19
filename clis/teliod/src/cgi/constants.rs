use const_format::concatcp;

#[cfg(feature = "qnap")]
mod consts {
    use super::*;

    pub const APP_DIR: &str = "/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet";
}

#[cfg(not(feature = "qnap"))]
mod consts {
    pub const APP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/debug");
}

use consts::*;

pub const TELIOD_TMP_DIR: &str = "/tmp/nordsecuritymeshnet";
pub const PID_FILE: &str = concatcp!(TELIOD_TMP_DIR, "/teliod.pid");
pub const TELIOD_BIN: &str = concatcp!(APP_DIR, "/teliod");
pub const MESHNET_LOG: &str = concatcp!(APP_DIR, "/meshnet.log");
pub const TELIOD_LOG: &str = "/var/log/teliod.log";

#[cfg(not(test))]
pub const TELIOD_CFG: &str = concatcp!(APP_DIR, "/teliod.cfg");
#[cfg(test)]
pub const TELIOD_CFG: &str = "/tmp/teliod_config.json";
