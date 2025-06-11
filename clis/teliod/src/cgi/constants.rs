use const_format::concatcp;
use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;

#[cfg(feature = "qnap")]
pub static APP_DIR: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    let output = Command::new("getcfg")
        .args([
            "NordSecurityMeshnet",
            "Install_Path",
            "-f",
            "/etc/config/qpkg.conf",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        None
    } else {
        let stdout = String::from_utf8(output.stdout).ok()?;
        let trimmed = stdout.trim();

        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    }
});
// pub static APP_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
//     std::env::var("NORDSECURITY_MESHNET_APP_DIR")
//         .map(PathBuf::from)
//         .unwrap_or_else(|_| PathBuf::from("/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet"))
// });
#[cfg(not(feature = "qnap"))]
pub const APP_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug");

pub static TELIOD_BIN: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| APP_DIR.as_ref().map(|dir| dir.join("teliod")));

pub static TELIOD_CFG: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| APP_DIR.as_ref().map(|dir| dir.join("teliod.cfg")));

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
pub static CGI_LOG: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| APP_DIR.as_ref().map(|dir| dir.join("cgi.log")));

/// Path to the user intent file used to automatically turn meshnet on if found by NordSecurityMeshnet.sh
pub const TELIOD_START_INTENT_FILE: &str = concatcp!(APP_DIR, "/.teliod_start_intent");
