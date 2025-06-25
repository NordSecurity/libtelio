use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Application paths configuration
pub static APP_PATHS: LazyLock<AppPaths> = LazyLock::new(AppPaths::new);

/// System-wide log paths configuration
pub static LOG_PATHS: LazyLock<LogPaths> = LazyLock::new(LogPaths::new);

/// Handles all teliod-relative paths
#[derive(Debug, Clone)]
pub struct AppPaths {
    root: Option<PathBuf>,
}

impl AppPaths {
    /// Creates a new AppPaths instance based on the current configuration
    fn new() -> Self {
        let root = if cfg!(feature = "qnap") {
            std::process::Command::new("getcfg")
                .args([
                    "NordSecurityMeshnet",
                    "Install_Path",
                    "-f",
                    "/etc/config/qpkg.conf",
                ])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|stdout| stdout.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        } else {
            Some(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join("target")
                    .join(if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    }),
            )
        };

        Self { root }
    }

    /// Path to the teliod executable
    pub fn teliod_bin(&self) -> PathBuf {
        self.join("teliod")
    }

    /// Path to the teliod config file
    pub fn teliod_cfg(&self) -> PathBuf {
        self.join("teliod.cfg")
    }

    /// Path to the CGI log file (debug builds only)
    #[cfg(debug_assertions)]
    pub fn cgi_log(&self) -> PathBuf {
        self.join("cgi.log")
    }

    /// Path to the user intent file used to automatically turn meshnet on
    /// if found by NordSecurityMeshnet.sh
    pub fn start_intent(&self) -> PathBuf {
        self.join(".teliod_start_intent")
    }

    /// Create a path relative to the root directory
    #[cfg_attr(test, visibility::make(pub))]
    fn join(&self, path: &str) -> PathBuf {
        self.root
            .as_ref()
            .map(|root| root.join(path))
            .unwrap_or_else(|| PathBuf::from(path))
    }
}

/// System-wide log paths configuration
#[derive(Debug, Clone)]
pub struct LogPaths {
    daemon_log: PathBuf,
    daemon_init_log: PathBuf,
    dir: PathBuf,
    prefix: String,
}

impl LogPaths {
    /// Creates a new LogPaths instance
    fn new() -> Self {
        Self {
            daemon_log: PathBuf::from("/var/log/teliod.log"),
            daemon_init_log: PathBuf::from("/var/log/teliod_init.log"),
            dir: PathBuf::from("/var/log"),
            prefix: String::from("teliod_lib.log"),
        }
    }

    /// Path to the redirected STDOUT/STDERR streams after daemonizing
    pub fn daemon_log(&self) -> &Path {
        &self.daemon_log
    }

    /// Path to the redirected STDOUT/STDERR streams before daemonizing
    pub fn daemon_init_log(&self) -> &Path {
        &self.daemon_init_log
    }

    /// Base directory for the rotating libtelio trace logs
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Filename prefix for the rotating libtelio trace logs
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Get path to the rotating log files (without suffix)
    pub fn log(&self) -> PathBuf {
        self.dir.join(&self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_paths_init() {
        let paths = AppPaths::new();
        assert!(paths.teliod_bin().ends_with("teliod"));
        assert!(paths.teliod_cfg().ends_with("teliod.cfg"));
    }

    #[test]
    fn test_app_paths_functionality() {
        let paths = AppPaths::new();
        let root = paths.join("");
        let test_path = paths.join("some/mysterious/path");
        let expected_path = Path::new(&root.as_os_str()).join("some/mysterious/path");

        assert_eq!(test_path, expected_path);
    }

    #[test]
    fn test_log_paths() {
        let paths = LogPaths::new();
        assert_eq!(paths.daemon_log(), Path::new("/var/log/teliod.log"));
        assert_eq!(paths.log(), PathBuf::from("/var/log/teliod_lib.log"));
    }
}
