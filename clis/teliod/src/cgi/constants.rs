use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Application paths configuration
pub static APP_PATHS: LazyLock<AppPaths> = LazyLock::new(AppPaths::new);

/// System-wide log paths configuration
pub static LOG_PATHS: LazyLock<LogPaths> = LazyLock::new(LogPaths::new);

/// Handles all teliod-relative paths
#[derive(Debug, Clone)]
pub struct AppPaths {
    root: PathBuf,
}

impl AppPaths {
    /// Creates a new AppPaths instance based on the current configuration
    fn new() -> Self {
        let root = if cfg!(feature = "qnap") {
            PathBuf::from("/share/CACHEDEV1_DATA/.qpkg/NordSecurityMeshnet")
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target")
                .join(if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                })
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
    pub fn join<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        self.root.join(path)
    }
}

/// System-wide log paths configuration
#[derive(Debug, Clone)]
pub struct LogPaths {
    stdout: PathBuf,
    init_stdout: PathBuf,
    lib_dir: PathBuf,
    lib_prefix: String,
}

impl LogPaths {
    /// Creates a new LogPaths instance
    fn new() -> Self {
        Self {
            stdout: PathBuf::from("/var/log/teliod.log"),
            init_stdout: PathBuf::from("/var/log/teliod_init.log"),
            lib_dir: PathBuf::from("/var/log"),
            lib_prefix: String::from("teliod_lib.log"),
        }
    }

    /// Path to the redirected STDOUT/STDERR streams after daemonizing
    pub fn stdout(&self) -> &Path {
        &self.stdout
    }

    /// Path to the redirected STDOUT/STDERR streams before daemonizing
    pub fn init_stdout(&self) -> &Path {
        &self.init_stdout
    }

    /// Base directory for the rotating libtelio trace logs
    pub fn lib_dir(&self) -> &Path {
        &self.lib_dir
    }

    /// Filename prefix for the rotating libtelio trace logs
    pub fn lib_logs_prefix(&self) -> &str {
        &self.lib_prefix
    }

    /// Get path to the rotating log files (without suffix)
    pub fn lib_log_path(&self) -> PathBuf {
        self.lib_dir.join(&self.lib_prefix)
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
        assert_eq!(paths.stdout(), Path::new("/var/log/teliod.log"));
        assert_eq!(
            paths.lib_log_path(),
            PathBuf::from("/var/log/teliod_lib.log")
        );
    }
}
