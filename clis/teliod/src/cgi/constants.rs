use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

use crate::TeliodError;

/// Application paths configuration
pub static APP_PATHS: AppPathsHandle = AppPathsHandle::new();

/// System-wide log paths configuration
pub static LOG_PATHS: LazyLock<LogPaths> = LazyLock::new(LogPaths::new);

pub struct AppPathsHandle {
    inner: OnceLock<AppPaths>,
}

impl AppPathsHandle {
    pub const fn new() -> Self {
        Self {
            inner: OnceLock::new(),
        }
    }

    pub fn init(&self) -> Result<(), TeliodError> {
        let paths = AppPaths::new()?;
        self.inner.set(paths).map_err(|_| {
            TeliodError::SystemCommandFailed("AppPaths already initialized".to_string())
        })?;
        Ok(())
    }
}

impl std::ops::Deref for AppPathsHandle {
    type Target = AppPaths;

    #[allow(clippy::expect_used)]
    fn deref(&self) -> &Self::Target {
        self.inner
            .get()
            .expect("AppPaths not initialized, initialize it first")
    }
}

/// Handles all teliod-relative paths
#[derive(Debug, Clone)]
pub struct AppPaths {
    root: PathBuf,
}

impl AppPaths {
    /// Creates a new AppPaths instance based on the current configuration
    fn new() -> Result<Self, TeliodError> {
        let root = if cfg!(feature = "qnap") {
            let output = std::process::Command::new("getcfg")
                .args([
                    "NordSecurityMeshnet",
                    "Install_Path",
                    "-f",
                    "/etc/config/qpkg.conf",
                ])
                .output()
                .map_err(|e| {
                    TeliodError::SystemCommandFailed(format!("Failed to execute getcfg: {e}"))
                })?;

            if !output.status.success() {
                return Err(TeliodError::SystemCommandFailed(format!(
                    "getcfg failed with status: {}",
                    output.status
                )));
            }

            let path = String::from_utf8(output.stdout).map_err(|e| {
                TeliodError::InvalidResponse(format!("Invalid UTF-8 in getcfg output: {e}"))
            })?;
            if path.trim().is_empty() {
                return Err(TeliodError::InvalidResponse(
                    "getcfg returned empty path".into(),
                ));
            }

            PathBuf::from(path.trim())
        } else {
            // TODO: LLT-6427
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target")
                .join(if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                })
        };

        Ok(Self { root })
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
        self.root.join(path)
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

    fn get_expected_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("target")
            .join("debug")
    }

    #[test]
    fn test_app_paths_root() {
        let handle = AppPathsHandle::new();
        handle.init().unwrap();

        assert_eq!(handle.join(""), get_expected_root());
    }

    #[test]
    fn test_app_paths_init() {
        let handle = AppPathsHandle::new();
        handle.init().unwrap();

        assert_eq!(handle.teliod_bin(), get_expected_root().join("teliod"));
        assert_eq!(handle.teliod_cfg(), get_expected_root().join("teliod.cfg"));
    }

    #[test]
    #[should_panic]
    fn test_uninit_app_paths_deref_fails() {
        let handle = AppPathsHandle::new();

        handle.teliod_bin();
    }

    #[test]
    fn test_app_paths_double_init_fails() {
        let handle = AppPathsHandle::new();

        assert!(handle.init().is_ok());
        assert!(handle.init().is_err());
    }

    #[test]
    fn test_app_paths_functionality() {
        let handle = AppPathsHandle::new();
        handle.init().unwrap();

        let root = handle.join("");
        let test_path = handle.join("some/mysterious/path");
        let expected_path = Path::new(&root.as_os_str()).join("some/mysterious/path");

        assert_eq!(test_path, expected_path);
    }

    #[test]
    fn test_app_paths_concurrency() {
        use std::thread;

        let res = APP_PATHS.init();
        if let Err(e) = res {
            assert_eq!(
                e.to_string(),
                "Failed executing system command: \"AppPaths already initialized\""
            );
        }

        let mut handles = vec![];
        for _ in 0..10 {
            let thread_handle = thread::spawn(move || {
                assert_eq!(APP_PATHS.teliod_bin(), get_expected_root().join("teliod"));
                assert_eq!(
                    APP_PATHS.teliod_cfg(),
                    get_expected_root().join("teliod.cfg")
                );
                assert_eq!(APP_PATHS.cgi_log(), get_expected_root().join("cgi.log"));
                assert_eq!(
                    APP_PATHS.start_intent(),
                    get_expected_root().join(".teliod_start_intent")
                );
            });
            handles.push(thread_handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_log_paths() {
        assert_eq!(LOG_PATHS.daemon_log(), Path::new("/var/log/teliod.log"));
        assert_eq!(LOG_PATHS.log(), PathBuf::from("/var/log/teliod_lib.log"));
    }
}
