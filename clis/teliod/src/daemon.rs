//! Code for general daemon handling utilities and abstracting away related dependencies.

use std::{
    fs::{self, File},
    io::{Error, ErrorKind, Result, Write},
    path::{Path, PathBuf},
    process::id,
};

/// Daemon name, used for naming daemon files
const DAEMON_NAME: &str = "teliod";

/// Struct for packaging together the functions for managing the daemon.
/// Currently does not need any members, since most of the data is stored
/// in files anyway.
pub struct TeliodDaemon {
    pid_path: PathBuf,
}

impl TeliodDaemon {
    /// Initializes all of the needed daemon stuff, currently just creates a PID file
    pub fn new() -> Result<Self> {
        let pid_path = Self::get_runtime_data_directory()?.join(format!("{}.pid", &DAEMON_NAME));

        // Create pid file
        let pid = id();
        let mut pid_file = File::create(&pid_path)?;
        pid_file.write_fmt(format_args!("{}\n", pid))?;

        Ok(Self { pid_path })
    }

    /// Returns the path to the directory in which Teliod stores runtime data
    /// When available it uses `/run/`, then checks `/var/run` and if none of
    /// them is available it returns an error.
    pub fn get_runtime_data_directory() -> Result<PathBuf> {
        if Path::new("/run").exists() {
            Ok(PathBuf::from("/run/"))
        } else if Path::new("/var/run/").exists() {
            Ok(PathBuf::from("/var/run/"))
        } else {
            Err(Error::new(
                ErrorKind::NotFound,
                "Neither /run/ nor /var/run/ exists",
            ))
        }
    }

    /// Returns path to the IPC socket
    pub fn get_ipc_socket_path() -> Result<PathBuf> {
        Self::get_runtime_data_directory().map(|path| path.join(format!("{}.sock", &DAEMON_NAME)))
    }

    /// Checks whether the daemon is currently running.
    pub fn is_running() -> Result<bool> {
        Ok(Self::get_ipc_socket_path()?.exists())
    }
}

impl Drop for TeliodDaemon {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.pid_path);
    }
}
