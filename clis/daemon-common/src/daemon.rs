//! Code for general daemon handling utilities and abstracting away related dependencies.

use std::path::PathBuf;

use anyhow::Result;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

/// Enum for figuring out the current process after the daemon is forked away
/// from the API by the daemonization.
pub enum ProcessType {
    /// Getting this value after the daemonization means that the current process is the API.
    Api,
    /// Getting this value after the daemonization means that the current process is the Daemon.
    Daemon,
}

/// Struct for packaging together the functions for managing the daemon.
/// Currently does not need any members, since most of the data is stored
/// in files anyway.
pub trait Daemon {
    /// Daemon name, used for naming daemon files
    const NAME: &'static str;

    /// Helper function for getting the path to the daemon's working directory.
    /// The directory is used for storing *.pid and *.socket files.
    ///
    /// # Returns
    ///
    /// Result containing the path of the daemons work directory.
    fn get_wd_path() -> Result<PathBuf>;

    /// Checks whether the daemon is currently running.
    /// Won't work if pid file had been tampered with or it's location changed.
    ///
    /// # Returns
    ///
    /// Result containing a bool. True means that the daemon is running.
    fn is_running() -> Result<bool> {
        let system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );

        match std::fs::read_to_string(Self::get_pid_path()?) {
            Ok(pid_str) => {
                let pid: usize = pid_str.trim().parse()?;
                match system.process(sysinfo::Pid::from(pid)) {
                    Some(_) => Ok(true),
                    None => Ok(false),
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => Ok(false),
                _ => Err(e.into()),
            },
        }
    }

    /// Helper function for putting together the directory in which the daemon socket file will reside.
    ///
    /// # Returns
    ///
    /// Path to the IPC socket
    fn get_ipc_socket_path() -> Result<PathBuf> {
        Self::get_wd_path().map(|path| path.join(format!("{}.sock", &Self::NAME)))
    }

    /// Helper function for getting the daemon's pid file path.
    ///
    /// # Returns
    ///
    /// Path to pid file
    fn get_pid_path() -> Result<PathBuf> {
        Self::get_wd_path().map(|path| path.join(format!("{}.pid", &Self::NAME)))
    }
}
