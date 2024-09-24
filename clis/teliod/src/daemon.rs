//! Code for general daemon handling utilities and abstracting away related dependencies.

use std::{
    fs::File,
    io::{Error, ErrorKind, Result, Write},
    path::{Path, PathBuf},
    process::id,
};

use sysinfo::{ProcessRefreshKind, RefreshKind, System};

/// Daemon name, used for naming daemon files
const DAEMON_NAME: &str = "teliod";

/// Struct for packaging together the functions for managing the daemon.
/// Currently does not need any members, since most of the data is stored
/// in files anyway.
pub struct TeliodDaemon {}

impl TeliodDaemon {
    /// Initializes all of the needed daemon stuff, currently just creates a PID file
    pub fn init() -> Result<()> {
        // Create pid file
        let pid = id();
        let mut pid_file = File::create(Self::get_pid_path()?)?;
        pid_file.write_fmt(format_args!("{}", pid))?;
        Ok(())
    }

    /// Checks whether the daemon is currently running.
    pub fn is_running() -> Result<bool> {
        let system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );

        match std::fs::read_to_string(Self::get_pid_path()?) {
            Ok(pid_str) => {
                let pid: usize = pid_str.trim().parse().map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "Cannot parse the PID from the daemon's PID file",
                    )
                })?;
                match system.process(sysinfo::Pid::from(pid)) {
                    Some(_) => Ok(true),
                    None => Ok(false),
                }
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(false),
                _ => Err(e),
            },
        }
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

    /// Returns path to pid file
    pub fn get_pid_path() -> Result<PathBuf> {
        Self::get_runtime_data_directory().map(|path| path.join(format!("{}.pid", &DAEMON_NAME)))
    }
}
