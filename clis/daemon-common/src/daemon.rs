//! Code for general daemon handling utilities and abstracting away related dependencies.

use std::path::PathBuf;

use anyhow::Result;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

use daemonize::Daemonize;

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

        match std::fs::read_to_string(get_wd_path(Self::NAME)?.join(format!("{}.pid", Self::NAME)))
        {
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

    /// Function for conveniently printing the stderr file of the daemon.
    /// Used by the API to quickly inform the user if something is wrong
    /// with the daemon.
    ///
    /// # Returns
    ///
    /// The whole contents of the daemons stderr file as a String.
    fn get_stderr() -> Result<String> {
        let stderr_file = get_wd_path(Self::NAME)?.join(format!("{}.err", Self::NAME));

        let stderr_string = std::fs::read_to_string(stderr_file)?;

        Ok(stderr_string)
    }

    /// Forks the daemon from the API process.
    ///
    /// # Returns
    ///
    /// Current process type indicating whether it's the API or the Daemon.
    /// This is useful because of how the fork syscall.
    fn start() -> Result<ProcessType> {
        use std::fs::File;
        let wd_path = get_wd_path(Self::NAME)?;

        std::fs::create_dir_all(&wd_path)?;
        let stderr = File::create(wd_path.join(format!("{}.err", Self::NAME)))?;

        // Every method except `new` and `start` is optional, see `Daemonize` documentation for
        // default behavior.
        let daemonize = Daemonize::new()
            .pid_file(format!("{}.pid", Self::NAME))
            .chown_pid_file(true)
            .working_directory(wd_path)
            .stderr(stderr);

        match daemonize.execute() {
            daemonize::Outcome::Parent(Ok(daemonize::Parent { .. })) => Ok(ProcessType::Api),
            daemonize::Outcome::Parent(Err(err)) => Err(err.into()),
            daemonize::Outcome::Child(Ok(_)) => Ok(ProcessType::Daemon),
            daemonize::Outcome::Child(Err(err)) => Err(err.into()),
        }
    }

    /// Helper function for putting together the directory in which the daemon socket file will reside.
    ///
    /// # Returns
    ///
    /// Path to the IPC socket.
    fn get_ipc_socket_path() -> Result<PathBuf> {
        get_wd_path(Self::NAME).map(|path| path.join(format!("{}.sock", &Self::NAME)))
    }
}

/// Private helper function for getting the path to the daemon's working directory.
///
/// # Returns
///
/// Result containing the path of the daemons work directory.
fn get_wd_path(daemon_name: &str) -> Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or(anyhow::anyhow!(
            "Cannot create daemon working directory at root"
        ))?
        .join(format!("/var/run/{}_wd", daemon_name)))
}
