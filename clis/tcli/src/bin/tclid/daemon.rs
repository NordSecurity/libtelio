//! Code for general daemon handling utilities and abstracting away related dependencies.

use std::path::PathBuf;

use anyhow::{self, Result};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

use crate::TCLID_WD_PATH;

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
pub struct Daemon;

impl Daemon {
    /// Checks whether the daemon is currently running.
    /// Won't work if pid file had been tampered with or it's location changed.
    ///
    /// # Returns
    ///
    /// Result containing a bool. True means that the daemon is running.
    pub fn is_running() -> Result<bool> {
        let system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );

        match std::fs::read_to_string(get_wd_path()?.join("tclid.pid")) {
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
    pub fn get_stderr() -> Result<String> {
        let stderr_file = get_wd_path()?.join("tclid.err");

        let stderr_string = std::fs::read_to_string(stderr_file)?;

        Ok(stderr_string)
    }

    /// Forks the daemon from the API process.
    ///
    /// # Returns
    ///
    /// Current process type indicating whether it's the API or the Daemon.
    /// This is useful because of how the fork syscall.
    pub fn start() -> Result<ProcessType> {
        #[cfg(unix)]
        {
            use std::fs::File;
            // This crate only works on unix systems and not Windows.
            use daemonize::Daemonize;

            let tclid_wd_path = get_wd_path()?;

            std::fs::create_dir_all(&tclid_wd_path)?;
            let stderr = File::create(tclid_wd_path.join("tclid.err"))?;

            let daemonize = Daemonize::new()
                .pid_file("tclid.pid") // Every method except `new` and `start`
                .chown_pid_file(true) // is optional, see `Daemonize` documentation
                .working_directory(tclid_wd_path) // for default behavior.
                .stderr(stderr); // Redirect stderr to `/tmp/daemon.err`.

            match daemonize.execute() {
                daemonize::Outcome::Parent(Ok(daemonize::Parent { .. })) => Ok(ProcessType::Api),
                daemonize::Outcome::Parent(Err(err)) => Err(err.into()),
                daemonize::Outcome::Child(Ok(_)) => Ok(ProcessType::Daemon),
                daemonize::Outcome::Child(Err(err)) => Err(err.into()),
            }
        }
        #[cfg(not(unix))]
        todo!("Windows support not implemented for TCLID");
    }
}

/// Private helper function for getting the path to the daemon's working directory.
///
/// # Returns
///
/// Result containing the path of the daemons work directory.
fn get_wd_path() -> Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or(anyhow::anyhow!(
            "Cannot create daemon working directory at root"
        ))?
        .join(TCLID_WD_PATH))
}
