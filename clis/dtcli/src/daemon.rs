use anyhow::Result;
// This crate only works on unix systems and not Windows.
use daemonize::Daemonize;
use psutil::process::{self, Process};
use std::fs::File;

pub enum ProcessType {
    Api,
    Daemon,
}

pub struct Daemon;

impl Daemon {
    pub fn is_running() -> Result<bool> {
        match std::fs::read_to_string("daemon/dtcli.pid") {
            Ok(pid_str) => {
                let pid: u32 = pid_str.trim().parse()?;
                match Process::new(pid) {
                    Ok(process) => Ok(process.is_running()),
                    Err(e) => match e {
                        process::ProcessError::NoSuchProcess { .. } => Ok(false),
                        e => Err(e.into()),
                    },
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => Ok(false),
                _ => Err(e.into()),
            },
        }
    }

    pub fn start() -> Result<ProcessType> {
        std::fs::create_dir_all("daemon")?;
        let stdout = File::create("daemon/daemon.out")?;
        let stderr = File::create("daemon/daemon.err")?;
        let daemonize = Daemonize::new()
            .pid_file("dtcli.pid") // Every method except `new` and `start`
            .chown_pid_file(true) // is optional, see `Daemonize` documentation
            .working_directory("daemon") // for default behavior.
            // TODO not sure if this is a good idea, but it's a workaround for now.
            .user("root")
            .group("daemon") // Group name
            .group(2) // or group id.
            .umask(0o777) // Set umask, `0o027` by default.
            .stdout(stdout) // Redirect stdout to `/tmp/daemon.out`.
            .stderr(stderr) // Redirect stderr to `/tmp/daemon.err`.
            .privileged_action(|| "Executed before privileges are dropped");

        match daemonize.execute() {
            daemonize::Outcome::Parent(Ok(daemonize::Parent { .. })) => Ok(ProcessType::Api),
            daemonize::Outcome::Parent(Err(err)) => Err(err.into()),
            daemonize::Outcome::Child(Ok(_)) => Ok(ProcessType::Daemon),
            daemonize::Outcome::Child(Err(err)) => Err(err.into()),
        }
    }
}
