//! Main and implementation of config and commands for Nord VPN Lite - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use daemonize::{Daemonize, Outcome};
use std::fs::OpenOptions;
use tokio::time::{timeout, Duration};

mod command_listener;
mod comms;
mod config;
mod core_api;
mod daemon;
mod interface;
mod logging;

use crate::{
    command_listener::{ClientCmd, Cmd, CommandResponse, TIMEOUT_SEC},
    comms::DaemonSocket,
    config::NordVpnLiteConfig,
    core_api::get_countries_with_exp_backoff,
    daemon::NordVpnLiteError,
};

/// Umask allows only rw-rw-r--
const DEFAULT_UMASK: u32 = 0o113;

fn main() -> Result<(), NordVpnLiteError> {
    let mut cmd = Cmd::parse();

    // Pre-daemonizing setup
    if let Cmd::Start(opts) = &mut cmd {
        // Check if daemon already is running before forking
        if DaemonSocket::get_ipc_socket_path()?.exists() {
            return Err(NordVpnLiteError::DaemonIsRunning);
        }

        // Parse config file
        let mut config = NordVpnLiteConfig::from_file(&opts.config_path)?;
        config.resolve_env_token();

        println!("Saving logs to: {}", config.log_file_path);
        println!("Starting daemon");

        // Fork the process before starting Tokio runtime.
        // Tokio creates a multi-threaded asynchronous runtime,
        // but during forking only a single thread survives,
        // leaving tokio runtime in an undefined state and resulting in a panic.
        // https://github.com/tokio-rs/tokio/issues/4301
        if !opts.no_detach {
            // Redirect stdout and stderr to a specified file or /var/log/nordvpnlite.log by default
            let stdout_log_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&opts.stdout_path)?;

            // Daemon working directory is set to `/` by default
            // any relative path operations from now on could fail
            let daemon = Daemonize::new()
                .umask(DEFAULT_UMASK)
                .working_directory(&opts.working_directory)
                .stdout(stdout_log_file.try_clone()?)
                .stderr(stdout_log_file);

            // Daemonize the process
            match daemon.execute() {
                // Quit parent process
                Outcome::Parent(Ok(_)) => {
                    return Ok(());
                }
                // Continue in child process
                Outcome::Child(Ok(_)) => {}
                // Errors
                Outcome::Parent(Err(err)) => {
                    eprintln!("Fork parent error: {err}");
                    return Err(err.into());
                }
                Outcome::Child(Err(err)) => {
                    eprintln!("Child error {err}");
                    return Err(err.into());
                }
            }
        }

        // Run the daemon event loop
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            // Setup daemon logging
            let _tracing_worker_guard = logging::setup_logging(
                &config.log_file_path,
                config.log_level,
                config.log_file_count,
            )
            .await?;

            Box::pin(daemon::daemon_event_loop(config)).await
        })
    } else {
        client_main(cmd)
    }
}

#[tokio::main]
async fn client_main(cmd: Cmd) -> Result<(), NordVpnLiteError> {
    match cmd {
        Cmd::Client(cmd) => {
            let socket_path = DaemonSocket::get_ipc_socket_path()?;
            if socket_path.exists() {
                let response = timeout(
                    Duration::from_secs(TIMEOUT_SEC),
                    DaemonSocket::send_command(&socket_path, &serde_json::to_string(&cmd)?),
                )
                .await
                .map_err(|_| NordVpnLiteError::ClientTimeoutError)?;

                match CommandResponse::deserialize(&response?)? {
                    CommandResponse::Ok => {
                        println!("Command executed successfully");
                        Ok(())
                    }
                    CommandResponse::StatusReport(status) => {
                        println!("{}", serde_json::to_string_pretty(&status)?);
                        Ok(())
                    }
                    CommandResponse::DaemonInitializing => {
                        println!("Daemon is not ready, ignoring");
                        Err(NordVpnLiteError::CommandFailed(cmd))
                    }
                    CommandResponse::Err(e) => {
                        println!("Command executed failed: {e}");
                        Err(NordVpnLiteError::CommandFailed(cmd))
                    }
                }
            } else {
                match cmd {
                    ClientCmd::QuitDaemon => {
                        println!("Daemon is already stopped");
                        Ok(())
                    }
                    _ => Err(NordVpnLiteError::DaemonIsNotRunning),
                }
            }
        }
        // Display list of available countries with VPN servers
        Cmd::Countries => {
            for country in get_countries_with_exp_backoff(None).await? {
                println!("{}: {}", country.name, country.code);
            }
            Ok(())
        }

        // Unexpected command, Cmd::Start should be handled by main
        _ => Err(NordVpnLiteError::InvalidCommand(format!("{cmd:?}"))),
    }
}
