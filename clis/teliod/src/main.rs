//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use comms::get_wd_path;
use daemonize::{Daemonize, Outcome, Parent};
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use std::{
    fs::{self, File},
    net::IpAddr,
    process::exit,
};
use telio::{device::Error as DeviceError, telio_model::mesh::Node};
use thiserror::Error as ThisError;
use tokio::{
    task::JoinError,
    time::{timeout, Duration},
};
use tracing::{debug, error};
use tracing_appender::rolling::InitError;

#[cfg(feature = "cgi")]
mod cgi;
mod command_listener;
mod comms;
mod config;
mod configure_interface;
mod core_api;
mod daemon;
mod logging;
mod nc;

use crate::{
    command_listener::CommandResponse,
    comms::DaemonSocket,
    config::{DeviceIdentity, TeliodDaemonConfig},
    core_api::Error as ApiError,
};

const TIMEOUT_SEC: u64 = 1;

#[derive(Parser, Debug, PartialEq)]
#[clap()]
#[derive(Serialize, Deserialize)]
enum ClientCmd {
    #[clap(about = "Retrieve the status report")]
    GetStatus,
    #[clap(about = "Query if daemon is running")]
    IsAlive,
    #[clap(about = "Stop daemon execution")]
    QuitDaemon,
}

#[derive(Parser, Debug)]
#[clap()]
enum Cmd {
    #[clap(about = "Runs the teliod event loop")]
    Daemon(DaemonOpts),
    #[clap(flatten)]
    Client(ClientCmd),
    #[cfg(feature = "cgi")]
    #[clap(about = "Receive and parse http requests")]
    Cgi,
}

#[derive(Parser, Debug)]
struct DaemonOpts {
    /// Path to the config file
    config_path: String,

    /// Run in the foreground instead of daemonizing
    #[clap(short = 'n', long = "no-detach")]
    no_detach: bool,
}

#[derive(Debug, ThisError)]
enum TeliodError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Invalid command received: {0}")]
    InvalidCommand(String),
    #[error("Invalid response received: {0}")]
    InvalidResponse(String),
    #[error("Client failed to receive response in {TIMEOUT_SEC}s")]
    ClientTimeoutError,
    #[error("Broken signal stream")]
    BrokenSignalStream,
    #[error(transparent)]
    TelioTaskError(#[from] JoinError),
    #[error(transparent)]
    ParsingError(#[from] SerdeJsonError),
    #[error("Command failed to execute: {0:?}")]
    CommandFailed(ClientCmd),
    #[error("Failed executing system command: {0:?}")]
    SystemCommandFailed(String),
    #[error("Daemon is not running")]
    DaemonIsNotRunning,
    #[error("Daemon is running")]
    DaemonIsRunning,
    #[error("NotificationCenter failure: {0}")]
    NotificationCenter(#[from] nc::Error),
    #[error(transparent)]
    CoreApiError(#[from] ApiError),
    #[error(transparent)]
    DeviceError(#[from] DeviceError),
    #[error("Invalid config option {0}: {1} (value '{2}')")]
    InvalidConfigOption(String, String, String),
    #[error(transparent)]
    LogAppenderError(#[from] InitError),
    #[error(transparent)]
    DaemonizeError(#[from] daemonize::Error),
}

/// Libtelio and meshnet status report
#[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
pub struct TelioStatusReport {
    /// State of telio runner
    pub telio_is_running: bool,
    /// Assigned mesnet IP address
    pub meshnet_ip: Option<IpAddr>,
    /// List of meshnet peers
    pub external_nodes: Vec<Node>,
}

#[tokio::main]
async fn main() -> Result<(), TeliodError> {
    match Cmd::parse() {
        Cmd::Daemon(opts) => {
            // Check if teliod working directory is available, otherwise create it
            let wd_path = get_wd_path()?;
            if !wd_path.exists() {
                fs::create_dir_all(&wd_path)?;
            }
            println!(
                "Starting teliod daemon with working directory {}",
                wd_path.to_string_lossy()
            );

            if DaemonSocket::get_ipc_socket_path()?.exists() {
                Err(TeliodError::DaemonIsRunning)
            } else {
                let file = fs::File::open(&opts.config_path)?;

                let mut config: TeliodDaemonConfig = serde_json::from_reader(file)?;

                if let Ok(token) = std::env::var("NORD_TOKEN") {
                    debug!("Overriding token from env");
                    if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
                        config.authentication_token = token;
                    } else {
                        error!("Token from env not valid")
                    }
                }

                // daemonize the process
                if !opts.no_detach {
                    println!("Daemonizing teliod process");
                    debug!("Daemonizing teliod process");
                    // redirect stdout and stderr
                    let stdout = File::create(wd_path.join("out.log"))?;
                    let stderr = File::create(wd_path.join("err.log"))?;
                    let pid_file = wd_path.join("teliod.pid");
                    let daemon = Daemonize::new()
                        .pid_file(pid_file)
                        .chown_pid_file(true)
                        .working_directory(wd_path)
                        .stdout(stdout)
                        .stderr(stderr);

                    match daemon.execute() {
                        Outcome::Parent(Ok(Parent {
                            first_child_exit_code,
                            ..
                        })) => {
                            eprintln!("parent Ok {}", first_child_exit_code);
                            exit(first_child_exit_code);
                        }
                        Outcome::Parent(Err(err)) => {
                            eprintln!("parent error {}", err);
                        }
                        Outcome::Child(Ok(child)) => {
                            eprintln!("Ok child {:?}", child.privileged_action_result);
                        }
                        Outcome::Child(Err(err)) => {
                            eprintln!("child error {}", err);
                        }
                    }
                }

                Box::pin(daemon::daemon_event_loop(config)).await
            }
        }
        Cmd::Client(cmd) => {
            let socket_path = DaemonSocket::get_ipc_socket_path()?;
            if socket_path.exists() {
                let response = timeout(
                    Duration::from_secs(TIMEOUT_SEC),
                    DaemonSocket::send_command(&socket_path, &serde_json::to_string(&cmd)?),
                )
                .await
                .map_err(|_| TeliodError::ClientTimeoutError)?;

                match CommandResponse::deserialize(&response?)? {
                    CommandResponse::Ok => {
                        println!("Command executed successfully");
                        Ok(())
                    }
                    CommandResponse::StatusReport(status) => {
                        println!("{}", serde_json::to_string_pretty(&status)?);
                        Ok(())
                    }
                    CommandResponse::Err(e) => {
                        println!("Command executed failed: {}", e);
                        Err(TeliodError::CommandFailed(cmd))
                    }
                }
            } else {
                Err(TeliodError::DaemonIsNotRunning)
            }
        }
        #[cfg(feature = "cgi")]
        Cmd::Cgi => {
            #[cfg(debug_assertions)]
            let _tracing_worker_guard = logging::setup_logging(
                cgi::constants::CGI_LOG,
                tracing::level_filters::LevelFilter::TRACE,
                7,
            )
            .await?;

            tokio::task::spawn_blocking(|| {
                rust_cgi::handle(cgi::handle_request);
            })
            .await?;
            Ok(())
        }
    }
}
