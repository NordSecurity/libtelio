//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use std::{fs::File, net::IpAddr};
use telio::{device::Error as DeviceError, telio_model::mesh::Node};
use thiserror::Error as ThisError;
use tokio::{
    task::JoinError,
    time::{timeout, Duration},
};
use tracing::{debug, error};

mod command_listener;
mod comms;
mod config;
mod configure_interface;
mod core_api;
mod daemon;
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
}

#[derive(Parser, Debug)]
#[clap()]
enum Cmd {
    #[clap(about = "Runs the teliod event loop")]
    Daemon { config_path: String },
    #[clap(flatten)]
    Client(ClientCmd),
}

#[derive(Debug, ThisError)]
enum TeliodError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Invalid command received: {0}")]
    InvalidCommand(String),
    #[error("Invalid response received: {0}")]
    InvalidResponse(String),
    #[error("Client failed to receive response in {TIMEOUT_SEC}")]
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
}

/// Libtelio and meshnet status report
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
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
        Cmd::Daemon { config_path } => {
            if DaemonSocket::get_ipc_socket_path()?.exists() {
                Err(TeliodError::DaemonIsRunning)
            } else {
                let file = File::open(&config_path)?;
                let mut config: TeliodDaemonConfig = serde_json::from_reader(file)?;
                let token = std::env::var("NORD_TOKEN").ok();
                if let Some(t) = token {
                    debug!("Overriding token from env");
                    config.authentication_token = t;
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
    }
}
