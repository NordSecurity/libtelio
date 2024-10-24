//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use command_listener::CommandResponse;
use config::TeliodDaemonConfig;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use std::fs::File;
use telio::{
    device::Error as DeviceError,
    telio_model::{config::Config as MeshMap, mesh::Node},
};
use thiserror::Error as ThisError;
use tokio::{
    task::JoinError,
    time::{timeout, Duration},
};
use tracing::{debug, error};

mod command_listener;
mod comms;
mod config;
mod core_api;
mod daemon;
mod nc;

use crate::core_api::Error as ApiError;
use crate::{comms::DaemonSocket, config::DeviceIdentity};

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

#[derive(Debug)]
pub enum TelioTaskCmd {
    // Command to set the downloaded meshmap to telio instance
    UpdateMeshmap(MeshMap),
    // Get telio status
    GetStatus,
    // Break the recieve loop to quit the daemon and exit gracefully
    Quit,
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
    pub is_running: bool,
    /// List of meshnet peers
    pub nodes: Vec<Node>,
}

#[tokio::main]
#[allow(large_futures)]
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
                daemon::daemon_event_loop(config).await
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
                        println!("{:#?}", status);
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
