//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use nix::libc::SIGTERM;
use signal_hook_tokio::Signals;
use std::{
    fs::{self, File},
    str::FromStr,
};
use thiserror::Error as ThisError;
use tokio::task::JoinError;
use tracing::{error, info, level_filters::LevelFilter, warn};

mod comms;
mod daemon;

use crate::{comms::DaemonSocket, daemon::TeliodDaemon};

use telio::{device::Device, telio_model::features::Features, telio_utils::select};

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::error::Error as SerdeJsonError;

use futures::stream::StreamExt;

#[derive(Deserialize)]
struct TeliodDaemonConfig {
    #[serde(deserialize_with = "deserialize_log_level")]
    log_level: LevelFilter,
    log_file_path: String,
}

fn deserialize_log_level<'de, D>(deserializer: D) -> Result<LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).and_then(|s: String| {
        LevelFilter::from_str(&s).map_err(|_| {
            de::Error::unknown_variant(&s, &["error", "warn", "info", "debug", "trace", "off"])
        })
    })
}

#[derive(Parser, Debug)]
#[clap()]
#[derive(Serialize, Deserialize)]
enum ClientCmd {
    #[clap(
        about = "Forces daemon to add a log, added for testing to be, to be removed when the daemon will be more mature"
    )]
    HelloWorld { name: String },
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
    #[error("Broken signal stream")]
    BrokenSignalStream,
    #[error(transparent)]
    TelioTaskError(#[from] JoinError),
    #[error("Cannot find any feasible runtime data directory")]
    NoRuntimeDataDirectory,
    #[error(transparent)]
    ParsingError(#[from] SerdeJsonError),
    #[error("Command failed to execute: {0:?}")]
    CommandFailed(ClientCmd),
    #[error("Daemon is not running")]
    DaemonIsNotRunning,
    #[error("Daemon is running")]
    DaemonIsRunning,
}

#[tokio::main]
async fn main() -> Result<(), TeliodError> {
    match Cmd::parse() {
        Cmd::Daemon { config_path } => {
            if TeliodDaemon::is_running()? {
                Err(TeliodError::DaemonIsRunning)
            } else {
                let file = File::open(config_path)?;
                let config: TeliodDaemonConfig = serde_json::from_reader(file)?;
                TeliodDaemon::init()?;
                daemon_event_loop(config).await
            }
        }
        Cmd::Client(cmd) => {
            if TeliodDaemon::is_running()? {
                let response = DaemonSocket::send_command(
                    &TeliodDaemon::get_ipc_socket_path()?,
                    &serde_json::to_string(&cmd)?,
                )
                .await?;

                if response.as_str() == "OK" {
                    println!("Command executed successfully");
                    Ok(())
                } else {
                    Err(TeliodError::CommandFailed(cmd))
                }
            } else {
                Err(TeliodError::DaemonIsNotRunning)
            }
        }
    }
}

struct CommandListener {
    socket: DaemonSocket,
}

impl CommandListener {
    async fn get_command(&self) -> Result<ClientCmd, TeliodError> {
        let mut connection = self.socket.accept().await?;
        let command_str = connection.read_command().await?;

        if let Ok(cmd) = serde_json::from_str::<ClientCmd>(&command_str) {
            connection.respond("OK".to_owned()).await?;
            Ok(cmd)
        } else {
            connection.respond("ERR".to_owned()).await?;
            Err(TeliodError::InvalidCommand(command_str))
        }
    }
}

// From async context Telio needs to be run in separate task
fn telio_task() {
    let _telio = Device::new(
        Features::default(),
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    );
}

async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<(), TeliodError> {
    let (non_blocking_writer, _tracing_worker_guard) =
        tracing_appender::non_blocking(fs::File::create(config.log_file_path)?);
    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let socket = DaemonSocket::new(
        &TeliodDaemon::get_ipc_socket_path().map_err(|_| TeliodError::NoRuntimeDataDirectory)?,
    )?;
    let cmd_listener = CommandListener { socket };

    let telio_task_handle = tokio::task::spawn_blocking(telio_task);

    let mut signals = Signals::new([SIGTERM])?;

    info!("Entering event loop");

    let result = loop {
        select! {
            maybe_cmd = cmd_listener.get_command() => {
                match maybe_cmd {
                    Ok(ClientCmd::HelloWorld{name}) => {
                        info!("Hello {}", name);
                    }
                    Err(TeliodError::InvalidCommand(cmd)) => {
                        warn!("Received invalid command from client: {}", cmd);
                    }
                    Err(error) => {
                        break Err(error);
                    }
                }
            },
            signal = signals.next() => {
                match signal {
                    Some(SIGTERM) => {
                        info!("Received SIGTERM signal, exiting");
                        break Ok(());
                    }
                    Some(_) => {
                        info!("Received unexpected signal, ignoring");
                    }
                    None => {
                        break Err(TeliodError::BrokenSignalStream);
                    }
                }
            }
        }
    };

    // Wait until Telio task ends
    // TODO: When it will be doing something some channel with commands etc. might be needed
    let join_result = telio_task_handle.await;

    if result.is_err() {
        result
    } else {
        join_result.map_err(|err| err.into())
    }
}
