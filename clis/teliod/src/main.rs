//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use config::TeliodDaemonConfig;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use signal_hook_tokio::Signals;
use std::{
    fs::{self, File},
    sync::Arc,
};
use thiserror::Error as ThisError;
use tokio::task::JoinError;
use tracing::{debug, error, info, warn};

use telio::{device::Device, telio_model::features::Features, telio_utils::select};

mod comms;
mod config;
mod nc;

use crate::{comms::DaemonSocket, nc::NotificationCenter};

#[derive(Parser, Debug)]
#[clap()]
#[derive(Serialize, Deserialize)]
enum ClientCmd {
    #[clap(
        about = "Forces daemon to add a log, added for testing, to be removed when the daemon will be more mature"
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
}

#[tokio::main]
async fn main() -> Result<(), TeliodError> {
    match Cmd::parse() {
        Cmd::Daemon { config_path } => {
            if DaemonSocket::get_ipc_socket_path()?.exists() {
                Err(TeliodError::DaemonIsRunning)
            } else {
                let file = File::open(config_path)?;
                let config: TeliodDaemonConfig = serde_json::from_reader(file)?;
                daemon_event_loop(config).await
            }
        }
        Cmd::Client(cmd) => {
            let socket_path = DaemonSocket::get_ipc_socket_path()?;
            if socket_path.exists() {
                let response =
                    DaemonSocket::send_command(&socket_path, &serde_json::to_string(&cmd)?).await?;

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
        tracing_appender::non_blocking(fs::File::create(&config.log_file_path)?);
    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    debug!("started with config: {config:?}");

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let cmd_listener = CommandListener { socket };

    let nc = NotificationCenter::new(
        &config,
        vec![Arc::new(|am| {
            println!("Example callback registered at the start: {am:?}")
        })],
    )
    .await?;

    nc.add_callback(Arc::new(|am| {
        println!("Example callback registered after nc start: {am:?}")
    }))
    .await;

    let telio_task_handle = tokio::task::spawn_blocking(telio_task);

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

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
                    Some(s @ SIGHUP | s @ SIGTERM | s @ SIGINT | s @ SIGQUIT) => {
                        info!("Received signal {:?}, exiting", Signal::try_from(s));
                        break Ok(());
                    }
                    Some(s) => {
                        info!("Received unexpected signal {s:?}, ignoring");
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
