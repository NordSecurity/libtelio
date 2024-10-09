//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use config::TeliodDaemonConfig;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use reqwest::StatusCode;
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

use std::cmp::min;
use telio::crypto::{PublicKey, SecretKey};
use telio::telio_model::config::Config as MeshMap;
use telio::{device::Device, telio_model::features::Features, telio_utils::select};
use telio::{
    device::{Device, Error as DeviceError},
    telio_model::features::Features,
    telio_utils::select,
};

mod comms;
mod config;
mod core_api;
mod nc;

use crate::{comms::DaemonSocket, config::ClientConfig, nc::NotificationCenter};

const MAX_RETRIES: u32 = 5;
const BASE_DELAY_MS: u64 = 500;
const MAX_BACKOFF_TIME: u64 = 5000;

fn serialize_log_level<S>(level: &LevelFilter, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let level_str = match level {
        &LevelFilter::ERROR => "error",
        &LevelFilter::WARN => "warn",
        &LevelFilter::INFO => "info",
        &LevelFilter::DEBUG => "debug",
        &LevelFilter::TRACE => "trace",
        &LevelFilter::OFF => "off",
    };

    serializer.serialize_str(level_str)
}

#[derive(Parser, Debug)]
#[clap()]
#[derive(Serialize, Deserialize)]
enum ClientCmd {
    #[clap(
        about = "Forces daemon to add a log, added for testing, to be removed when the daemon will be more mature"
    )]
    HelloWorld { name: String },
    #[clap(about = "Fetches and update meshmap")]
    GetMeshmap,
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
enum TelioTaskCmd {
    UpdateMeshmap,
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
    #[error("Token not fully loaded")]
    TokenError,
    #[error(transparent)]
    CoreApiError(#[from] ApiError),
    #[error(transparent)]
    DeviceError(#[from] DeviceError),
    #[error("Unable to update machine due to Error: {0}")]
    UpdateMachineError(StatusCode),
    #[error("Max retries exceeding to update machine")]
    UpdateMachineTimeoutError,
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
                let config: TeliodDaemonConfig = serde_json::from_reader(file)?;
                daemon_event_loop(config, config_path).await
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

async fn init_api(config: &mut TeliodDaemonConfig, config_path: String) -> Result<(), TeliodError> {
    let mut client_config = ClientConfig::new(config).await?;

    let mut retries = 0;
    loop {
        let status = update_machine(&client_config).await?;
        match status {
            StatusCode::OK => break,
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST => {
                // exit daemon
                return Err(TeliodError::UpdateMachineError(status));
            }
            StatusCode::NOT_FOUND => {
                // Retry machine update after registering. To make sure everything was successful
                // If registering fails. Close the daemon
                client_config.machine_identifier = register_machine(
                    &client_config.hw_identifier,
                    client_config.public_key,
                    &client_config.auth_token,
                )
                .await?;
            }
            _ => {
                // Retry with exp back-off
                if retries < MAX_RETRIES {
                    let backoff_time = BASE_DELAY_MS * 2_u64.pow(retries);
                    let sleep_time = min(backoff_time, MAX_BACKOFF_TIME);
                    debug!("Retrying after {} ms...", sleep_time);
                    tokio::time::sleep(Duration::from_millis(sleep_time)).await;
                    retries += 1;
                } else {
                    // If max retries exceeded, exit daemon
                    return Err(TeliodError::UpdateMachineTimeoutError);
                    // panic!("Max retries reached. Exiting.");
                }
            }
        }
    }

    config.private_key = Some(client_config.private_key.clone());
    config.hw_identifier = Some(client_config.hw_identifier.clone());
    config.machine_identifier = Some(client_config.machine_identifier.clone());

    let mut file = File::create(config_path)?;
    serde_json::to_writer(&mut file, &config)?;
    Ok(())
}

// From async context Telio needs to be run in separate task
fn telio_task(
    client_config: ClientConfig,
    mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
) -> Result<(), TeliodError> {
    debug!("Initializing telio device");
    let telio = Device::new(
        Features::default(),
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    )?;

    // TODO: This is temporary to be removed later on when we have proper integration
    // tests with core API. This is to not look for tokens in a test environment
    // right now as the values are dummy and program will not run as it expects
    // real tokens.
    if !client_config.auth_token.eq("") {
        if let Err(e) = update_meshmap(&client_config, &telio) {
            error!("Unable to set meshmap due to {e}");
        }

        while let Some(cmd) = rx_channel.blocking_recv() {
            info!("Got command {:?}", cmd);
            match cmd {
                TelioTaskCmd::UpdateMeshmap => {
                    if let Err(e) = update_meshmap(&client_config, &telio) {
                        error!("Unable to set meshmap due to {e}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn update_meshmap(client_config: &ClientConfig, telio: &Device) -> Result<(), TeliodError> {
    let meshmap: MeshMap = serde_json::from_str(&get_meshmap(client_config)?)?;
    trace!("Meshmap {:#?}", meshmap);
    telio.set_config(&Some(meshmap))?;
    Ok(())
}

impl ClientConfig {
    async fn new(config: &mut TeliodDaemonConfig) -> Result<ClientConfig, TeliodError> {
        info!("Fetching tokens");

        // Copy or generate Secret/public key pair
        let private_key = if let Some(sk) = config.private_key {
            sk
        } else {
            debug!("Generating secret key!");
            SecretKey::gen()
        };
        let public_key = private_key.public();

        // Copy or generate hw_identifier
        let hw_identifier = if let Some(hw_id) = &config.hw_identifier {
            hw_id.to_string()
        } else {
            debug!("Generating hw identifier");
            format!("{}.{}", public_key, "openWRT")
        };

        // Copy or generate machine_identifier
        let machine_identifier = if let Some(machine_id) = &config.machine_identifier {
            machine_id.to_string()
        } else {
            if let Ok(id) = load_identifier_from_api(&config.authentication_token, public_key).await
            {
                id
            } else {
                debug!("Machine not yet registered");
                // If registering fails. Close the daemon
                register_machine(&hw_identifier, public_key, &config.authentication_token).await?
            }
        };

        Ok(ClientConfig {
            hw_identifier,
            auth_token: config.authentication_token.clone(),
            private_key,
            public_key,
            machine_identifier,
        })
    }
}

async fn daemon_event_loop(
    mut config: TeliodDaemonConfig,
    config_path: String,
) -> Result<(), TeliodError> {
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

    // Tx is unused here, but this channel can be used to communicate with the
    // telio task
    let (tx, rx) = mpsc::channel(10);

    // TODO: This is temporary to be removed later on when we have proper integration
    // tests with core API. This is to not look for tokens in a test environment
    // right now as the values are dummy and program will not run as it expects
    // real tokens.
    let mut client_config = ClientConfig::default();
    if !config.authentication_token.eq("abcd1234") {
        init_api(&mut config, config_path).await?;

        client_config = ClientConfig {
            hw_identifier: config.hw_identifier.ok_or(TeliodError::TokenError)?,
            auth_token: config.authentication_token,
            machine_identifier: config.machine_identifier.ok_or(TeliodError::TokenError)?,
            private_key: config.private_key.ok_or(TeliodError::TokenError)?,
            public_key: config.private_key.ok_or(TeliodError::TokenError)?.public(),
        };
    }
    let telio_task_handle = tokio::task::spawn_blocking(|| telio_task(client_config, rx));
    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

    info!("Entering event loop");

    let result = loop {
        select! {
            maybe_cmd = cmd_listener.get_command() => {
                match maybe_cmd {
                    Ok(ClientCmd::HelloWorld{name}) => {
                        info!("Hello {}", name);
                    }
                    Ok(ClientCmd::GetMeshmap) => {
                        if let Err(e) = tx.try_send(TelioTaskCmd::UpdateMeshmap) {
                            error!("Channel closed or telio not yet started. {e}");
                        };
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
    let join_result = telio_task_handle.await?;

    if result.is_err() {
        result
    } else {
        join_result.map_err(|err| err.into())
    }
}
