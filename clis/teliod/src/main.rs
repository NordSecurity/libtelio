//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use config::TeliodDaemonConfig;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use signal_hook_tokio::Signals;
use std::time::Duration;
use std::{
    fs::{self, File},
    sync::Arc,
};
use telio::{
    crypto::SecretKey,
    device::{Device, DeviceConfig, Error as DeviceError},
    telio_model::{config::Config as MeshMap, features::Features},
    telio_utils::select,
    telio_wg::AdapterType,
};
use thiserror::Error as ThisError;
use tokio::{sync::mpsc, task::JoinError};
use tracing::{debug, error, info, trace, warn};

mod comms;
mod config;
mod core_api;
mod nc;

use crate::core_api::{get_meshmap as get_meshmap_from_server, init_with_api, Error as ApiError};
use crate::{comms::DaemonSocket, config::DeviceIdentity, nc::NotificationCenter};

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

#[derive(Debug)]
pub enum TelioTaskCmd {
    // Command to set the downloaded meshmap to telio instance
    UpdateMeshmap(MeshMap),
    // Break the recieve loop to quit the daemon and exit gracefully
    Quit,
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
    #[error(transparent)]
    CoreApiError(#[from] ApiError),
    #[error(transparent)]
    DeviceError(#[from] DeviceError),
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
fn telio_task(
    node_identity: Arc<DeviceIdentity>,
    auth_token: Arc<String>,
    mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    tx_channel: mpsc::Sender<TelioTaskCmd>,
    interface_name: &str,
) -> Result<(), TeliodError> {
    debug!("Initializing telio device");
    let mut telio = Device::new(
        Features::default(),
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    )?;

    // TODO: This is temporary to be removed later on when we have proper integration
    // tests with core API. This is to not look for tokens in a test environment
    // right now as the values are dummy and program will not run as it expects
    // real tokens.
    if !auth_token.as_str().eq("") {
        start_telio(
            &mut telio,
            node_identity.private_key.clone(),
            &interface_name,
        )?;
        task_retrieve_meshmap(node_identity, auth_token, tx_channel);

        while let Some(cmd) = rx_channel.blocking_recv() {
            info!("Got command {:?}", cmd);
            match cmd {
                TelioTaskCmd::UpdateMeshmap(map) => {
                    if let Err(e) = telio.set_config(&Some(map)) {
                        error!("Unable to set meshmap due to {e}");
                    }
                }
                TelioTaskCmd::Quit => {
                    telio.stop();
                    break;
                }
            }
        }
    }
    Ok(())
}

fn task_retrieve_meshmap(
    device_identity: Arc<DeviceIdentity>,
    auth_token: Arc<String>,
    tx: mpsc::Sender<TelioTaskCmd>,
) {
    tokio::spawn(async move {
        let result = get_meshmap_from_server(device_identity, auth_token).await;
        match result {
            Ok(meshmap) => {
                trace!("Meshmap {:#?}", meshmap);
                #[allow(mpsc_blocking_send)]
                if let Err(e) = tx.send(TelioTaskCmd::UpdateMeshmap(meshmap)).await {
                    error!("Unable to send meshmap due to {e}");
                }
            }
            Err(e) => error!("Getting meshmap failed due to {e}"),
        }
    });
}

fn start_telio(
    telio: &mut Device,
    private_key: SecretKey,
    interface_name: &str,
) -> Result<(), DeviceError> {
    telio.start(&DeviceConfig {
        private_key,
        name: Some(interface_name.to_owned()),
        adapter: AdapterType::BoringTun,
        ..Default::default()
    })?;

    debug!("started telio with {:?}...", AdapterType::BoringTun,);
    Ok(())
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

    let nc = NotificationCenter::new(&config).await?;

    // Tx is unused here, but this channel can be used to communicate with the
    // telio task
    let (tx, rx) = mpsc::channel(10);

    // TODO: This if condition and ::default call is temporary to be removed later
    // on when we have proper integration tests with core API.
    // This is to not look for tokens in a test environment right now as the values
    // are dummy and program will not run as it expects real tokens.
    let mut identity = DeviceIdentity::default();
    if !config
        .authentication_token
        .eq("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    {
        identity = init_with_api(&config.authentication_token, &config.interface_name).await?;
    }
    let tx_clone = tx.clone();

    let token_ptr = Arc::new(config.authentication_token);
    let token_clone = token_ptr.clone();

    let identity_ptr = Arc::new(identity);
    let identity_clone = identity_ptr.clone();

    let telio_task_handle = tokio::task::spawn_blocking(move || {
        telio_task(
            identity_clone,
            token_clone,
            rx,
            tx_clone,
            &config.interface_name,
        )
    });

    let tx_clone = tx.clone();
    nc.add_callback(Arc::new(move |_am| {
        task_retrieve_meshmap(identity_ptr.clone(), token_ptr.clone(), tx_clone.clone());
    }))
    .await;

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
                        if let Err(e) = tx.send_timeout(TelioTaskCmd::Quit, Duration::from_secs(2)).await {
                            error!("Unable to send QUIT due to {e}");
                        };
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
