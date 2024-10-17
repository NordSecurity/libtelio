//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use crate::comms::DaemonSocket;
use crate::core_api::{
    get_meshmap as get_meshmap_from_server, load_identifier_from_api, register_machine,
    update_machine, Error as ApiError,
};
use clap::Parser;
use futures::stream::StreamExt;
use nix::libc::SIGTERM;
use reqwest::StatusCode;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::error::Error as SerdeJsonError;
use signal_hook_tokio::Signals;
use std::cmp::min;
use std::{
    fs::{self, File},
    str::FromStr,
    sync::Arc,
};
use telio::{
    crypto::{PublicKey, SecretKey},
    device::{Device, DeviceConfig, Error as DeviceError},
    telio_model::{config::Config as MeshMap, features::Features},
    telio_utils::select,
    telio_wg::AdapterType,
};
use thiserror::Error as ThisError;
use tokio::{sync::mpsc, task::JoinError, time::Duration};
use tracing::{debug, error, info, level_filters::LevelFilter, trace, warn};

mod comms;
mod core_api;

const MAX_RETRIES: u32 = 5;
const BASE_DELAY_MS: u64 = 500;
const MAX_BACKOFF_TIME: u64 = 5000;

#[derive(Serialize, Deserialize, Debug)]
struct TeliodDaemonConfig {
    #[serde(
        deserialize_with = "deserialize_log_level",
        serialize_with = "serialize_log_level"
    )]
    log_level: LevelFilter,
    log_file_path: String,
    hw_identifier: Option<String>,
    #[serde(deserialize_with = "deserialize_authentication_token")]
    authentication_token: String,
    private_key: Option<SecretKey>,
    machine_identifier: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct ClientConfig {
    hw_identifier: String,
    auth_token: String,
    private_key: SecretKey,
    public_key: PublicKey,
    machine_identifier: String,
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

fn deserialize_authentication_token<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let raw_string: String = de::Deserialize::deserialize(deserializer)?;
    let re = regex::Regex::new("[0-9a-f]{64}").map_err(de::Error::custom)?;
    if re.is_match(&raw_string) {
        Ok(raw_string)
    } else {
        Err(de::Error::custom("Incorrect authentication token"))
    }
}

#[derive(Parser, Debug)]
#[clap()]
#[derive(Serialize, Deserialize)]
enum ClientCmd {
    #[clap(
        about = "Forces daemon to add a log, added for testing to be, to be removed when the daemon will be more mature"
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
pub enum TelioTaskCmd {
    // Command to set the downloaded meshmap to telio instance
    UpdateMeshmap(MeshMap),
    // Triggers downloading meshmap from server
    GetMeshmap,
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
    #[error(transparent)]
    CoreApiError(#[from] ApiError),
    #[error(transparent)]
    DeviceError(#[from] DeviceError),
    #[error("Unable to update machine due to Error: {0}")]
    UpdateMachineError(StatusCode),
    #[error("Max retries exceeding to update machine")]
    UpdateMachineTimeout,
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

async fn init_api(
    config: &mut TeliodDaemonConfig,
    config_path: String,
) -> Result<ClientConfig, TeliodError> {
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
                client_config.machine_identifier = match load_identifier_from_api(
                    &config.authentication_token,
                    client_config.public_key,
                )
                .await
                {
                    Ok(id) => id,
                    Err(e) => {
                        info!("Unable to load identifier due to {e}");
                        // Retry machine update after registering. To make sure everything was successful
                        // If registering fails. Close the daemon
                        register_machine(
                            &client_config.hw_identifier,
                            client_config.public_key,
                            &client_config.auth_token,
                        )
                        .await?
                    }
                }
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
                    return Err(TeliodError::UpdateMachineTimeout);
                }
            }
        }
    }

    config.private_key = Some(client_config.private_key.clone());
    config.hw_identifier = Some(client_config.hw_identifier.clone());
    config.machine_identifier = Some(client_config.machine_identifier.clone());

    let mut file = File::create(config_path)?;
    serde_json::to_writer(&mut file, &config)?;
    Ok(client_config)
}

// From async context Telio needs to be run in separate task
fn telio_task(
    client_config: ClientConfig,
    mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    tx_channel: mpsc::Sender<TelioTaskCmd>,
) -> Result<(), TeliodError> {
    debug!("Initializing telio device");
    let mut telio = Device::new(
        Features::default(),
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    )?;

    let config_ptr = std::sync::Arc::new(client_config);
    // TODO: This is temporary to be removed later on when we have proper integration
    // tests with core API. This is to not look for tokens in a test environment
    // right now as the values are dummy and program will not run as it expects
    // real tokens.
    if !config_ptr.auth_token.eq("") {
        start_telio(&mut telio, config_ptr.private_key)?;
        get_meshmap(config_ptr.clone(), tx_channel.clone());

        while let Some(cmd) = rx_channel.blocking_recv() {
            info!("Got command {:?}", cmd);
            match cmd {
                TelioTaskCmd::GetMeshmap => get_meshmap(config_ptr.clone(), tx_channel.clone()),
                TelioTaskCmd::UpdateMeshmap(map) => {
                    if let Err(e) = telio.set_config(&Some(map)) {
                        error!("Unable to set meshmap due to {e}");
                    }
                }
            }
        }
    }
    Ok(())
}

#[allow(mpsc_blocking_send)]
fn get_meshmap(client_config: Arc<ClientConfig>, tx: mpsc::Sender<TelioTaskCmd>) {
    let config_clone = client_config.clone();
    tokio::spawn(async move {
        let result = get_meshmap_from_server(config_clone).await;
        match result {
            Ok(map) => {
                let meshmap: MeshMap = match serde_json::from_str(&map) {
                    Ok(map) => map,
                    Err(e) => {
                        error!("Unable to parse meshmap due to {e}");
                        return;
                    }
                };
                trace!("Meshmap {:#?}", meshmap);
                if let Err(e) = tx.send(TelioTaskCmd::UpdateMeshmap(meshmap)).await {
                    error!("Unable to send meshmap due to {e}");
                }
            }
            Err(e) => error!("Getting meshmap failed due to {e}"),
        }
    });
}

fn start_telio(telio: &mut Device, private_key: SecretKey) -> Result<(), DeviceError> {
    if !telio.is_running() {
        let device_config = DeviceConfig {
            private_key,
            name: Some("utun10".to_owned()),
            adapter: AdapterType::BoringTun,
            ..Default::default()
        };

        telio.start(&device_config)?;

        info!(
            "started telio with {:?}:{}...",
            AdapterType::BoringTun,
            private_key
        );
    }
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
            "".to_string()
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
        tracing_appender::non_blocking(fs::File::create(&(config.log_file_path))?);
    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let cmd_listener = CommandListener { socket };

    // Tx is unused here, but this channel can be used to communicate with the
    // telio task
    let (tx, rx) = mpsc::channel(10);

    // TODO: This if condition and ::default call is temporary to be removed later
    // on when we have proper integration tests with core API.
    // This is to not look for tokens in a test environment right now as the values
    // are dummy and program will not run as it expects real tokens.
    let mut client_config = ClientConfig::default();
    if !config
        .authentication_token
        .eq("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    {
        client_config = init_api(&mut config, config_path).await?;
    }
    let tx_clone = tx.clone();
    let telio_task_handle =
        tokio::task::spawn_blocking(move || telio_task(client_config, rx, tx_clone));
    let mut signals = Signals::new([SIGTERM])?;

    info!("Entering event loop");

    let result = loop {
        select! {
            maybe_cmd = cmd_listener.get_command() => {
                match maybe_cmd {
                    Ok(ClientCmd::HelloWorld{name}) => {
                        info!("Hello {}", name);
                    }
                    Ok(ClientCmd::GetMeshmap) => {
                        if let Err(e) = tx.try_send(TelioTaskCmd::GetMeshmap) {
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
                    Some(SIGTERM) => {
                        info!("Received SIGTERM signal, exiting");
                        fs::remove_file("/var/run/teliod.sock")?;
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
    let join_result = telio_task_handle.await?;

    if result.is_err() {
        result
    } else {
        join_result.map_err(|err| err.into())
    }
}
