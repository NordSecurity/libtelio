//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use signal_hook_tokio::Signals;
use smart_default::SmartDefault;
use std::{
    fs::{self, File},
    num::NonZeroU64,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use thiserror::Error as ThisError;
use tokio::task::JoinError;
use tracing::{debug, error, info, level_filters::LevelFilter, warn};
use uuid::Uuid;

mod comms;
mod nc;

use crate::{comms::DaemonSocket, nc::NotificationCenter};

use telio::{device::Device, telio_model::features::Features, telio_utils::select};

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::error::Error as SerdeJsonError;

use futures::stream::StreamExt;

#[derive(Clone, Copy, Debug, SmartDefault)]
#[repr(transparent)]
struct Percentage(u8);

impl std::ops::Mul<std::time::Duration> for Percentage {
    type Output = std::time::Duration;

    fn mul(self, rhs: std::time::Duration) -> Self::Output {
        (self.0 as u32 * rhs) / 100
    }
}

#[derive(Clone, Debug, Deserialize, SmartDefault)]
struct MqttConfig {
    /// Starting backoff time for mqtt retry, has to be at least one. (in seconds)
    #[default(backoff_initial_default())]
    #[serde(default = "backoff_initial_default")]
    backoff_initial: NonZeroU64,
    /// Maximum backoff time for the mqtt retry. Has to be greater than the initial value. (in seconds)
    #[default(backoff_maximal_default())]
    #[serde(default = "backoff_maximal_default")]
    backoff_maximal: NonZeroU64,

    /// Percentage of the expiry period after which new mqtt token will be requested
    #[default(reconnect_after_expiry_default())]
    #[serde(deserialize_with = "deserialize_percent")]
    #[serde(default = "reconnect_after_expiry_default")]
    reconnect_after_expiry: Percentage,

    /// Path to a mqtt pem certificate to be used when connecting to Notification Center
    #[serde(default)]
    certificate_file_path: Option<PathBuf>,
}

fn backoff_initial_default() -> NonZeroU64 {
    #[allow(unwrap_check)]
    NonZeroU64::new(1).unwrap()
}

fn backoff_maximal_default() -> NonZeroU64 {
    #[allow(unwrap_check)]
    NonZeroU64::new(300).unwrap()
}

fn reconnect_after_expiry_default() -> Percentage {
    Percentage(90)
}

#[derive(Deserialize, Debug)]
struct TeliodDaemonConfig {
    #[serde(deserialize_with = "deserialize_log_level")]
    log_level: LevelFilter,
    log_file_path: String,

    app_user_uid: Uuid,

    #[serde(deserialize_with = "deserialize_authentication_token")]
    authentication_token: String,

    /// Path to a http pem certificate to be used when connecting to CoreApi
    http_certificate_file_path: Option<PathBuf>,

    #[serde(default)]
    mqtt: MqttConfig,
}

fn deserialize_percent<'de, D>(deserializer: D) -> Result<Percentage, D::Error>
where
    D: Deserializer<'de>,
{
    let value: u8 = de::Deserialize::deserialize(deserializer)?;
    if value > 100 {
        return Err(de::Error::custom(
            "Percentage value can only be in range from 0 to 100 inclusive",
        ));
    }
    Ok(Percentage(value))
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
                        info!("Received signal {s}, exiting");
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn percentage_times_duration() {
        let input = Duration::from_secs(86400);
        let expected = Duration::from_secs(77760);
        let percentage = Percentage(90);
        assert_eq!(expected, percentage * input);
    }
}
