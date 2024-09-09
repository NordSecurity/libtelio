//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use anyhow::Result;
use clap::Parser;
use std::{
    fs::{self, File},
    str::FromStr,
    time::Duration,
};
use tracing::{error, info, level_filters::LevelFilter, warn};

use daemon_common::{
    comms::DaemonSocket,
    daemon::{Daemon, ProcessType},
};

use telio::{device::Device, telio_model::features::Features};

use serde::{de, Deserialize, Deserializer, Serialize};

struct TeliodDaemon;

impl Daemon for TeliodDaemon {
    const NAME: &'static str = "teliod";
}

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

#[derive(Parser)]
#[clap()]
#[derive(Serialize, Deserialize)]
enum Cmd {
    #[clap(about = "Starts the daemon")]
    Start { config_path: String },
    #[clap(
        about = "Forces daemon to add a log, added for testing to be, to be removed when the daemon will be more mature"
    )]
    HelloWorld { name: String },
    #[clap(about = "Same as 'status' but in json string")]
    Stop,
}

fn main() -> Result<()> {
    match Cmd::parse() {
        Cmd::Start { config_path } => {
            if TeliodDaemon::is_running()? {
                eprintln!("Teliod is already running, stop it by calling `teliod stop`");
            } else {
                let file = File::open(config_path)?;
                let config: TeliodDaemonConfig = serde_json::from_reader(file)?;
                start_daemon(config)?;
            }
        }
        cmd => {
            if TeliodDaemon::is_running()? {
                let response = DaemonSocket::send_command(
                    &TeliodDaemon::get_ipc_socket_path()?,
                    &serde_json::to_string(&cmd)?,
                )?;

                if response.as_str() == "OK" {
                    println!("Command executed successfully");
                } else {
                    eprintln!("Command failed");
                }
            } else {
                eprintln!("Teliod daemon is not running");
            }
        }
    };

    Ok(())
}

/// Starts the Teliod daemon which will run actual Telio.
///
/// # Arguments
///
/// * `config` - Daemon config.
fn start_daemon(config: TeliodDaemonConfig) -> Result<()> {
    println!("Starting Teliod daemon...");
    match TeliodDaemon::start() {
        Ok(ProcessType::Api) => {
            // Verifying that the server had been started, but we have no way of synchronizing
            // the verification with the daemon, so using retries instead.
            // The delay values had been chose experimentally to get a fast, but efficient start of the daemon.
            // This delay mostly depends on how quickly Telio initializes itself from inside the daemon.
            DaemonSocket::send_command_with_retries(
                &TeliodDaemon::get_ipc_socket_path()?,
                "hello_world",
                &[
                    Duration::from_millis(400),
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                    Duration::from_millis(500),
                ],
            )?;

            println!("Teliod daemon started");

            Ok(())
        }
        Ok(ProcessType::Daemon) => daemon_event_loop(config),
        Err(e) => Err(e),
    }
}

fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<()> {
    let (non_blocking_writer, _tracing_worker_guard) =
        tracing_appender::non_blocking(fs::File::create(config.log_file_path)?);
    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let socket = DaemonSocket::new(&TeliodDaemon::get_ipc_socket_path()?)?;

    let _telio = Device::new(
        Features::default(),
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    );

    info!("Entered event loop");

    loop {
        let mut connection = match socket.accept() {
            Ok(conn) => conn,
            Err(err) => {
                error!("Failed to accept connection: {:?} - stopping daemon", err);
                break;
            }
        };

        let command_str = connection.read_command()?;

        if let Ok(command) = serde_json::from_str::<Cmd>(&command_str) {
            match command {
                Cmd::Start { .. } => {
                    warn!("Start command should never be passed to the daemon");
                    connection.respond("ERR".to_owned())?;
                }
                Cmd::HelloWorld { name } => {
                    info!("Hello {}!", name);
                    connection.respond("OK".to_owned())?;
                }
                Cmd::Stop => {
                    info!("Stopping daemon");
                    connection.respond("OK".to_owned())?;
                    break;
                }
            };
        } else {
            warn!("Unknown command");
            connection.respond("ERR".to_owned())?;
        };
    }

    Ok(())
}
