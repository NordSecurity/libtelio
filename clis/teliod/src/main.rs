//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use anyhow::{bail, Result};
use clap::Parser;
use nix::libc::SIGTERM;
use signal_hook_tokio::Signals;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::id,
    str::FromStr,
};
use tracing::{error, info, level_filters::LevelFilter};

mod comms;
mod daemon;

use crate::{comms::DaemonSocket, daemon::Daemon};

use telio::{device::Device, telio_model::features::Features, telio_utils::select};

use serde::{de, Deserialize, Deserializer, Serialize};

use futures::stream::StreamExt;

struct TeliodDaemon;

impl Daemon for TeliodDaemon {
    const NAME: &'static str = "teliod";

    fn get_wd_path() -> Result<PathBuf> {
        if Path::new("/run").exists() {
            Ok(PathBuf::from("/run/"))
        } else {
            Ok(PathBuf::from("/var/run/"))
        }
    }
}

impl TeliodDaemon {
    /// Inits the daemon on the same process
    fn init() -> Result<()> {
        // Create pid file
        let pid = id();
        let mut pid_file = File::create(Self::get_pid_path()?)?;
        pid_file.write_fmt(format_args!("{}", pid))?;
        Ok(())
    }
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
    #[clap(about = "Runs the teliod event loop")]
    Daemon { config_path: String },
    #[clap(
        about = "Forces daemon to add a log, added for testing to be, to be removed when the daemon will be more mature"
    )]
    HelloWorld { name: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cmd::parse() {
        Cmd::Daemon { config_path } => {
            if TeliodDaemon::is_running()? {
                eprintln!("Teliod is already running");
            } else {
                let file = File::open(config_path)?;
                let config: TeliodDaemonConfig = serde_json::from_reader(file)?;
                TeliodDaemon::init()?;
                if daemon_event_loop(config).await.is_ok() {
                    eprintln!("Ended event loop: ok");
                } else {
                    eprintln!("Ended event loop: not ok");
                }
                eprintln!("Exited daemon event loop");
            }
        }
        cmd => {
            if TeliodDaemon::is_running()? {
                let response = DaemonSocket::send_command(
                    &TeliodDaemon::get_ipc_socket_path()?,
                    &serde_json::to_string(&cmd)?,
                )
                .await?;

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

enum EventLoopCommand {
    HelloWorld(String),
}

struct CommandListener {
    socket: DaemonSocket,
}

impl CommandListener {
    async fn get_command(&self) -> Result<EventLoopCommand, String> {
        let mut connection = match self.socket.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                return Err(format!(
                    "Failed to accept connection: {:?} - stopping daemon",
                    err
                ));
            }
        };

        let Ok(command_str) = connection.read_command().await else {
            return Err("Unknown command".to_string());
        };

        if let Ok(cmd) = serde_json::from_str::<Cmd>(&command_str) {
            match cmd {
                Cmd::Daemon { .. } => {
                    if connection.respond("ERR".to_owned()).await.is_err() {
                        Err("Socket failed on sending response".to_string())
                    } else {
                        Err("Start command should never be passed to the daemon".to_string())
                    }
                }
                Cmd::HelloWorld { name } => {
                    if connection.respond("OK".to_owned()).await.is_err() {
                        Err("Socket failed on sending response".to_string())
                    } else {
                        Ok(EventLoopCommand::HelloWorld(name))
                    }
                }
            }
        } else if connection.respond("ERR".to_owned()).await.is_err() {
            Err("Socket failed on sending response".to_string())
        } else {
            Err("Received unknown command".to_string())
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

async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<()> {
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
    let cmd_listener = CommandListener { socket };

    let telio_task_handle = tokio::task::spawn_blocking(telio_task);

    let mut signals = Signals::new([SIGTERM])?;

    info!("Entering event loop");

    let err_str = loop {
        select! {
            maybe_cmd = cmd_listener.get_command() => {
                match maybe_cmd {
                    Ok(EventLoopCommand::HelloWorld(name)) => {
                        info!("Hello {}", name);
                    }
                    Err(err_str) => {
                        error!(err_str);
                        break Some(err_str);
                    }
                }
            },
            signal = signals.next() => {
                match signal {
                    Some(SIGTERM) => {
                        info!("Recieved SIGTERM signal, exiting");
                        break None;
                    }
                    Some(_) => {
                        info!("Recieved unexpected signal, ignoring");
                    }
                    None => {
                        break Some("Signal channel broken".to_string());
                    }
                }
            }
        }
    };

    // Wait until Telio task ends
    // TODO: When it will be doing something some channel with commands etc. might be needed
    telio_task_handle.await?;

    if let Some(err_str) = err_str {
        bail!(err_str);
    } else {
        Ok(())
    }
}
