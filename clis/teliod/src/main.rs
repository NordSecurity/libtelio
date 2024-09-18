//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use anyhow::Result;
use clap::Parser;
use nix::libc::SIGTERM;
use signal_hook_tokio::Signals;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{self, id},
    str::FromStr,
};
use tokio::{spawn, sync::mpsc};
use tracing::{error, info, level_filters::LevelFilter, warn};

use daemon_common::{comms::DaemonSocket, daemon::Daemon};

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
                    info!("Ended event loop: ok");
                } else {
                    info!("Ended event loop: not ok");
                }
                info!("Exited daemon event loop");
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
    Err,
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

    let _telio = Device::new(
        Features::default(),
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    );

    let mut signals = Signals::new(&[SIGTERM])?;

    // The thread handles recieves commands, makes the basic validation and if they seem to be correct it passes them to the main event loop
    let (command_sender, mut command_receiver) = mpsc::channel(10);
    let cmd_task_handle = async move {
        let mut connection = match socket.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                error!("Failed to accept connection: {:?} - stopping daemon", err);
                let _ = command_sender.send(EventLoopCommand::Err).await;
                break;
            }
        };

        let Ok(command_str) = connection.read_command().await else {
            warn!("Unknown command");
            continue;
        };

        if let Ok(cmd) = serde_json::from_str::<Cmd>(&command_str) {
            match cmd {
                Cmd::Daemon { .. } => {
                    warn!("Start command should never be passed to the daemon");
                    if connection.respond("ERR".to_owned()).await.is_err() {
                        if command_sender.send(EventLoopCommand::Err).await.is_err() {
                            error!("Broken channel, exiting");
                            break;
                        }
                    } else {
                        continue;
                    }
                }
                Cmd::HelloWorld { name } => {
                    if match connection.respond("OK".to_owned()).await {
                        Ok(_) => {
                            command_sender
                                .send(EventLoopCommand::HelloWorld(name))
                                .await
                        }
                        Err(_) => command_sender.send(EventLoopCommand::Err).await,
                    }
                    .is_err()
                    {
                        error!("Broken channel, exiting");
                        break;
                    }
                }
            }
        } else {
            warn!("Received unknown command: {}", command_str);
            if connection.respond("ERR".to_owned()).await.is_err()
                && command_sender.send(EventLoopCommand::Err).await.is_err()
            {
                error!("Broken channel, exiting");
                break;
            }
        }
    };

    info!("Entering event loop");

    let _ = loop {
        select! {
            maybe_cmd = command_receiver.recv() => {
                match maybe_cmd {
                    Some(EventLoopCommand::HelloWorld(name)) => {
                        info!("Hello {}", name);
                    }
                    Some(EventLoopCommand::Err) => {
                        break Some("Socket closed")
                    }
                    None => {
                        break Some("Channel closed")
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
                        break Some("Signal channel broken")
                    }
                }
            }
        }
    };

    info!("Before abort");

    if !signals.handle().is_closed() {
        signals.handle().close();
    }

    info!("After abort");

    info!("CMD task finished");

    // TODO: There are these two blocking processes, so we cannot just
    // return as it will hang on them, thus we exit process instead.
    // This should be done in some nicer way.
    // if let Some(_) = result {
    //     process::exit(1);
    // } else {
    //     process::exit(0);
    // }

    Ok(())
}
