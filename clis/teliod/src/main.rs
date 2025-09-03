//! Main and implementation of config and commands for Teliod - simple telio daemon for Linux and OpenWRT

use clap::Parser;
use daemonize::{Daemonize, Outcome};
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use std::{
    fs::OpenOptions,
    net::{IpAddr, SocketAddr},
};
use telio::{
    crypto::PublicKey,
    device::Error as DeviceError,
    telio_model::mesh::{Node, NodeState},
};
use thiserror::Error as ThisError;
use tokio::{
    task::JoinError,
    time::{timeout, Duration},
};
use tracing_appender::rolling::InitError;

#[cfg(feature = "cgi")]
mod cgi;
mod command_listener;
mod comms;
mod config;
mod configure_interface;
mod core_api;
mod daemon;
mod logging;
mod nc;

use crate::{
    command_listener::CommandResponse, comms::DaemonSocket, config::TeliodDaemonConfig,
    core_api::Error as ApiError,
};

const TIMEOUT_SEC: u64 = 1;

/// Umask allows only rw-rw-r--
const DEFAULT_UMASK: u32 = 0o113;

#[derive(Parser, Debug, PartialEq)]
#[clap()]
#[derive(Serialize, Deserialize)]
enum ClientCmd {
    #[clap(about = "Retrieve the status report")]
    GetStatus,
    #[clap(about = "Query if daemon is running")]
    IsAlive,
    #[clap(about = "Stop daemon execution")]
    QuitDaemon,
}

#[derive(Parser, Debug)]
#[clap()]
enum Cmd {
    #[clap(about = "Runs the teliod event loop")]
    Start(DaemonOpts),
    #[clap(flatten)]
    Client(ClientCmd),
    #[cfg(feature = "cgi")]
    #[clap(about = "Receive and parse http requests")]
    Cgi,
}

#[derive(Parser, Debug)]
struct DaemonOpts {
    /// Path to the config file
    config_path: String,

    /// Do not detach the teliod process from the terminal
    #[clap(long = "no-detach")]
    no_detach: bool,

    /// Specifies the daemons working directory.
    ///
    /// Defaults to "/".
    /// Ignored with no_detach flag.
    #[clap(long = "working-directory", default_value = "/")]
    working_directory: String,

    /// Redirect standard output to the specified file
    ///
    /// Defaults to "/var/log/teliod.log".
    /// Ignored with no-detach flag.
    #[clap(long = "stdout-path", default_value = "/var/log/teliod.log")]
    stdout_path: String,
}

#[derive(Debug, ThisError)]
enum TeliodError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Invalid command received: {0}")]
    InvalidCommand(String),
    #[error("Invalid response received: {0}")]
    InvalidResponse(String),
    #[error("Client failed to receive response in {TIMEOUT_SEC}s")]
    ClientTimeoutError,
    #[error("Broken signal stream")]
    BrokenSignalStream,
    #[error(transparent)]
    TelioTaskError(#[from] JoinError),
    #[error(transparent)]
    ParsingError(#[from] SerdeJsonError),
    #[error("Command failed to execute: {0:?}")]
    CommandFailed(ClientCmd),
    #[error("Failed executing system command: {0:?}")]
    SystemCommandFailed(String),
    #[error("Daemon is not running")]
    DaemonIsNotRunning,
    #[error("Daemon is running")]
    DaemonIsRunning,
    #[error("NotificationCenter failure: {0}")]
    NotificationCenter(#[from] Box<nc::Error>),
    #[error(transparent)]
    CoreApiError(#[from] ApiError),
    #[error(transparent)]
    DeviceError(#[from] DeviceError),
    #[error("Invalid config option {key}: {msg} (value '{value}')")]
    InvalidConfigOption {
        key: String,
        msg: String,
        value: String,
    },
    #[error(transparent)]
    LogAppenderError(#[from] InitError),
    #[error(transparent)]
    DaemonizeError(#[from] daemonize::Error),
    #[error("Could not configure IP rules")]
    IpRule,
    #[error("Could not configure IP routing")]
    IpRoute,
    #[error("Endpoint has no PublicKey")]
    EndpointNoPublicKey,
}

/// Libtelio and meshnet status report
#[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
pub struct TelioStatusReport {
    /// State of telio runner
    pub telio_is_running: bool,
    /// Assigned mesnet IP address
    pub meshnet_ip: Option<IpAddr>,
    /// Node used in traffic routing, VPN server or meshnet peer
    pub exit_node: Option<ExitNodeStatus>,
    /// List of meshnet peers
    pub external_nodes: Vec<Node>,
}

/// Description of the Exit Node
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitNodeStatus {
    /// An identifier for a node
    pub identifier: String,
    /// The public key of the exit node
    pub public_key: PublicKey,
    /// Socket address of the Exit Node
    pub endpoint: Option<SocketAddr>,
    /// State of the node (Connecting, connected, or disconnected)
    pub state: NodeState,
}

impl From<&Node> for ExitNodeStatus {
    fn from(value: &Node) -> Self {
        Self {
            identifier: value.identifier.to_owned(),
            public_key: value.public_key,
            state: value.state,
            endpoint: value.endpoint,
        }
    }
}

fn main() -> Result<(), TeliodError> {
    #[cfg(feature = "cgi")]
    cgi::constants::APP_PATHS.init()?;

    let mut cmd = Cmd::parse();

    // Pre-daemonizing setup
    if let Cmd::Start(opts) = &mut cmd {
        // Check if daemon already is running before forking
        if DaemonSocket::get_ipc_socket_path()?.exists() {
            return Err(TeliodError::DaemonIsRunning);
        }

        // Parse config file
        let mut config = TeliodDaemonConfig::from_file(&opts.config_path)?;
        config.resolve_env_token();

        println!("Saving logs to: {}", config.log_file_path);
        println!("Starting daemon");

        // Fork the process before starting Tokio runtime.
        // Tokio creates a multi-threaded asynchronous runtime,
        // but during forking only a single thread survives,
        // leaving tokio runtime in an undefined state and resulting in a panic.
        // https://github.com/tokio-rs/tokio/issues/4301
        if !opts.no_detach {
            // Redirect stdout and stderr to a specified file or /var/log/teliod.log by default
            let stdout_log_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&opts.stdout_path)?;

            // Daemon working directory is set to `/` by default
            // any relative path operations from now on could fail
            let daemon = Daemonize::new()
                .umask(DEFAULT_UMASK)
                .working_directory(&opts.working_directory)
                .stdout(stdout_log_file.try_clone()?)
                .stderr(stdout_log_file);

            // Daemonize the process
            match daemon.execute() {
                // Quit parent process
                Outcome::Parent(Ok(_)) => {
                    return Ok(());
                }
                // Continue in child process
                Outcome::Child(Ok(_)) => {}
                // Errors
                Outcome::Parent(Err(err)) => {
                    eprintln!("Fork parent error: {err}");
                    return Err(err.into());
                }
                Outcome::Child(Err(err)) => {
                    eprintln!("Child error {err}");
                    return Err(err.into());
                }
            }
        }

        // Run the daemon event loop
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            // Setup daemon logging
            let _tracing_worker_guard = logging::setup_logging(
                &config.log_file_path,
                config.log_level,
                config.log_file_count,
            )
            .await?;

            Box::pin(daemon::daemon_event_loop(config)).await
        })
    } else {
        client_main(cmd)
    }
}

#[tokio::main]
async fn client_main(cmd: Cmd) -> Result<(), TeliodError> {
    match cmd {
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
                        println!("{}", serde_json::to_string_pretty(&status)?);
                        Ok(())
                    }
                    CommandResponse::Err(e) => {
                        println!("Command executed failed: {e}");
                        Err(TeliodError::CommandFailed(cmd))
                    }
                }
            } else {
                Err(TeliodError::DaemonIsNotRunning)
            }
        }
        #[cfg(feature = "cgi")]
        Cmd::Cgi => {
            #[cfg(debug_assertions)]
            let _tracing_worker_guard = logging::setup_logging(
                cgi::constants::APP_PATHS.cgi_log(),
                tracing::level_filters::LevelFilter::TRACE,
                7,
            )
            .await?;

            tokio::task::spawn_blocking(|| {
                rust_cgi::handle(cgi::handle_request);
            })
            .await?;
            Ok(())
        }
        // Unexpected command, Cmd::Start should be handled by main
        _ => Err(TeliodError::InvalidCommand(format!("{cmd:?}"))),
    }
}
