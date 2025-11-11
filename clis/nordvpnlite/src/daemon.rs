use futures::pin_mut;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use signal_hook_tokio::Signals;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use telio::crypto::PublicKey;
use telio::telio_model::mesh::{ExitNode, Node};
use thiserror::Error as ThisError;
use tokio::task::JoinError;
use tokio::{
    sync::{mpsc, oneshot},
    time::Duration,
};
use tracing::{debug, error, info, trace, warn};
use tracing_appender::rolling::InitError;

use telio::telio_utils::select;
#[cfg(target_os = "linux")]
use telio::telio_utils::LIBTELIO_FWMARK;
use telio::{
    crypto::SecretKey,
    device::{Device, DeviceConfig, Error as DeviceError},
    ffi::defaults_builder::FeaturesDefaultsBuilder,
    telio_model::event::{ErrorLevel, Event},
    telio_model::mesh::NodeState,
};

use crate::command_listener::{ClientCmd, ExitNodeConfig, TelioTaskCmd, TIMEOUT_SEC};
use crate::core_api::get_server_endpoints_list;
use crate::{
    command_listener::CommandListener,
    comms::DaemonSocket,
    config::{NordVpnLiteConfig, LOCAL_IP},
    core_api::{request_nordlynx_key, Error as ApiError, DEFAULT_WIREGUARD_PORT},
    interface::ConfigureInterface,
};

#[derive(Debug, ThisError)]
pub enum NordVpnLiteError {
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
    #[error("Invalid token in config: {msg}")]
    InvalidConfigToken { msg: String },
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

/// Libtelio and VPN status report
#[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
pub struct TelioStatusReport {
    /// State of telio runner
    pub telio_is_running: bool,
    /// Assigned IP address
    pub ip_address: Option<IpAddr>,
    /// VPN server node
    pub exit_node: Option<ExitNodeStatus>,
}

/// Description of the exit Node
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitNodeStatus {
    /// An identifier for a node
    pub identifier: String,
    /// The public key of the exit node
    pub public_key: PublicKey,
    /// Hostname of the node
    pub hostname: Option<String>,
    /// Socket address of the Exit Node
    pub endpoint: Option<SocketAddr>,
    /// State of the node (connecting, connected, or disconnected)
    pub state: NodeState,
}

impl ExitNodeStatus {
    fn from_node(value: &Node, hostname: Option<String>) -> Self {
        Self {
            identifier: value.identifier.to_owned(),
            public_key: value.public_key,
            state: value.state,
            endpoint: value.endpoint,
            hostname: hostname.or(value.hostname.to_owned()),
        }
    }
}

/// Outcome of executing a TelioTaskCmd, indicating whether TelioTask should keep listening
/// for commands or not
#[derive(Debug, PartialEq, Eq)]
pub enum TelioTaskOutcome {
    Continue,
    Exit,
}

struct TelioContext {
    telio: Device,
    interface_config_provider: Box<dyn ConfigureInterface>,
    config: NordVpnLiteConfig,
    exit_node: Option<ExitNodeStatus>,
}

impl TelioContext {
    fn new(
        config: NordVpnLiteConfig,
        nordlynx_private_key: SecretKey,
    ) -> Result<Self, NordVpnLiteError> {
        debug!("Initializing telio device");

        // TODO: Make telio features configurable from nordvpnlite config: LLT-6587
        // Create default features with direct connections enabled
        let features = Arc::new(FeaturesDefaultsBuilder::new())
            .enable_direct()
            .build();

        let mut telio = Device::new(features, handle_telio_event, None)?;
        Self::start_telio(&mut telio, &config, nordlynx_private_key)?;

        let mut interface_config_provider = config.interface.get_config_provider();
        interface_config_provider.initialize()?;
        interface_config_provider
            .set_ip(&LOCAL_IP.into())
            .inspect_err(|e| error!("Failed to set interface IP with error '{e:?}'"))?;

        Ok(Self {
            telio,
            interface_config_provider,
            config,
            exit_node: None,
        })
    }

    fn start_listening_commands(
        &mut self,
        mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    ) -> Result<(), NordVpnLiteError> {
        while let Some(cmd) = rx_channel.blocking_recv() {
            trace!("TelioTask got command {:?}", cmd);
            match cmd.execute(self)? {
                TelioTaskOutcome::Exit => break,
                TelioTaskOutcome::Continue => continue,
            }
        }
        Ok(())
    }

    fn start_telio(
        telio: &mut Device,
        config: &NordVpnLiteConfig,
        nordlynx_private_key: SecretKey,
    ) -> Result<(), DeviceError> {
        telio.start(DeviceConfig {
            private_key: nordlynx_private_key,
            name: Some(config.interface.name.to_owned()),
            adapter: config.adapter_type.to_owned(),
            ..Default::default()
        })?;

        #[cfg(target_os = "linux")]
        telio.set_fwmark(LIBTELIO_FWMARK)?;

        info!("started telio with {:?}...", config.adapter_type);
        Ok(())
    }

    fn update_exit_node(&mut self, mut updated_node: ExitNodeStatus) {
        if let Some(current_node) = self.exit_node.as_ref() {
            if updated_node != *current_node {
                debug!(
                    "Updating exit node {:?} -> {:?}",
                    current_node, updated_node
                );
                if updated_node.identifier == current_node.identifier
                    && updated_node.hostname.is_none()
                {
                    updated_node.hostname = current_node.hostname.to_owned()
                };
                self.exit_node = Some(updated_node);
            }
        } else {
            self.exit_node = Some(updated_node);
        }
    }

    fn fetch_exit_node(&mut self) -> Result<(), NordVpnLiteError> {
        let external_nodes = self.telio.external_nodes()?;
        let exit_node = external_nodes
            .iter()
            .find(|node| node.is_exit)
            .map(|node| ExitNodeStatus::from_node(node, None));
        if let Some(node) = exit_node {
            self.update_exit_node(node);
        }
        Ok(())
    }
}

impl TelioTaskCmd {
    fn execute(self, ctx: &mut TelioContext) -> Result<TelioTaskOutcome, NordVpnLiteError> {
        match self {
            TelioTaskCmd::GetStatus(response_tx_channel) => {
                ctx.fetch_exit_node()?;
                let status_report = TelioStatusReport {
                    telio_is_running: ctx.telio.is_running(),
                    ip_address: ctx.interface_config_provider.get_ip(),
                    exit_node: ctx.exit_node.clone(),
                };
                debug!("Telio status: {:#?}", status_report);
                if response_tx_channel.send(status_report).is_err() {
                    error!("Telio task failed sending status report: receiver dropped")
                }
                Ok(TelioTaskOutcome::Continue)
            }
            TelioTaskCmd::ConnectToExitNode(exit_node) => {
                ctx.interface_config_provider
                    .set_exit_routes(&exit_node.endpoint.address, &exit_node.dns)
                    .inspect_err(|e| {
                        error!("Failed to set routes for exit routing with error '{e:?}'")
                    })?;
                let node = ExitNode {
                    identifier: uuid::Uuid::new_v4().to_string(),
                    public_key: exit_node.endpoint.public_key,
                    allowed_ips: None,
                    endpoint: Some(SocketAddr::new(
                        exit_node.endpoint.address,
                        ctx.config
                            .override_default_wg_port
                            .unwrap_or(DEFAULT_WIREGUARD_PORT),
                    )),
                };
                match ctx.telio.connect_exit_node(&node) {
                    Ok(_) => {
                        info!(
                            "Connected to exit node: {} ({}) [{}]",
                            exit_node.endpoint.address,
                            exit_node.endpoint.public_key,
                            exit_node.endpoint.hostname.as_deref().unwrap_or_default()
                        );
                        let external_nodes = ctx.telio.external_nodes()?;
                        let exit_node =
                            external_nodes.iter().find(|node| node.is_exit).map(|node| {
                                ExitNodeStatus::from_node(node, exit_node.endpoint.hostname)
                            });
                        ctx.exit_node = exit_node;
                    }
                    Err(e) => {
                        error!("Failed to connect to VPN with error: {e:?}");
                    }
                }
                Ok(TelioTaskOutcome::Continue)
            }
            TelioTaskCmd::Quit(response_tx_channel) => {
                ctx.telio.stop();
                _ = ctx
                    .interface_config_provider
                    .cleanup_exit_routes()
                    .inspect_err(|e| {
                        error!("Failed to cleanup routes for exit routing with error '{e:?}'")
                    });
                _ = ctx
                    .interface_config_provider
                    .cleanup_interface()
                    .inspect_err(|e| error!("Failed to cleanup interface with error '{e:?}'"));

                if response_tx_channel.send(()).is_err() {
                    error!("Telio task failed sending quit response: receiver dropped")
                }
                Ok(TelioTaskOutcome::Exit)
            }
        }
    }
}

/// Handles establishing a connection to a VPN exit node based on the given configuration.
///
/// If the config contains a specific server, it uses that directly, otherwise if
/// a country is provided, it queries the API to find a recommended server.
/// Sends a `ConnectToExitNode` command via the provided channel on success.
/// Sends a `Quit` command via the provided channel on failure.
async fn handle_exit_node_connection(config: &NordVpnLiteConfig, tx: mpsc::Sender<TelioTaskCmd>) {
    let (response_tx, _) = oneshot::channel();
    let command = match get_server_endpoints_list(config).await {
        Ok(endpoints) => {
            // TODO: LLT-6460 - We can store the recommended server list, just in case
            // one server fails to connect, try the next one.
            if let Some(endpoint) = endpoints.first() {
                debug!("Selected exit node: {:#?}", endpoint);
                // initiate the VPN connection
                TelioTaskCmd::ConnectToExitNode(ExitNodeConfig {
                    endpoint: endpoint.to_owned(),
                    dns: config.dns.clone(),
                })
            } else {
                error!("Getting exit node endpoint failed: empty list");
                TelioTaskCmd::Quit(response_tx)
            }
        }
        Err(e) => {
            error!("Getting exit node endpoint failed: {e}");
            TelioTaskCmd::Quit(response_tx)
        }
    };

    // Send the command to the telio task
    #[allow(mpsc_blocking_send)]
    if let Err(e) = tx.send(command).await {
        error!("Failed to send exit node command to telio task: {e}");
    }
}

pub async fn daemon_event_loop(config: NordVpnLiteConfig) -> Result<(), NordVpnLiteError> {
    debug!("started with config: {config:?}");

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

    let (telio_tx, telio_rx) = mpsc::channel(10);

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let mut cmd_listener = CommandListener::new(socket, telio_tx.clone());

    let nordlynx_private_key = {
        let api_request_future = request_nordlynx_key(
            &config.authentication_token,
            config.http_certificate_file_path.as_deref(),
        );
        pin_mut!(api_request_future);
        loop {
            select! {
                nordlynx_private_key = &mut api_request_future => break nordlynx_private_key?,
                connection_result = cmd_listener.accept_client_connection() => {
                    match connection_result {
                        Ok(connection) => {
                            match cmd_listener.handle_client_command(false, connection).await {
                                Ok(ClientCmd::QuitDaemon) => {
                                    info!("Received quit command, exiting");
                                    return Ok(())
                                },
                                Ok(command) => {
                                    debug!("Received command {command:?} while obtaining service credentials, ignoring");
                                },
                                Err(err) => {
                                    debug!("Received invalid command while obtaining service credentials: {err:?}");
                                },
                            }
                        },
                        Err(err) => {
                            error!("Failed accepting client connection: {err}");
                        }
                    }
                },
                _ = signals.next() => {
                    warn!("Interrupted while obtaining service credentials - stopping");
                    return Ok(());
                }
            };
        }
    };

    let config_clone = config.clone();
    let mut telio_task_handle = tokio::task::spawn_blocking(move || {
        let mut context = TelioContext::new(config_clone, nordlynx_private_key)?;
        context.start_listening_commands(telio_rx)
    });

    // Spawn the async task for exit node connection
    // TODO: This can be triggered through nordvpnlite command to allow the user to stop/restart.
    let config_clone = config.clone();
    let tx_clone = telio_tx.clone();
    tokio::spawn(async move {
        handle_exit_node_connection(&config_clone, tx_clone).await;
        debug!("Exit node connection task completed");
    });

    info!("Entering event loop");
    loop {
        select! {
            // Check if telio_task completes and exit if it fails
            join_result = &mut telio_task_handle => {
                match join_result {
                    Ok(Ok(_)) => {
                        info!("Telio task thread completed, exiting");
                        break Ok(())
                    }
                    Ok(Err(err)) => {
                        error!("Telio task failed with error: {:?}", err);
                        break Err(err);
                    }
                    Err(err) => {
                        error!("Failed to join telio task: {:?}", err);
                        break Err(err.into());
                    }
                }
            },
            // Handle commands from the client side
            connection_result = cmd_listener.accept_client_connection() => {
                match connection_result {
                    Ok(connection) => {
                        match cmd_listener.handle_client_command(true, connection).await {
                            Ok(command) => {
                                debug!("Client command {:?} executed successfully", command);
                            },
                            Err(err) => {
                                error!("Received invalid command from client: {}", err);
                            }
                        }
                    },
                    Err(err) => {
                        error!("Failed accepting client connection: {err}");
                    }
                }
            },
            // Handle interrupt signals for clean shutdown
            signal = signals.next() => {
                match signal {
                    Some(s @ SIGHUP | s @ SIGTERM | s @ SIGINT | s @ SIGQUIT) => {
                        info!("Received signal {:?}, exiting", Signal::try_from(s));
                        let (response_tx, response_rx) = oneshot::channel();
                        if let Err(e) = telio_tx.send_timeout(TelioTaskCmd::Quit(response_tx), Duration::from_secs(2)).await {
                            error!("Unable to send QUIT due to {e}");
                        };
                        if let Err(e) = response_rx.await {
                            error!("Error receiving quit response from telio task: {e}");
                        }

                        break Ok(());
                    }
                    Some(s) => {
                        info!("Received unexpected signal {s:?}, ignoring");
                    }
                    None => {
                        break Err(NordVpnLiteError::BrokenSignalStream);
                    }
                }
            }
        }
    }
}

/// Handle events from telio::device
fn handle_telio_event(event: Box<Event>) {
    match event.as_ref() {
        Event::Node { body } => {
            match body.state {
                NodeState::Connected => {
                    info!(
                        "Node connected: {} ({})",
                        body.hostname.as_deref().unwrap_or(&body.identifier),
                        body.public_key
                    );
                    if body.is_exit {
                        info!("Exit node connection established");
                    }
                }
                NodeState::Connecting => {
                    info!(
                        "Node connecting: {} ({})",
                        body.hostname.as_deref().unwrap_or(&body.identifier),
                        body.public_key
                    );
                }
                NodeState::Disconnected => {
                    info!(
                        "Node disconnected: {} ({})",
                        body.hostname.as_deref().unwrap_or(&body.identifier),
                        body.public_key
                    );
                    if body.is_exit {
                        info!(
                            "Exit node connection lost: {} ({})",
                            body.hostname.as_deref().unwrap_or(&body.identifier),
                            body.public_key
                        );
                    }
                }
            }
            if let Some(endpoint) = &body.endpoint {
                info!("Node endpoint: {}", endpoint);
            }
            if let Some(link_state) = &body.link_state {
                info!("Link state: {:?}", link_state);
            }
        }
        Event::Error { body } => match body.level {
            ErrorLevel::Critical => {
                error!("Critical error: {} (code: {:?})", body.msg, body.code);
            }
            ErrorLevel::Severe => {
                error!("Severe error: {} (code: {:?})", body.msg, body.code);
            }
            ErrorLevel::Warning => {
                warn!("Warning: {} (code: {:?})", body.msg, body.code);
            }
            ErrorLevel::Notice => {
                info!("Notice: {} (code: {:?})", body.msg, body.code);
            }
        },
        Event::Relay { body } => {
            warn!("Received unsupported relay event: {:?}", body);
        }
    }
}
