use futures::pin_mut;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use signal_hook_tokio::Signals;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use telio_core::crypto::PublicKey;
use telio_core::telio_model::mesh::{ExitNode, Node};
use thiserror::Error as ThisError;
use tokio::task::JoinError;
use tokio::{
    sync::{mpsc, oneshot},
    time::Duration,
};
use tracing::{debug, error, info, trace, warn};
use tracing_appender::rolling::InitError;

use crate::logging;
use telio_core::telio_utils::select;

#[cfg(target_os = "linux")]
use telio_core::telio_utils::LIBTELIO_FWMARK;
use telio_core::{
    crypto::SecretKey,
    defaults_builder::FeaturesDefaultsBuilder,
    device::{Device, DeviceConfig, Error as DeviceError},
    telio_model::{
        constants::LOCAL_TUNNEL_IPV4,
        event::{ErrorLevel, Event},
        mesh::NodeState,
    },
};

use crate::command_listener::{ClientCmd, ExitNodeConfig, TelioTaskCmd, TIMEOUT_SEC};
use crate::core_api::get_server_endpoints_list;
use crate::{
    command_listener::CommandListener,
    comms::DaemonSocket,
    config::{NordVpnLiteConfig, RunningConfig},
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
    #[error("Failed to configure tracing subscriber: {0}")]
    TracingError(String),
    #[error("Could not configure IP rules")]
    IpRule,
    #[error("Could not configure IP routing")]
    IpRoute,
    #[error("Endpoint has no PublicKey")]
    EndpointNoPublicKey,
    #[error("Already connected to exit node")]
    AlreadyConnected,
    #[error("Not connected to exit node")]
    NotConnected,
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
    /// Handle to the tokio runtime. Used to run async tasks (e.g. HTTP calls) from
    /// within the spawn_blocking context of start_listening_commands
    tokio_handle: tokio::runtime::Handle,
}

impl TelioContext {
    fn new(
        config: NordVpnLiteConfig,
        nordlynx_private_key: SecretKey,
        tokio_handle: tokio::runtime::Handle,
    ) -> Result<Self, NordVpnLiteError> {
        debug!("Initializing telio device");

        // TODO: Make telio features configurable from nordvpnlite config: LLT-6587
        // Create default features with direct connections enabled
        let mut features = Arc::new(FeaturesDefaultsBuilder::new())
            .enable_direct()
            .build();

        if config.enable_firewall {
            features.firewall = Some(Default::default());
        }

        let mut telio = Device::new(features, handle_telio_event, None)?;
        Self::start_telio(&mut telio, &config, nordlynx_private_key)?;

        let mut interface_config_provider = config.interface.get_config_provider();
        interface_config_provider.initialize()?;
        interface_config_provider
            .set_ip(&LOCAL_TUNNEL_IPV4.into())
            .inspect_err(|e| error!("Failed to set interface IP with error '{e:?}'"))?;

        Ok(Self {
            telio,
            interface_config_provider,
            config,
            exit_node: None,
            tokio_handle,
        })
    }

    fn start_listening_commands(
        &mut self,
        mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    ) -> Result<bool, NordVpnLiteError> {
        let mut was_connected = false;
        while let Some(cmd) = rx_channel.blocking_recv() {
            trace!("TelioTask got command {:?}", cmd);

            if matches!(cmd, TelioTaskCmd::Quit(_)) {
                was_connected = self.was_connected()?;
            }

            match cmd.execute(self)? {
                TelioTaskOutcome::Exit => break,
                TelioTaskOutcome::Continue => continue,
            }
        }
        Ok(was_connected)
    }

    // This function is called in the context of configuration reload.
    // Returns true if exit node is in connected or connecting state.
    fn was_connected(&self) -> Result<bool, NordVpnLiteError> {
        let external_nodes = self.telio.external_nodes()?;
        Ok(external_nodes.iter().any(|node| {
            node.is_exit && matches!(node.state, NodeState::Connected | NodeState::Connecting)
        }))
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
    fn connect_to_exit_node(
        &mut self,
        exit_node_config: ExitNodeConfig,
    ) -> Result<(), NordVpnLiteError> {
        self.interface_config_provider
            .set_exit_routes(&exit_node_config.endpoint.address, &exit_node_config.dns)
            .inspect_err(|e| error!("Failed to set routes for exit routing with error '{e:?}'"))?;
        let node = ExitNode {
            identifier: uuid::Uuid::new_v4().to_string(),
            public_key: exit_node_config.endpoint.public_key,
            allowed_ips: None,
            endpoint: Some(SocketAddr::new(
                exit_node_config.endpoint.address,
                self.config
                    .override_default_wg_port
                    .unwrap_or(DEFAULT_WIREGUARD_PORT),
            )),
        };
        let (connect, kind): (fn(_, _) -> _, _) = if exit_node_config.post_quantum {
            (Device::connect_vpn_post_quantum, "post quantum ")
        } else {
            (Device::connect_exit_node, "")
        };
        match connect(&self.telio, &node) {
            Ok(_) => {
                info!(
                    "Connected to {kind}exit node: {} ({}) [{}]",
                    exit_node_config.endpoint.address,
                    exit_node_config.endpoint.public_key,
                    exit_node_config
                        .endpoint
                        .hostname
                        .as_deref()
                        .unwrap_or_default()
                );
                let external_nodes = self.telio.external_nodes()?;
                let exit_node_status =
                    external_nodes.iter().find(|node| node.is_exit).map(|node| {
                        ExitNodeStatus::from_node(node, exit_node_config.endpoint.hostname)
                    });
                self.exit_node = exit_node_status;
            }
            Err(e) => {
                error!("Failed to connect to VPN with error: {e:?}");
                return Err(NordVpnLiteError::DeviceError(e));
            }
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
            TelioTaskCmd::Disconnect(response_tx) => {
                let result = (|| {
                    if let Some(exit_node) = &ctx.exit_node {
                        ctx.telio
                            .disconnect_exit_node(&exit_node.public_key)
                            .map_err(|_| NordVpnLiteError::CommandFailed(ClientCmd::Disconnect))?;
                        let _ = ctx.interface_config_provider
                            .cleanup()
                            .inspect_err(|e| {
                                error!("Failed to cleanup routes for exit routing when disconnecting with error '{e:?}'")
                            });

                        ctx.exit_node = None;
                        Ok(())
                    } else {
                        error!("No connection to exit node");
                        Err(NordVpnLiteError::NotConnected)
                    }
                })();
                if response_tx
                    .send(result.as_ref().map_err(|e| e.to_string()).map(|_| ()))
                    .is_err()
                {
                    error!("Disconnect: receiver dropped before result could be sent");
                }
                Ok(TelioTaskOutcome::Continue)
            }
            TelioTaskCmd::Connect(response_tx) => {
                if ctx.exit_node.is_some() {
                    error!("Already connected to exit node");
                    if response_tx
                        .send(Err(NordVpnLiteError::AlreadyConnected.to_string()))
                        .is_err()
                    {
                        error!("Connect: receiver dropped before result could be sent");
                    }
                    return Ok(TelioTaskOutcome::Continue);
                }

                let endpoint_result = ctx
                    .tokio_handle
                    .block_on(get_server_endpoints_list(&ctx.config))
                    .map_err(NordVpnLiteError::CoreApiError)
                    .and_then(|endpoints| {
                        endpoints.into_iter().next().ok_or_else(|| {
                            error!("Getting exit node endpoint failed: empty list");
                            NordVpnLiteError::CommandFailed(ClientCmd::Connect)
                        })
                    });

                match endpoint_result {
                    Ok(endpoint) => {
                        debug!("Selected exit node endpoint: {:#?}", endpoint);
                        TelioTaskCmd::ConnectToExitNode(
                            ExitNodeConfig {
                                endpoint,
                                dns: ctx.config.dns.clone(),
                                post_quantum: ctx.config.post_quantum,
                            },
                            Some(response_tx),
                        )
                        .execute(ctx)
                    }
                    Err(e) => {
                        if response_tx.send(Err(e.to_string())).is_err() {
                            error!("Connect: receiver dropped before result could be sent");
                        }
                        Ok(TelioTaskOutcome::Continue)
                    }
                }
            }
            TelioTaskCmd::ConnectToExitNode(exit_node_config, response_tx) => {
                debug!(
                    "Connecting to exit node endpoint: {:#?}",
                    exit_node_config.endpoint
                );
                let result = ctx.connect_to_exit_node(exit_node_config);
                if let Some(tx) = response_tx {
                    if tx
                        .send(result.as_ref().map_err(|e| e.to_string()).map(|_| ()))
                        .is_err()
                    {
                        error!("ConnectToExitNode: receiver dropped before result could be sent");
                    }
                }
                Ok(TelioTaskOutcome::Continue)
            }
            TelioTaskCmd::Quit(response_tx_channel) => {
                _ = ctx.interface_config_provider.cleanup().inspect_err(|e| {
                    error!("Failed to cleanup interface and routes with error '{e:?}'")
                });

                // Has to be after cleanup to avoid issues with missing device
                ctx.telio.stop();

                if response_tx_channel.send(()).is_err() {
                    error!("Telio task failed sending quit response: receiver dropped")
                }
                Ok(TelioTaskOutcome::Exit)
            }
        }
    }
}

/// Sends a `ConnectToExitNode` command via the provided channel on success.
/// Sends a `Quit` command on failure so the daemon exits cleanly.
async fn handle_exit_node_connection(config: &NordVpnLiteConfig, tx: mpsc::Sender<TelioTaskCmd>) {
    let command = match get_server_endpoints_list(config).await {
        Ok(endpoints) => {
            // TODO: LLT-6460 - We can store the recommended server list, just in case
            // one server fails to connect, try the next one.
            if let Some(endpoint) = endpoints.first() {
                debug!("Selected exit node: {:#?}", endpoint);
                // initiate the VPN connection — fire-and-forget, no response needed
                TelioTaskCmd::ConnectToExitNode(
                    ExitNodeConfig {
                        endpoint: endpoint.to_owned(),
                        dns: config.dns.clone(),
                        post_quantum: config.post_quantum,
                    },
                    None,
                )
            } else {
                error!("Getting exit node endpoint failed: empty list");
                let (response_tx, _) = oneshot::channel();
                TelioTaskCmd::Quit(response_tx)
            }
        }
        Err(e) => {
            error!("Getting exit node endpoint failed: {e}");
            let (response_tx, _) = oneshot::channel();
            TelioTaskCmd::Quit(response_tx)
        }
    };

    // Send the command to the telio task
    #[allow(mpsc_blocking_send)]
    if let Err(e) = tx.send(command).await {
        error!("Failed to send exit node command to telio task: {e}");
    }
}

/// Outcome of a single daemon run
enum LoopOutcome {
    Exit,
    /// Carries new configuration and whether the VPN was connected at the time of reload.
    Reload {
        config: Box<RunningConfig>,
        was_connected: bool,
    },
}

pub async fn daemon_event_loop(
    mut config: RunningConfig,
    logging_handle: &mut logging::LoggingHandle,
    auto_connect: bool,
) -> Result<(), NordVpnLiteError> {
    let mut was_connected_before_reload = None;
    loop {
        // For the initial launch, respect the --do-not-connect flag.
        // For subsequent runs after a reload, the pre reload state directly encodes the intent
        let connect_on_startup = match was_connected_before_reload {
            None => auto_connect,
            Some(connected) => connected,
        };

        match run_daemon(config.clone(), connect_on_startup).await? {
            LoopOutcome::Exit => break,
            LoopOutcome::Reload {
                config: new_config,
                was_connected,
            } => {
                info!("Reloading config from {}", config.path.display());

                let logging_configuration_changed =
                    config.parsed.logging_params_changed(&new_config.parsed);

                config = *new_config;
                was_connected_before_reload = Some(was_connected);

                if logging_configuration_changed {
                    if let Err(e) = logging::reload_logging(
                        logging_handle,
                        &config.parsed.log_file_path,
                        config.parsed.log_level,
                        config.parsed.log_file_count,
                    ) {
                        error!("Failed to reload logging configuration: {e}, continue with previous logging configuration");
                    } else {
                        info!("Logging reconfigured successfully");
                    }
                } else {
                    info!("Logging configuration unchanged");
                }

                info!("Config reloaded, restarting daemon");
                // loop continues and run_daemon called again with new config
            }
        }
    }
    Ok(())
}

async fn run_daemon(
    config: RunningConfig,
    connect_on_startup: bool,
) -> Result<LoopOutcome, NordVpnLiteError> {
    debug!("started with config: {:?}", config.parsed);

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

    let (telio_tx, telio_rx) = mpsc::channel(10);

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let mut cmd_listener = CommandListener::new(socket, telio_tx.clone(), config.clone());

    let nordlynx_private_key = {
        let auth_token =
            config
                .parsed
                .get_auth_token()
                .map_err(|e| NordVpnLiteError::InvalidConfigToken {
                    msg: format!("Failed to get authentication token: {e}"),
                })?;
        let api_request_future = request_nordlynx_key(
            &auth_token,
            config.parsed.http_certificate_file_path.as_deref(),
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
                                    return Ok(LoopOutcome::Exit)
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
                    return Ok(LoopOutcome::Exit);
                }
            };
        }
    };

    let config_clone = config.parsed.clone();
    let tokio_handle = tokio::runtime::Handle::current();
    let (init_done_tx, init_done_rx) = oneshot::channel::<()>();
    let mut telio_task_handle = tokio::task::spawn_blocking(move || {
        let mut context = TelioContext::new(config_clone, nordlynx_private_key, tokio_handle)?;
        let _ = init_done_tx.send(());
        context.start_listening_commands(telio_rx)
    });

    if connect_on_startup && init_done_rx.await.is_ok() {
        let config_clone = config.parsed.clone();
        let tx_clone = telio_tx.clone();
        // Without blocking the main thread select (HTTP request) and connect to exit node
        tokio::spawn(async move {
            handle_exit_node_connection(&config_clone, tx_clone).await;
            debug!("Exit node connection task completed");
        });
    }

    info!("Entering event loop");
    loop {
        select! {
            // Check if telio_task completes and exit if it fails
            join_result = &mut telio_task_handle => {
                match join_result {
                    Ok(Ok(was_connected)) => {
                        if let Some(new_config) = cmd_listener.take_pending_config() {
                            trace!("Telio task thread completed after reload request, restarting");
                            break Ok(LoopOutcome::Reload {
                                config: Box::new(new_config),
                                was_connected,
                            })
                        } else {
                            trace!("Telio task thread completed, exiting");
                            break Ok(LoopOutcome::Exit)
                        }
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
            // Handle interrupt signals for clean shutdown or reload
            signal = signals.next() => {
                match signal {
                    Some(SIGHUP) => {
                        info!("Received signal SIGHUP, reloading");
                        match RunningConfig::from_file(&config.path) {
                            Err(e) => {
                                error!("Config file changed but failed to parse: {e}. Ignoring reload.");
                            }
                            Ok(new_config) if new_config.hash == config.hash => {
                                info!("Config file unchanged, ignoring reload request");
                            }
                            Ok(new_config) => {
                                let (response_tx, response_rx) = oneshot::channel();
                                if let Err(e) = telio_tx.send_timeout(TelioTaskCmd::Quit(response_tx), Duration::from_secs(2)).await {
                                    error!("Unable to send QUIT due to {e} during reload");
                                };
                                if let Err(e) = response_rx.await {
                                    error!("Error receiving quit response from telio task: {e}");
                                }
                                let was_connected = match telio_task_handle.await {
                                    Ok(Ok(state)) => state,
                                    err => {
                                        error!("Telio task did not complete cleanly during reload: {err:?}, defaulting to disconnected state");
                                        false
                                    }
                                };
                                break Ok(LoopOutcome::Reload {
                                    config: Box::new(new_config),
                                    was_connected,
                                });
                            }
                        }
                    }
                    Some(s @ SIGTERM | s @ SIGINT | s @ SIGQUIT) => {
                        info!("Received signal {:?}, exiting", Signal::try_from(s));
                        let (response_tx, response_rx) = oneshot::channel();
                        if let Err(e) = telio_tx.send_timeout(TelioTaskCmd::Quit(response_tx), Duration::from_secs(2)).await {
                            error!("Unable to send QUIT due to {e}");
                        };
                        if let Err(e) = response_rx.await {
                            error!("Error receiving quit response from telio task: {e}");
                        }

                        break Ok(LoopOutcome::Exit);
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

/// Handle events from telio_core::device
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
