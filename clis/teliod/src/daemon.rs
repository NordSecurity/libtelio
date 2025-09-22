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
use tokio::task::{JoinError, JoinHandle};
use tokio::{sync::mpsc, time::Duration};
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

use crate::command_listener::{ClientCmd, TelioTaskCmd, TIMEOUT_SEC};
use crate::core_api::get_server_endpoints_list;
use crate::{
    command_listener::CommandListener,
    comms::DaemonSocket,
    config::{TeliodDaemonConfig, LOCAL_IP},
    core_api::{request_nordlynx_key, Error as ApiError, DEFAULT_WIREGUARD_PORT},
    interface::ConfigureInterface,
};

#[derive(Debug, ThisError)]
pub enum TeliodError {
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
    #[error("Event loop error: {0}")]
    EventLoopError(String),
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
    config: TeliodDaemonConfig,
    exit_node: Option<ExitNodeStatus>,
}

impl TelioContext {
    fn new(
        config: TeliodDaemonConfig,
        nordlynx_private_key: SecretKey,
    ) -> Result<Self, TeliodError> {
        debug!("Initializing telio device");

        // TODO: Make telio features configurable from teliod config: LLT-6587
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
    ) -> Result<(), TeliodError> {
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
        config: &TeliodDaemonConfig,
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

    fn fetch_exit_node(&mut self) -> Result<(), TeliodError> {
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
    fn execute(self, ctx: &mut TelioContext) -> Result<TelioTaskOutcome, TeliodError> {
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
            TelioTaskCmd::ConnectToExitNode(endpoint) => {
                ctx.interface_config_provider
                    .set_exit_routes(&endpoint.address)
                    .inspect_err(|e| {
                        error!("Failed to set routes for exit routing with error '{e:?}'")
                    })?;
                let node = ExitNode {
                    identifier: uuid::Uuid::new_v4().to_string(),
                    public_key: endpoint.public_key,
                    allowed_ips: None,
                    endpoint: Some(SocketAddr::new(
                        endpoint.address,
                        ctx.config
                            .override_default_wg_port
                            .unwrap_or(DEFAULT_WIREGUARD_PORT),
                    )),
                };
                match ctx.telio.connect_exit_node(&node) {
                    Ok(_) => {
                        info!(
                            "Connected to exit node: {} ({}) [{}]",
                            endpoint.address,
                            endpoint.public_key,
                            endpoint.hostname.as_deref().unwrap_or_default()
                        );
                        let external_nodes = ctx.telio.external_nodes()?;
                        let exit_node = external_nodes
                            .iter()
                            .find(|node| node.is_exit)
                            .map(|node| ExitNodeStatus::from_node(node, endpoint.hostname));
                        ctx.exit_node = exit_node;
                    }
                    Err(e) => {
                        error!("Failed to connect to VPN with error: {e:?}");
                    }
                }
                Ok(TelioTaskOutcome::Continue)
            }
            TelioTaskCmd::Quit => {
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
async fn handle_exit_node_connection(config: &TeliodDaemonConfig, tx: mpsc::Sender<TelioTaskCmd>) {
    match get_server_endpoints_list(config).await {
        Ok(endpoints) => {
            // TODO: LLT-6460 - We can store the recommended server list, just in case
            // one server fails to connect, try the next one.
            if let Some(endpoint) = endpoints.first() {
                debug!("Selected exit node: {:#?}", endpoint);
                // Send the command to initiate the VPN connection
                #[allow(mpsc_blocking_send)]
                if let Err(e) = tx
                    .send(TelioTaskCmd::ConnectToExitNode(endpoint.to_owned()))
                    .await
                {
                    error!("Failed to send connect command to telio task: {e}");
                }
            } else {
                error!("Getting exit node endpoint failed: empty list");
            }
        }
        Err(e) => {
            error!("Getting exit node endpoint failed: {e}");
        }
    }
}

pub async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<(), TeliodError> {
    debug!("started with config: {config:?}");

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

    let (telio_tx, telio_rx) = mpsc::channel(10);
    // Wrap in option to move the rx only once in the event loop
    let mut telio_rx = Some(telio_rx);

    // Kick off fetching nordlynx_key
    let auth_token = Arc::new(config.authentication_token.clone());
    let cert_path = config
        .http_certificate_file_path
        .as_ref()
        .map(|s| Arc::from(s.as_path()));
    let mut fetch_key_task = Some(Box::pin(request_nordlynx_key(auth_token, cert_path)));

    // Only created after completed fetching the nordlynx_key
    let mut telio_task_handle: Option<JoinHandle<Result<(), TeliodError>>> = None;
    // Indicates daemon has started and is ready to process events normally
    let mut daemon_ready = false;

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let mut cmd_listener = CommandListener::new(socket, telio_tx.clone());

    info!("Entering event loop");
    loop {
        select! {
            // Handle nordlynx_key retrieval task first
            // If the task exists, await it and return the key.
            // after completion it is set to None
            Some(key_result) = async {
                match &mut fetch_key_task {
                    Some(fut) => Some(fut.as_mut().await),
                    None => None,
                }
            }, if !daemon_ready => {
                match key_result {
                Ok(nordlynx_key) => {
                    info!("Nordlynx key obtained, starting telio task");

                    if let Some(rx) = telio_rx.take(){
                        let config_clone = config.clone();
                        let tx_clone = telio_tx.clone();
                        let key_clone = nordlynx_key.clone();

                        // Spawn telio main task
                        telio_task_handle = Some(tokio::task::spawn_blocking(move || {
                            let mut context = TelioContext::new(config_clone, key_clone)?;
                            context.start_listening_commands(rx)
                        }));

                        // Spawn exit node connection task
                        let config_clone = config.clone();
                        tokio::spawn(async move {
                            handle_exit_node_connection(&config_clone, tx_clone).await;
                            debug!("Exit node connection task completed");
                        });

                        fetch_key_task = None;
                        daemon_ready = true;
                        debug!("Daemon is initialized and ready");
                    } else {
                        error!("telio_rx already taken");
                        break Err(TeliodError::EventLoopError("telio_rx missing".into()));
                    }
                },
                Err(err) => {
                    error!("Failed to obtain nordlynx key: {:?}", err);
                    break Err(err.into());
                    }
                }
            }
            // Poll the telio_task for completion
            // Uses an async block to await on the optional telio_task handle,
            // that is created after fetch_key_task is completed
            Some(join_result) = async {
                match &mut telio_task_handle {
                    Some(handle) => Some(handle.await),
                    None => None,
                }
            }, if daemon_ready => {
                match join_result {
                    Ok(Ok(_)) => {
                        info!("Telio task thread completed normally");
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
            result = cmd_listener.handle_client_connection(daemon_ready) => {
                match result {
                    Ok(command) => {
                        debug!("Client command {:?} executed successfully", command);
                        if command == ClientCmd::QuitDaemon {
                            break Ok(())
                        }
                    }
                    Err(err) => {
                        error!("Received invalid command from client: {}", err);
                    }
                }
            },
            // Handle interrupt signals for clean shutdown
            signal = signals.next() => {
                match signal {
                    Some(s @ SIGHUP | s @ SIGTERM | s @ SIGINT | s @ SIGQUIT) => {
                        info!("Received signal {:?}, exiting", Signal::try_from(s));
                        if let Err(e) = telio_tx.send_timeout(TelioTaskCmd::Quit, Duration::from_secs(2)).await {
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
