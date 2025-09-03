use futures::pin_mut;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use signal_hook_tokio::Signals;
use std::net::SocketAddr;
use std::sync::Arc;
use telio::telio_model::mesh::ExitNode;
use tokio::{sync::mpsc, sync::oneshot, time::Duration};
use tracing::{debug, error, info, trace, warn};

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

use crate::{
    command_listener::CommandListener,
    comms::DaemonSocket,
    config::{Endpoint, TeliodDaemonConfig, VpnConfig, LOCAL_IP},
    core_api::{
        DEFAULT_WIREGUARD_PORT,
        get_countries_with_exp_backoff, get_recommended_servers_with_exp_backoff,
        request_nordlynx_key,
    },
    interface::ConfigureInterface,
    ClientCmd, ExitNodeStatus, TelioStatusReport, TeliodError,
};

#[derive(Debug)]
pub enum TelioTaskCmd {
    // Get telio status
    GetStatus(oneshot::Sender<TelioStatusReport>),
    // Connect to exit node with endpoint and optional hostname
    ConnectToExitNode(Endpoint),
    // Break the receive loop to quit the daemon and exit gracefully
    Quit,
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
    let endpoint = match &config.vpn {
        // Use the endpoint directly if provided in the config
        VpnConfig::Server(endpoint) => Some(endpoint.clone()),
        // Find VPN exit node based on country
        VpnConfig::Country(target_country) => {
            // Fetch the list of countries to find the matching country ID
            let country_id = match get_countries_with_exp_backoff(
                &config.authentication_token,
                config.http_certificate_file_path.as_deref(),
            )
            .await
            {
                Ok(countries_list) => countries_list.iter().find_map(|country| {
                    if country.matches(target_country) {
                        Some(country.id)
                    } else {
                        None
                    }
                }),
                Err(e) => {
                    error!("Getting countries failed due to: {e}");
                    None
                }
            };
            if country_id.is_none() {
                warn!("country_id not found for: {target_country}");
            }

            // Fetch the list of recommended server from the API
            // if no country_id is found, as a fallback the API will still return a
            // recommended server based on other metrics
            match get_recommended_servers_with_exp_backoff(
                country_id,
                Some(1),
                &config.authentication_token,
                config.http_certificate_file_path.as_deref(),
            )
            .await
            {
                Ok(servers) => {
                    // TODO: LLT-6460 - We can store the recommended server list, just in case
                    // one server fails to connect, try the next one.
                    trace!("Servers {:#?}", servers);
                    servers.first().and_then(|server| {
                        // Convert Server to Endpoint
                        server.wg_public_key().and_then(|pk| {
                            pk.parse().ok().map(|public_key| Endpoint {
                                address: server.address(),
                                public_key,
                                hostname: server.hostname(),
                            })
                        })
                    })
                }
                Err(e) => {
                    error!("Getting recommended servers failed due to: {e}");
                    None
                }
            }
        }
    };

    debug!("Selected exit node: {:#?}", endpoint);
    if let Some(endpoint) = endpoint {
        // Send the command to initiate the VPN connection
        if let Err(e) = tx.send(TelioTaskCmd::ConnectToExitNode(endpoint)).await {
            error!("Failed to send connect to exit node command: {e}");
        }
    } else {
        warn!("No endpoint found");
    }
}

pub async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<(), TeliodError> {
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
                res = cmd_listener.try_recv_quit() => {
                    match res {
                        Ok(_) => {
                            info!("Received quit command, exiting");
                            return Ok(())
                        },
                        Err(e) => {
                            debug!("Received command {:?} while obtaining service credentials, ignoring", e);
                        },
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
    // TODO: This can be triggered through teliod command to allow the user to stop/restart.
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
            result = cmd_listener.handle_client_connection() => {
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
