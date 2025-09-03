use futures::pin_mut;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use reqwest::StatusCode;
use signal_hook_tokio::Signals;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::{net::IpAddr, sync::Arc};
use telio::crypto::PublicKey;
use telio::telio_model::mesh::{ExitNode, NodeState};
#[cfg(target_os = "linux")]
use telio::telio_utils::LIBTELIO_FWMARK;
use telio::{
    crypto::SecretKey,
    device::{Device, DeviceConfig, Error as DeviceError},
    ffi::defaults_builder::FeaturesDefaultsBuilder,
    telio_model::config::Config as MeshMap,
    telio_utils::select,
    telio_wg::AdapterType,
};
use tokio::{sync::mpsc, sync::mpsc::Sender, sync::oneshot, time::Duration};
use tracing::{debug, error, info, trace, warn};

use crate::{
    command_listener::CommandListener,
    comms::DaemonSocket,
    config::{DirectEndpointConfig, NordToken, TeliodDaemonConfig, VpnConfig},
    core_api::{
        get_countries_with_exp_backoff as get_countries_from_server,
        get_meshmap as get_meshmap_from_server,
        get_recommended_servers_with_exp_backoff as get_recommended_servers, init_with_api,
        DeviceIdentity, Error as CoreApiError, Server as CoreApiServer,
    },
    nc::NotificationCenter,
    ClientCmd, ExitNodeStatus, TelioStatusReport, TeliodError,
};

#[derive(Debug)]
pub enum TelioTaskCmd {
    /// Command to set the downloaded meshmap to telio instance
    UpdateMeshmap(MeshMap),
    /// Get telio status
    GetStatus(oneshot::Sender<TelioStatusReport>),
    /// Configure the system interface
    SetIp(IpAddr),
    /// Connect to exit node with IP and public key
    ConnectToExitNode(ExitNodeConfig),
    /// Check if connected to VPN server and if so, setup device routing
    MaybeSetupVPNRoutes(IpAddr, PublicKey),
    // Break the receive loop to quit the daemon and exit gracefully
    Quit,
}

const EMPTY_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEFAULT_WIREGUARD_PORT: u16 = 51820;

#[derive(Debug, Default)]
pub struct TelioTaskStates {
    interface_ip_address: Option<IpAddr>,
}

/// Endpoint configuration used for connection
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ExitNodeConfig {
    /// IP of ExitNode server
    pub address: IpAddr,
    /// Public key of ExitNode
    pub public_key: PublicKey,
}

impl ExitNodeConfig {
    /// Convert Server from API response to ExitNode endpoint configuration
    pub fn from_api(server: &CoreApiServer) -> Result<Self, TeliodError> {
        Ok(Self {
            address: server.address(),
            public_key: server
                .wg_public_key()
                .and_then(|key| key.parse().ok())
                .ok_or(TeliodError::EndpointNoPublicKey)?,
        })
    }
}

/// Convert DirectEndpointConfig specified manually to ExitNode configuration
impl From<DirectEndpointConfig> for ExitNodeConfig {
    fn from(server: DirectEndpointConfig) -> Self {
        Self {
            address: server.address,
            public_key: server.public_key,
        }
    }
}

// From async context Telio needs to be run in separate task
fn telio_task(
    node_identity: Arc<DeviceIdentity>,
    mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    tx_channel: mpsc::Sender<TelioTaskCmd>,
    config: TeliodDaemonConfig,
) -> Result<(), TeliodError> {
    debug!("Initializing telio device");

    // Create default features with direct connections enabled
    let features = Arc::new(FeaturesDefaultsBuilder::new())
        .enable_direct()
        .build();

    let mut telio = Device::new(
        features,
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    )?;

    // Keep track of current states
    let mut state = TelioTaskStates::default();
    let mut sys_config = config
        .interface
        .config_provider
        .create(config.interface.name.clone());

    if !config.authentication_token.is_empty() {
        start_telio(
            &mut telio,
            node_identity.private_key.clone(),
            &config.interface.name,
            config.adapter_type.to_owned(),
        )?;
        sys_config.initialize()?;
        task_retrieve_meshmap(
            node_identity,
            config.http_certificate_file_path.clone(),
            config.authentication_token.clone(),
            tx_channel.clone(),
        );

        while let Some(cmd) = rx_channel.blocking_recv() {
            trace!("TelioTask got command {:?}", cmd);
            match cmd {
                TelioTaskCmd::UpdateMeshmap(map) => {
                    let some_new_ip_address = map
                        .ip_addresses
                        .as_deref()
                        .and_then(|addresses| addresses.first().cloned());
                    match telio.set_config(&Some(map)) {
                        Ok(_) => {
                            debug!("meshnet map set successfully");
                            // configure the interface ip address
                            if let Some(new_ip_address) = some_new_ip_address {
                                task_set_ip(new_ip_address, tx_channel.clone());
                            }
                        }
                        Err(e) => {
                            error!("Unable to set meshmap due to {e}");
                        }
                    }
                }
                TelioTaskCmd::GetStatus(response_tx_channel) => {
                    let external_nodes = telio.external_nodes()?;
                    // Find the identifier of the exit node (VPN server or meshnet peer), if present.
                    let exit_node = external_nodes
                        .iter()
                        .find(|node| node.is_exit)
                        .map(ExitNodeStatus::from);

                    let status_report = TelioStatusReport {
                        telio_is_running: telio.is_running(),
                        meshnet_ip: state.interface_ip_address,
                        exit_node,
                        external_nodes,
                    };
                    debug!("Telio status: {:#?}", status_report);
                    if response_tx_channel.send(status_report).is_err() {
                        error!("Telio task failed sending status report")
                    }
                }
                TelioTaskCmd::SetIp(new_ip_address) => {
                    // update the interface only if the address is new
                    if state.interface_ip_address != Some(new_ip_address) {
                        state.interface_ip_address = Some(new_ip_address);
                        match sys_config.set_ip(&new_ip_address) {
                            Ok(_) => {
                                if let Some(vpn_config) = config.vpn.as_ref() {
                                    handle_exit_node_connection(
                                        vpn_config.clone(),
                                        tx_channel.clone(),
                                        config.http_certificate_file_path.clone(),
                                        config.authentication_token.clone(),
                                    );
                                }
                            }
                            Err(e) => {
                                error!("Failed to set IP with error '{e:?}'");
                            }
                        }
                    }
                }
                TelioTaskCmd::ConnectToExitNode(server) => {
                    let port = config
                        .override_default_wg_port
                        .unwrap_or(DEFAULT_WIREGUARD_PORT);

                    let node = ExitNode {
                        identifier: uuid::Uuid::new_v4().to_string(),
                        public_key: server.public_key,
                        allowed_ips: None,
                        endpoint: Some(SocketAddr::new(server.address, port)),
                    };
                    match telio.connect_exit_node(&node) {
                        Ok(_) => {
                            // routing for VPN should only be setup once the VPN connection has been established
                            // which could take some amount of time, yet we don't want to block the event loop
                            // this task checks the connection status and if connected sets up routing information
                            // otherwise it sleeps and tries again
                            task_maybe_setup_vpn_routes(
                                tx_channel.clone(),
                                server.address,
                                server.public_key,
                            );
                        }
                        Err(e) => {
                            error!("Failed to connect to VPN with error: {e:?}");
                        }
                    }
                }
                TelioTaskCmd::MaybeSetupVPNRoutes(ip, pubkey) => {
                    // find connection status for VPN server
                    let is_connected = telio
                        .external_nodes()
                        .ok()
                        .and_then(|nodes| {
                            nodes
                                .iter()
                                .find(|n| n.public_key == pubkey)
                                .map(|n| n.state == NodeState::Connected)
                        })
                        .unwrap_or(false);
                    if is_connected {
                        // if we're connected, setup routing information
                        info!("Successfully connected to VPN");
                        _ = sys_config.set_exit_routes(&ip).inspect_err(|e| {
                            error!("Failed to set routes for exit routing with error '{e:?}'")
                        });
                    } else {
                        // if not connected, call the task to sleep and then try again
                        task_maybe_setup_vpn_routes(tx_channel.clone(), ip, pubkey);
                    }
                }
                TelioTaskCmd::Quit => {
                    telio.stop();
                    _ = sys_config.cleanup_exit_routes().inspect_err(|e| {
                        error!("Failed to cleanup routes for exit routing with error '{e:?}'")
                    });
                    _ = sys_config
                        .cleanup_interface()
                        .inspect_err(|e| error!("Failed to cleanup interface with error '{e:?}'"));
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Handles establishing a connection to a VPN exit node based on the given configuration.
///
/// If a specific server is provided, it uses that directly.
/// If a country is provided, it queries the API to find a recommended server.
/// Sends a `ConnectToExitNode` command via the provided channel on success.
#[allow(mpsc_blocking_send)]
fn handle_exit_node_connection(
    vpn_config: VpnConfig,
    tx_channel: mpsc::Sender<TelioTaskCmd>,
    cert_path: Option<PathBuf>,
    auth_token: NordToken,
) {
    tokio::spawn(async move {
        let server = match vpn_config {
            // Use the server directly if provided in the config
            VpnConfig::Server(server) => Some(server.into()),
            // Find VPN exit node based on country
            VpnConfig::Country(target_country) => {
                // Fetch the list of countries to find the matching country ID
                let country_id = match get_countries_from_server(&auth_token, &cert_path).await {
                    Ok(countries_list) => countries_list.iter().find_map(|country| {
                        if country.matches(&target_country) {
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
                match get_recommended_servers(country_id, Some(1), &auth_token, &cert_path).await {
                    Ok(servers) => {
                        // TODO: LLT-6460 - We can store the recommended server list, just in case
                        // one server fails to connect, try the next one.
                        trace!("Servers {:#?}", servers);
                        let server = servers
                            .first()
                            // Override the default wg port, since it's not fetched by the API
                            .and_then(|server| ExitNodeConfig::from_api(server).ok());
                        server
                    }
                    Err(e) => {
                        error!("Getting recommended servers failed due to: {e}");
                        None
                    }
                }
            }
        };

        debug!("Selected exit node: {:#?}", server);
        if let Some(server) = server {
            // Send the command to initiate the VPN connection
            if let Err(e) = tx_channel
                .send(TelioTaskCmd::ConnectToExitNode(server))
                .await
            {
                error!("Faild to send connect to exit node command: {e}");
            }
        } else {
            warn!("No exit node found");
        }
    });
}

fn task_retrieve_meshmap(
    device_identity: Arc<DeviceIdentity>,
    cert_path: Option<PathBuf>,
    auth_token: NordToken,
    tx: mpsc::Sender<TelioTaskCmd>,
) {
    tokio::spawn(async move {
        let result = get_meshmap_from_server(device_identity, &auth_token, &cert_path).await;
        match result {
            Ok(meshmap) => {
                trace!("Meshmap {:#?}", meshmap);
                #[allow(mpsc_blocking_send)]
                if let Err(e) = tx.send(TelioTaskCmd::UpdateMeshmap(meshmap)).await {
                    error!("Unable to send meshmap due to {e}");
                }
            }
            Err(e) => error!("Getting meshmap failed due to {e}"),
        }
    });
}

fn task_set_ip(address: IpAddr, tx: mpsc::Sender<TelioTaskCmd>) {
    tokio::spawn(async move {
        #[allow(mpsc_blocking_send)]
        if let Err(e) = tx.send(TelioTaskCmd::SetIp(address)).await {
            error!("Unable to send command due to {e}");
        }
    });
}

// The task cannot interact directly with the telio device so we have to send a command over the command channel
// This will be a recursive-like story because if the connection with the VPN server has not been established,
// this task will be started again
fn task_maybe_setup_vpn_routes(
    tx_channel: mpsc::Sender<TelioTaskCmd>,
    server_ip: IpAddr,
    server_pubkey: PublicKey,
) {
    #[allow(mpsc_blocking_send)]
    tokio::spawn(async move {
        std::thread::sleep(Duration::from_millis(100));
        _ = tx_channel
            .send(TelioTaskCmd::MaybeSetupVPNRoutes(server_ip, server_pubkey))
            .await
            .inspect_err(|e| error!("Failed to send maybe setup vpn routes event: {e:?}"));
    });
}

fn start_telio(
    telio: &mut Device,
    private_key: SecretKey,
    interface_name: &str,
    adapter: AdapterType,
) -> Result<(), DeviceError> {
    telio.start(DeviceConfig {
        private_key,
        name: Some(interface_name.to_owned()),
        adapter,
        ..Default::default()
    })?;

    #[cfg(target_os = "linux")]
    telio.set_fwmark(LIBTELIO_FWMARK)?;

    info!("started telio with {:?}...", adapter);
    Ok(())
}

async fn daemon_init(
    config: TeliodDaemonConfig,
    telio_tx: Sender<TelioTaskCmd>,
) -> Result<Arc<DeviceIdentity>, TeliodError> {
    // TODO: This if condition and ::default call is temporary to be removed later
    // on when we have proper integration tests with core API.
    // This is to not look for tokens in a test environment right now as the values
    // are dummy and program will not run as it expects real tokens.
    let identity = Arc::new(if *config.authentication_token != *EMPTY_TOKEN {
        match Box::pin(init_with_api(&config)).await {
            Err(CoreApiError::UpdateMachine(StatusCode::NOT_FOUND)) => {
                debug!("Machine not found, removing cached identity file and trying again..");
                DeviceIdentity::remove_file();

                Box::pin(init_with_api(&config)).await?
            }
            Ok(identity) => identity,
            Err(e) => return Err(e.into()),
        }
    } else {
        DeviceIdentity::default()
    });

    let nc = NotificationCenter::new(&config, &identity.hw_identifier)
        .await
        .map_err(Box::new)?;

    let identity_clone = identity.clone();
    let cert_path = config.http_certificate_file_path.clone();
    nc.add_callback(Arc::new(move |_am| {
        task_retrieve_meshmap(
            identity_clone.clone(),
            cert_path.clone(),
            config.authentication_token.clone(),
            telio_tx.clone(),
        );
    }))
    .await;

    Ok(identity)
}

pub async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<(), TeliodError> {
    debug!("started with config: {config:?}");

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

    let (telio_tx, telio_rx) = mpsc::channel(10);

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let mut cmd_listener = CommandListener::new(socket, telio_tx.clone());

    let identity_ptr = {
        let daemon_init_future = daemon_init(config.clone(), telio_tx.clone());
        pin_mut!(daemon_init_future);
        loop {
            select! {
                init_values = &mut daemon_init_future => break init_values?,
                res = cmd_listener.try_recv_quit() => {
                    match res {
                        Ok(_) => {
                            info!("Received quit command, exiting");
                            return Ok(())
                        },
                        Err(e) => {
                            debug!("Received command {:?} while obtaining identity, ignoring", e);
                        },
                    }
                },
                _ = signals.next() => {
                    warn!("Interrupted while obtaining identity - stopping");
                    return Ok(());
                }
            };
        }
    };

    let tx_clone = telio_tx.clone();
    let mut telio_task_handle =
        tokio::task::spawn_blocking(move || telio_task(identity_ptr, telio_rx, tx_clone, config));

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
