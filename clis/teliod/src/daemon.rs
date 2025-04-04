use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use signal_hook_tokio::Signals;
use std::{net::IpAddr, sync::Arc};
use telio::telio_model::mesh::ExitNode;
use telio::{
    crypto::SecretKey,
    device::{Device, DeviceConfig, Error as DeviceError},
    ffi::defaults_builder::FeaturesDefaultsBuilder,
    telio_model::config::Config as MeshMap,
    telio_utils::select,
    telio_wg::AdapterType,
};
use tokio::sync::mpsc::Sender;
use tokio::{sync::mpsc, sync::oneshot, time::Duration};
use tracing::{debug, error, info, trace, warn};

use crate::core_api::{fetch_vpn_server, get_meshmap as get_meshmap_from_server, init_with_api};
use crate::logging::setup_logging;
use crate::ClientCmd;
use crate::{
    command_listener::CommandListener,
    comms::DaemonSocket,
    config::DeviceIdentity,
    config::{InterfaceConfig, TeliodDaemonConfig},
    nc::NotificationCenter,
    TelioStatusReport, TeliodError,
};

#[derive(Debug)]
pub enum TelioTaskCmd {
    FetchVpnServer,
    ConnectToExit(ExitNode),
    // Command to set the downloaded meshmap to telio instance
    UpdateMeshmap(MeshMap),
    // Get telio status
    GetStatus(oneshot::Sender<TelioStatusReport>),
    // Configure the system interface
    SetIp(IpAddr),
    // Break the receive loop to quit the daemon and exit gracefully
    Quit,
}

const EMPTY_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Debug, Default)]
pub struct TelioTaskStates {
    interface_ip_address: Option<IpAddr>,
}

// From async context Telio needs to be run in separate task
fn telio_task(
    node_identity: Arc<DeviceIdentity>,
    auth_token: Arc<String>,
    mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    tx_channel: mpsc::Sender<TelioTaskCmd>,
    interface_config: &InterfaceConfig,
    adapter: AdapterType,
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

    // Keep track of current meshnet states
    let mut state = TelioTaskStates::default();
    let sys_config = interface_config.config_provider.create();

    // TODO: This is temporary to be removed later on when we have proper integration
    // tests with core API. This is to not look for tokens in a test environment
    // right now as the values are dummy and program will not run as it expects
    // real tokens.
    if !auth_token.as_str().eq("") {
        start_telio(
            &mut telio,
            node_identity.private_key.clone(),
            &interface_config.name,
            adapter,
        )?;
        task_retrieve_meshmap(node_identity, auth_token.clone(), tx_channel.clone());

        while let Some(cmd) = rx_channel.blocking_recv() {
            info!("Got command {:?}", cmd);
            match cmd {
                TelioTaskCmd::FetchVpnServer => {
                    task_retrieve_vpn_server(auth_token.clone(), tx_channel.clone())
                }
                TelioTaskCmd::ConnectToExit(node) => match telio.connect_exit_node(&node) {
                    Ok(_) => {
                        eprintln!("Connected to exit node {node:?}");
                        debug!("connect to exit node successful {node:?}");
                    }
                    Err(e) => {
                        error!("Unable to connect to exit node due to {e}");
                    }
                },
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
                    let status_report = TelioStatusReport {
                        telio_is_running: telio.is_running(),
                        meshnet_ip: state.interface_ip_address,
                        external_nodes: telio.external_nodes()?,
                    };
                    debug!("Telio status: {:#?}", status_report);
                    if response_tx_channel.send(status_report).is_err() {
                        error!("Telio task failed sending status report")
                    }
                }
                TelioTaskCmd::SetIp(new_ip_address) => {
                    // update the interface only if the address is new
                    if state
                        .interface_ip_address
                        .map_or(true, |ip| ip != new_ip_address)
                    {
                        state.interface_ip_address = Some(new_ip_address);
                        _ = sys_config.set_ip(&interface_config.name, &new_ip_address);
                    }
                }
                TelioTaskCmd::Quit => {
                    telio.stop();
                    break;
                }
            }
        }
    }
    Ok(())
}

fn task_retrieve_vpn_server(auth_token: Arc<String>, tx: mpsc::Sender<TelioTaskCmd>) {
    tokio::spawn(async move {
        let result = fetch_vpn_server(auth_token).await;
        match result {
            Ok(vpn_server) => {
                trace!("Vpn {:#?}", vpn_server);
                #[allow(mpsc_blocking_send)]
                if let Err(e) = tx.send(TelioTaskCmd::ConnectToExit(vpn_server)).await {
                    error!("Unable to connect to vpn due to {e}");
                }
            }
            Err(e) => error!("Getting VPN Server failed due to {e}"),
        }
    });
}

fn task_retrieve_meshmap(
    device_identity: Arc<DeviceIdentity>,
    auth_token: Arc<String>,
    tx: mpsc::Sender<TelioTaskCmd>,
) {
    tokio::spawn(async move {
        let result = get_meshmap_from_server(device_identity, auth_token).await;
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

fn start_telio(
    telio: &mut Device,
    private_key: SecretKey,
    interface_name: &str,
    adapter: AdapterType,
) -> Result<(), DeviceError> {
    telio.start(&DeviceConfig {
        private_key,
        name: Some(interface_name.to_owned()),
        adapter,
        ..Default::default()
    })?;

    debug!("started telio with {:?}...", adapter);
    Ok(())
}

async fn daemon_init(
    config: TeliodDaemonConfig,
    telio_tx: Sender<TelioTaskCmd>,
    token: Arc<String>,
) -> Result<Arc<DeviceIdentity>, TeliodError> {
    // TODO: This if condition and ::default call is temporary to be removed later
    // on when we have proper integration tests with core API.
    // This is to not look for tokens in a test environment right now as the values
    // are dummy and program will not run as it expects real tokens.
    let identity = Arc::new(if !config.authentication_token.eq(EMPTY_TOKEN) {
        init_with_api(&config.authentication_token).await?
    } else {
        DeviceIdentity::default()
    });

    let nc = NotificationCenter::new(&config, &identity.hw_identifier).await?;

    let identity_clone = identity.clone();
    nc.add_callback(Arc::new(move |_am| {
        task_retrieve_meshmap(identity_clone.clone(), token.clone(), telio_tx.clone());
    }))
    .await;

    Ok(identity)
}

pub async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<(), TeliodError> {
    let _tracing_worker_guard = setup_logging(
        &config.log_file_path,
        config.log_level,
        config.log_file_count,
    )
    .await?;

    debug!("started with config: {config:?}");

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

    let (telio_tx, telio_rx) = mpsc::channel(10);

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let mut cmd_listener = CommandListener::new(socket, telio_tx.clone());

    let token_ptr = Arc::new(config.authentication_token.clone());

    let identity_ptr = select! {
        init_values = daemon_init(config.clone(), telio_tx.clone(), token_ptr.clone()) => init_values?,
        _ = signals.next() => {
            warn!("Interrupted while obtaining identity - stopping");
            return Ok(());
        }
    };

    let tx_clone = telio_tx.clone();
    let mut telio_task_handle = tokio::task::spawn_blocking(move || {
        let adapter = match config.adapter_type {
            crate::config::AdapterType::NepTUN => AdapterType::NepTUN,
            crate::config::AdapterType::Native => AdapterType::LinuxNativeWg,
        };

        telio_task(
            identity_ptr,
            token_ptr,
            telio_rx,
            tx_clone,
            &config.interface,
            adapter,
        )
    });

    info!("Entering event loop");
    eprintln!("Daemon started");

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
                        info!("Client command {:?} executed successfully", command);
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
