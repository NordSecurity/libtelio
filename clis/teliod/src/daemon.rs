use futures::pin_mut;
use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use signal_hook_tokio::Signals;
use std::sync::Arc;
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
    telio_model::mesh::{ExitNode, NodeState},
    telio_wg::AdapterType,
};

use crate::{
    command_listener::CommandListener,
    comms::DaemonSocket,
    config::{TeliodDaemonConfig, LOCAL_IP},
    core_api::request_nordlynx_key,
    ClientCmd, ExitNodeStatus, TelioStatusReport, TeliodError,
};

#[derive(Debug)]
pub enum TelioTaskCmd {
    // Get telio status
    GetStatus(oneshot::Sender<TelioStatusReport>),
    // Connect to exit node with IP and public key
    ConnectToExitNode(ExitNode),
    // Break the receive loop to quit the daemon and exit gracefully
    Quit,
}

// From async context Telio needs to be run in separate task
fn telio_task(
    mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    tx_channel: mpsc::Sender<TelioTaskCmd>,
    config: TeliodDaemonConfig,
    nordlynx_private_key: SecretKey,
) -> Result<(), TeliodError> {
    debug!("Initializing telio device");

    // TODO: Make telio features configurable from teliod config LLT-6587]
    // Create default features with direct connections enabled
    let features = Arc::new(FeaturesDefaultsBuilder::new())
        .enable_direct()
        .build();

    let mut telio = Device::new(features, handle_telio_event, None)?;

    let mut interface_configurator = config.interface.get_configurator();

    start_telio(
        &mut telio,
        nordlynx_private_key,
        &config.interface.name,
        config.adapter_type.to_owned(),
    )?;

    interface_configurator.initialize()?;
    interface_configurator
        .set_ip(&LOCAL_IP.into())
        .inspect_err(|e| error!("Failed to set interface IP with error '{e:?}'"))?;

    let vpn_config = config.vpn.ok_or(TeliodError::InvalidConfigOption {
        key: "vpn".to_owned(),
        msg: "Couldn't get vpn configuration.".to_owned(),
        value: format!("{:?}", config),
    })?;
    let exit_node = ExitNode {
        identifier: uuid::Uuid::new_v4().to_string(),
        public_key: vpn_config.server_pubkey,
        allowed_ips: None,
        endpoint: Some(vpn_config.server_endpoint),
    };
    task_connect_to_exit_node(exit_node, tx_channel.clone());

    while let Some(cmd) = rx_channel.blocking_recv() {
        trace!("TelioTask got command {:?}", cmd);
        match cmd {
            TelioTaskCmd::GetStatus(response_tx_channel) => {
                let external_nodes = telio.external_nodes()?;
                // Find the identifier of the exit node (VPN server or meshnet peer), if present.
                let exit_node = external_nodes
                    .iter()
                    .find(|node| node.is_exit)
                    .map(ExitNodeStatus::from);

                let status_report = TelioStatusReport {
                    telio_is_running: telio.is_running(),
                    ip_address: interface_configurator.get_ip(),
                    exit_node,
                    external_nodes,
                };
                debug!("Telio status: {:#?}", status_report);
                if response_tx_channel.send(status_report).is_err() {
                    error!("Telio task failed sending status report")
                }
            }
            TelioTaskCmd::ConnectToExitNode(exit_node) => {
                interface_configurator
                    .set_exit_routes(
                        &exit_node
                            .endpoint
                            .ok_or(TeliodError::InvalidConfigOption {
                                key: "vpn: endpoint".to_owned(),
                                msg: "Couldn't get vpn endpoint".to_owned(),
                                value: format!("{:?}", config),
                            })?
                            .ip(),
                    )
                    .inspect_err(|e| {
                        error!("Failed to set routes for exit routing with error '{e:?}'")
                    })?;
                match telio.connect_exit_node(&exit_node) {
                    Ok(_) => {
                        info!("Connected to {exit_node:?}")
                    }
                    Err(e) => {
                        error!("Failed to connect to VPN with error: {e:?}");
                    }
                }
            }
            TelioTaskCmd::Quit => {
                telio.stop();
                _ = interface_configurator
                    .cleanup_exit_routes()
                    .inspect_err(|e| {
                        error!("Failed to cleanup routes for exit routing with error '{e:?}'")
                    });
                _ = interface_configurator
                    .cleanup_interface()
                    .inspect_err(|e| error!("Failed to cleanup interface with error '{e:?}'"));
                break;
            }
        }
    }

    Ok(())
}

fn task_connect_to_exit_node(exit_node: ExitNode, tx_channel: mpsc::Sender<TelioTaskCmd>) {
    #[allow(mpsc_blocking_send)]
    tokio::spawn(async move {
        _ = tx_channel
            .send(TelioTaskCmd::ConnectToExitNode(exit_node))
            .await
            .inspect_err(|e| error!("Failed to send connect to exit node event: {e:?}"));
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

pub async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<(), TeliodError> {
    debug!("started with config: {config:?}");

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

    let (telio_tx, telio_rx) = mpsc::channel(10);

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;
    let mut cmd_listener = CommandListener::new(socket, telio_tx.clone());

    let nordlynx_private_key = {
        let daemon_init_future = request_nordlynx_key(
            &config.authentication_token,
            &config.http_certificate_file_path,
        );
        pin_mut!(daemon_init_future);
        loop {
            select! {
                nordlynx_private_key = &mut daemon_init_future => break nordlynx_private_key?,
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

    let tx_clone = telio_tx.clone();
    let mut telio_task_handle = tokio::task::spawn_blocking(move || {
        telio_task(telio_rx, tx_clone, config, nordlynx_private_key)
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
