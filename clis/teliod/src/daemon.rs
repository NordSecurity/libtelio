use futures::stream::StreamExt;
use nix::libc::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use nix::sys::signal::Signal;
use signal_hook_tokio::Signals;
use std::{fs, sync::Arc};
use telio::{
    crypto::SecretKey,
    device::{Device, DeviceConfig, Error as DeviceError},
    telio_model::{config::Config as MeshMap, features::Features},
    telio_utils::select,
    telio_wg::AdapterType,
};
use tokio::{sync::mpsc, sync::oneshot, time::Duration};
use tracing::{debug, error, info, trace};

use crate::core_api::{get_meshmap as get_meshmap_from_server, init_with_api};
use crate::{
    command_listener::CommandListener, comms::DaemonSocket, config::DeviceIdentity,
    config::TeliodDaemonConfig, nc::NotificationCenter, TelioStatusReport, TeliodError,
};

#[derive(Debug)]
pub enum TelioTaskCmd {
    // Command to set the downloaded meshmap to telio instance
    UpdateMeshmap(MeshMap),
    // Get telio status
    GetStatus(oneshot::Sender<TelioStatusReport>),
    // Break the receive loop to quit the daemon and exit gracefully
    Quit,
}

const EMPTY_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// From async context Telio needs to be run in separate task
fn telio_task(
    node_identity: Arc<DeviceIdentity>,
    auth_token: Arc<String>,
    mut rx_channel: mpsc::Receiver<TelioTaskCmd>,
    tx_channel: mpsc::Sender<TelioTaskCmd>,
    interface_name: &str,
) -> Result<(), TeliodError> {
    debug!("Initializing telio device");
    let mut telio = Device::new(
        Features::default(),
        // TODO: replace this with some real event handling
        move |event| info!("Incoming event: {:?}", event),
        None,
    )?;

    // TODO: This is temporary to be removed later on when we have proper integration
    // tests with core API. This is to not look for tokens in a test environment
    // right now as the values are dummy and program will not run as it expects
    // real tokens.
    if !auth_token.as_str().eq("") {
        start_telio(&mut telio, node_identity.private_key, interface_name)?;
        task_retrieve_meshmap(node_identity, auth_token, tx_channel);

        while let Some(cmd) = rx_channel.blocking_recv() {
            info!("Got command {:?}", cmd);
            match cmd {
                TelioTaskCmd::UpdateMeshmap(map) => {
                    if let Err(e) = telio.set_config(&Some(map)) {
                        error!("Unable to set meshmap due to {e}");
                    }
                }
                TelioTaskCmd::GetStatus(response_tx_channel) => {
                    let status_report = TelioStatusReport {
                        is_running: telio.is_running(),
                        nodes: telio.external_nodes()?,
                    };
                    debug!("Telio status: {:#?}", status_report);
                    if response_tx_channel.send(status_report).is_err() {
                        error!("Telio task failed sending status report")
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

fn start_telio(
    telio: &mut Device,
    private_key: SecretKey,
    interface_name: &str,
) -> Result<(), DeviceError> {
    telio.start(&DeviceConfig {
        private_key,
        name: Some(interface_name.to_owned()),
        adapter: AdapterType::BoringTun,
        ..Default::default()
    })?;

    debug!("started telio with {:?}...", AdapterType::BoringTun,);
    Ok(())
}

pub async fn daemon_event_loop(config: TeliodDaemonConfig) -> Result<(), TeliodError> {
    let (non_blocking_writer, _tracing_worker_guard) =
        tracing_appender::non_blocking(fs::File::create(&config.log_file_path)?);
    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    debug!("started with config: {config:?}");

    let socket = DaemonSocket::new(&DaemonSocket::get_ipc_socket_path()?)?;

    let nc = NotificationCenter::new(&config).await?;

    // Tx is unused here, but this channel can be used to communicate with the
    // telio task
    let (tx, rx) = mpsc::channel(10);
    let mut cmd_listener = CommandListener::new(socket, tx.clone());

    // TODO: This if condition and ::default call is temporary to be removed later
    // on when we have proper integration tests with core API.
    // This is to not look for tokens in a test environment right now as the values
    // are dummy and program will not run as it expects real tokens.
    let mut identity = DeviceIdentity::default();
    if !config.authentication_token.eq(EMPTY_TOKEN) {
        identity = init_with_api(&config.authentication_token, &config.interface_name).await?;
    }
    let tx_clone = tx.clone();

    let token_ptr = Arc::new(config.authentication_token);
    let token_clone = token_ptr.clone();

    let identity_ptr = Arc::new(identity);
    let identity_clone = identity_ptr.clone();

    let mut telio_task_handle = tokio::task::spawn_blocking(move || {
        telio_task(
            identity_clone,
            token_clone,
            rx,
            tx_clone,
            &config.interface_name,
        )
    });

    let tx_clone = tx.clone();
    nc.add_callback(Arc::new(move |_am| {
        task_retrieve_meshmap(identity_ptr.clone(), token_ptr.clone(), tx_clone.clone());
    }))
    .await;

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;

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
                        info!("Client command {:?} executed succesfully", command);
                    }
                    Err(err) => {
                        break Err(err);
                    }
                }
            },
            // Handle interrupt signals for clean shutdown
            signal = signals.next() => {
                match signal {
                    Some(s @ SIGHUP | s @ SIGTERM | s @ SIGINT | s @ SIGQUIT) => {
                        info!("Received signal {:?}, exiting", Signal::try_from(s));
                        if let Err(e) = tx.send_timeout(TelioTaskCmd::Quit, Duration::from_secs(2)).await {
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
