use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::uapi::{Cmd, Cmd::Get, Cmd::Set, Interface, Peer, Response};
#[cfg(windows)]
use crate::windows::service;
#[cfg(windows)]
use crate::windows::tunnel::interfacewatcher::InterfaceWatcher;
use async_trait::async_trait;
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::io::Error as IOError;
use std::slice::Windows;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use std::{mem, option, result};
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};
use telio_wireguard_traceroute::traceroute;
use tokio::time::sleep;
use uuid::Uuid;
use widestring::U16CStr;
#[cfg(windows)]
use wireguard_nt::{self, set_logger, SetInterface, SetPeer, WIREGUARD_STATE_UP};
use wireguard_uapi::xplatform;

use once_cell::sync::Lazy;
use tokio::sync::broadcast::{error::TryRecvError, Receiver, Sender};

use std::net::UdpSocket;

pub static SERVER_HANDSHAKE_NOTIFICATION: Lazy<Sender<Instant>> = Lazy::new(|| Sender::new(1000));

/// Telio wrapper around wireguard-nt
#[cfg(windows)]
pub struct WindowsNativeWg {
    // Object holding the adapter handle and associated wireguard functionality
    adapter: Arc<wireguard_nt::Adapter>,

    server_handshake_receiver: Receiver<Instant>,
    last_server_handshake_ts: Option<Instant>,
    last_listen_port_change_ts: Option<Instant>,
    traceroute: Option<(tokio::task::JoinHandle<()>, Instant)>,

    // Required for calling winipcfg API. Cannot be retrieved from the driver once the vNIC has failed / was removed.
    luid: u64,

    // Indicates whether the network configuration was cleaned up regularly
    // during Adapter::stop(), or needs to be done in drop()
    cleaned_up: Arc<Mutex<bool>>,
    watcher: Arc<Mutex<InterfaceWatcher>>,

    /// Configurable up/down behavior of WireGuard-NT adapter. See RFC LLT-0089 for details
    enable_dynamic_wg_nt_control: bool,
}

/// Error type implementation for wg-nt
/// #[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wireguard-nt: {0}")]
    Fail(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, PartialEq)]
enum AdapterState {
    Up,
    Down,
}

/// In this PoC experiment we would like to get notified
/// when WireGuard handshake fails, such that we could,
/// react more quickly and swap the port. This will likely
/// produce some false-positives, but it is ok for experiment
/// purposes.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn intercepting_logger(
    level: wireguard_nt::wireguard_nt_raw::WIREGUARD_LOGGER_LEVEL,
    _timestamp: wireguard_nt::wireguard_nt_raw::DWORD64,
    message: *const wireguard_nt::wireguard_nt_raw::WCHAR,
) {
    if message.is_null() {
        return;
    }
    //WireGuard will always give us a valid UTF16 null terminated string
    let msg = unsafe { U16CStr::from_ptr_str(message) };
    let utf8_msg = msg.to_string_lossy();

    if utf8_msg.contains("Receiving handshake initiation from peer") {
        telio_log_info!("wireguard_nt: Notifying about server-side handshake");
        let res = SERVER_HANDSHAKE_NOTIFICATION.send(Instant::now());
        telio_log_info!("wireguard_nt: Notification {:?}", res);
    };

    match level {
        wireguard_nt::wireguard_nt_raw::WIREGUARD_LOGGER_LEVEL_WIREGUARD_LOG_INFO => {
            telio_log_info!("wireguard_nt: {}", utf8_msg)
        }
        wireguard_nt::wireguard_nt_raw::WIREGUARD_LOGGER_LEVEL_WIREGUARD_LOG_WARN => {
            telio_log_warn!("wireguard_nt: {}", utf8_msg)
        }
        wireguard_nt::wireguard_nt_raw::WIREGUARD_LOGGER_LEVEL_WIREGUARD_LOG_ERR => {
            telio_log_error!("wireguard_nt: {}", utf8_msg)
        }
        _ => telio_log_error!(
            "wireguard_nt: {} (with invalid log level {})",
            utf8_msg,
            level
        ),
    }
}

// Windows native associated functions
#[cfg(windows)]
impl WindowsNativeWg {
    pub fn new(
        adapter: &Arc<wireguard_nt::Adapter>,
        luid: u64,
        watcher: &Arc<Mutex<InterfaceWatcher>>,
        enable_dynamic_wg_nt_control: bool,
    ) -> Self {
        Self {
            adapter: adapter.clone(),
            server_handshake_receiver: SERVER_HANDSHAKE_NOTIFICATION.subscribe(),
            last_server_handshake_ts: None,
            last_listen_port_change_ts: None,
            traceroute: None,
            luid,
            cleaned_up: Arc::new(Mutex::new(false)),
            watcher: watcher.clone(),
            enable_dynamic_wg_nt_control,
        }
    }

    fn get_adapter_guid_from_name_hash(name: &str) -> u128 {
        // Generate deterministic GUID from the adapter name.
        let mut hasher = Sha256::new();
        hasher.update(name);
        let hash = hasher.finalize();
        let mut guid_bytes: [u8; 16] = [0u8; 16];
        guid_bytes[..16].copy_from_slice(&hash[..16]);
        let guid: u128 = u128::from_ne_bytes(guid_bytes);
        guid
    }

    /// Returns a wireguard adapter with name `name`, loading dll from path 'path'
    ///
    /// # Errors
    /// Returns a wg-nt error if dll file couldn't be loaded or adapter couldn't be  created
    ///
    fn create(
        name: &str,
        path: &str,
        enable_dynamic_wg_nt_control: bool,
    ) -> Result<Self, AdapterError> {
        unsafe {
            // try to load dll
            match wireguard_nt::load_from_path(path) {
                Ok(wg_dll) => {
                    // Someone to watch over me while I sleep
                    let watcher = Arc::new(Mutex::new(InterfaceWatcher::new(
                        enable_dynamic_wg_nt_control,
                    )));

                    if let Ok(mut watcher) = watcher.lock() {
                        if let Err(monitoring_err) = watcher.start_monitoring() {
                            return Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                                "Failed to start watcher with err {monitoring_err}",
                            ))));
                        }
                    } else {
                        return Err(AdapterError::WindowsNativeWg(Error::Fail(
                            "error obtaining lock".into(),
                        )));
                    }

                    // Try to create a new adapter
                    let adapter_guid = Self::get_adapter_guid_from_name_hash(name);
                    telio_log_debug!(
                        "Try to create adapter for name: {:#?} with guid: {{{}}}",
                        name,
                        Uuid::from_u128(adapter_guid)
                            .hyphenated()
                            .to_string()
                            .to_uppercase()
                    );

                    // Adapter name and pool name must be the same, because netsh
                    // identifies interfaces by their pool name and not the adapter or device name.
                    // This replicates the behavior of Wireguard-Go adapter which relies on WinTun.sys.
                    // If the pool name does not match the passed adapter name, then netsh in the nat-lab
                    // tests won't be able to find this adapter and the tests will fail.
                    match wireguard_nt::Adapter::create(
                        wg_dll.clone(),
                        name,
                        name,
                        Some(adapter_guid),
                    ) {
                        Ok(raw_adapter) => {
                            let adapter = Arc::new(raw_adapter);
                            let luid = adapter.get_luid();
                            let wgnt = WindowsNativeWg::new(
                                &adapter,
                                luid,
                                &watcher,
                                enable_dynamic_wg_nt_control,
                            );

                            // set custom logger to enable intercepting failed handshake logs:
                            wireguard_nt::log::set_logger(&wg_dll, Some(intercepting_logger));

                            if let Ok(mut watcher) = watcher.lock() {
                                watcher.configure(wgnt.adapter.clone(), luid);
                                Ok(wgnt)
                            } else {
                                Err(AdapterError::WindowsNativeWg(Error::Fail(
                                    "error obtaining lock".into(),
                                )))
                            }
                        }
                        Err((e, _)) => Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                            "Failed to create adapter: {:?}",
                            e
                        )))),
                    }
                }
                Err(e) => Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                    "Failed to load wireguard dll: {:?}",
                    e
                )))),
            }
        }
    }

    /// Start adapter with name `name`
    ///
    ///
    /// # Errors
    /// Returns a wg-nt error if adapter couldn't be created or started
    ///
    pub async fn start(
        name: &str,
        enable_dynamic_wg_nt_control: bool,
    ) -> Result<Self, AdapterError> {
        let dll_path = "wireguard.dll";
        let wg_dev = Self::create(name, dll_path, enable_dynamic_wg_nt_control)?;
        telio_log_info!(
            "Adapter '{}' using created successfully. enable_dynamic_wg_nt_control: {}",
            name,
            enable_dynamic_wg_nt_control
        );
        if !service::wait_for_service("WireGuard", service::DEFAULT_SERVICE_WAIT_TIMEOUT) {
            return Err(AdapterError::WindowsNativeWg(Error::Fail(
                "WireGuard service not running".to_string(),
            )));
        }

        if !wg_dev
            .adapter
            .set_logging(wireguard_nt::AdapterLoggingLevel::OnWithPrefix)
        {
            let os_error = IOError::last_os_error();
            return Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                "Failed to set logging for adapter, last error: {os_error:?}",
            ))));
        }

        if !wg_dev.enable_dynamic_wg_nt_control {
            wg_dev.ensure_adapter_state(AdapterState::Up).await?;
        }

        Ok(wg_dev)
    }

    async fn spawn_traceroute(&mut self, old_itf: Interface) -> Result<(), Error> {
        // First collect some necessary info
        telio_log_debug!("Spawning traceroute: {old_itf:?}");

        let traceroute_handle = tokio::task::spawn(async move {
            let source_port = old_itf.listen_port;
            let vpn_peer = if let Some(peer) = old_itf.peers.first_key_value().map(|(_, p)| p) {
                peer
            } else {
                telio_log_debug!("No Peer for traceroute");
                return;
            };

            let dest = if let Some(endpoint) = vpn_peer.endpoint {
                endpoint
            } else {
                telio_log_debug!("No Endpoint for traceroute");
                return;
            };

            let self_private_key = if let Some(sk) = old_itf.private_key {
                sk
            } else {
                telio_log_debug!("No key for traceroute");
                return;
            };

            let peer_public_key = vpn_peer.public_key;
            let first_ttl = 1;
            let max_ttl = 20;
            let queries = 2;
            let wait = Duration::from_secs(5);

            let report = traceroute(
                source_port,
                &dest,
                self_private_key.as_bytes(),
                &peer_public_key.0,
                first_ttl,
                max_ttl,
                queries,
                wait,
            )
            .await;

            match report {
                Ok(report) => telio_log_info!("{report}"),
                Err(e) => {
                    telio_log_debug!("traceroute failed: {e:?}");
                    return;
                }
            }
        });

        self.traceroute = Some((traceroute_handle, Instant::now()));

        Ok(())
    }

    async fn trigger_listen_port_change(&mut self, config: Response) -> Result<(), Error> {
        telio_log_debug!("Triggering listen_port change");

        // Guard against invalid config
        if config.errno != 0 {
            return Err(Error::Fail("Unsuccesfull config errno".to_string()));
        };

        let mut itf = if let Some(itf) = config.interface {
            itf
        } else {
            return Err(Error::Fail("Empty config".to_string()));
        };

        // The following is an oportunistic opproach
        // at acquiring port which is free on the OS.
        //
        // Yes, it is racy. But the whole initiative
        // here is an experiment, hence for experiment
        // purposes it should be good enough.
        //
        // The working principle is the following:
        //  1. create a IPv4 UDP socket, bind it to
        //     0.0.0.0 with unspecified port
        //  2. the close the port
        //  3. in quick succession issue set config
        //     UAPI command
        //
        //  and hope that in the steps between 2 and 3rd
        //  there was no other process which took this
        //  port.
        let ephemeral_socket = UdpSocket::bind("0.0.0.0:0")?;
        let assigned_port = ephemeral_socket.local_addr()?.port();
        let old_itf = itf.clone();
        drop(ephemeral_socket);

        // Now attempt to change the listen-port in WG-NT
        telio_log_debug!(
            "Attempting to change WG listen port from {:?} to {:?}",
            itf.listen_port,
            assigned_port
        );
        itf.listen_port = Some(assigned_port);

        self.send_uapi_cmd(&Cmd::Set(itf.into()))
            .await
            .map_err(|e| Error::Fail(format!("Adapter error: {:?}", e)))?;

        self.last_listen_port_change_ts = Some(Instant::now());

        // If traceroute is finished or running for too long - drop it.
        if let Some((task, ts)) = &self.traceroute {
            if task.is_finished() {
                telio_log_debug!(
                    "Last traceroute info: {:?} {:?}",
                    task.is_finished(),
                    ts.elapsed()
                );
                self.traceroute.take();
            } else if ts.elapsed() > Duration::from_secs(10 * 60) {
                task.abort();
                self.traceroute.take();
            }
        }

        // Spawn new traceroute if there is non running already
        if self.traceroute.is_none() {
            self.spawn_traceroute(old_itf).await?;
        }

        Ok(())
    }

    async fn get_config_uapi(&mut self) -> Response {
        let resp = match self.adapter.get_config_uapi() {
            Ok(device) => Response {
                errno: 0,
                interface: Some(Interface::from(device)),
            },
            Err(_) => Response {
                errno: 1,
                interface: None,
            },
        };

        // This function is called periodically, hence
        // we can check how many server-side handshakes
        // do we have and estimate the rate of those
        // handshakes.
        // If this rate is above 0.1 h/s - we can trigger
        // listen-port change
        match (
            self.last_server_handshake_ts,
            self.server_handshake_receiver.try_recv(),
        ) {
            (Some(last_hs_ts), Ok(hs_ts)) => {
                // Throttle listen-port change to no more than one per 30s
                if self
                    .last_listen_port_change_ts
                    .map(|ts| ts.elapsed() > Duration::from_secs(30))
                    .unwrap_or(true)
                {
                    let diff = hs_ts - last_hs_ts;
                    telio_log_debug!(
                        "Received second server-side handshake indicating, time diff: {:?}",
                        diff
                    );
                    if diff < Duration::from_secs(10) {
                        let res = self.trigger_listen_port_change(resp.clone()).await;
                        telio_log_debug!("listen_port_change resulted in {:?}", res);
                    }
                } else {
                    telio_log_debug!(
                        "Skipping listen_port change due to one performed just recently"
                    );
                }

                self.last_server_handshake_ts = Some(hs_ts);
            }
            (None, Ok(hs_ts)) => {
                telio_log_debug!("First server-side handshake");
                self.last_server_handshake_ts = Some(hs_ts);
            }
            (None, Err(TryRecvError::Empty)) => {} //Empty notifications is not interesting enough
            // to be logged
            (None, Err(e)) => {
                telio_log_debug!("Received error from server-side handshake monitor: {:?}", e);
            }
            (_, _) => {}
        }

        resp
    }

    /// Ensure adapter state (up/down)
    ///
    /// `ensure_adapter_state` attempts to bring interface up (requested_state == true) if
    /// it is requested to be up and is not already up. Or bring it down if it is requested
    /// to be down, but adapter is not yet down.
    ///
    /// As one may expect - this function is idempotent.
    async fn ensure_adapter_state(
        &self,
        want_adapter_state: AdapterState,
    ) -> Result<(), AdapterError> {
        // We have seen a few cases where single attempt to bring
        // The adapter up caused some issues. Especially if performed
        // Early after driver installation.
        // Exact root cause is not yet found, therefore lets attempt to bring
        // The interface up for slightly longer before declaring error.
        //
        // See LLT-5443 for more details
        let mut os_error = IOError::from_raw_os_error(0);
        for _ in 0..5 {
            // Retrieve up/down state of the adapter
            let have_adapter_state = match self.adapter.get_adapter_state() {
                Ok(state) => {
                    if state == WIREGUARD_STATE_UP {
                        AdapterState::Up
                    } else {
                        AdapterState::Down
                    }
                }
                Err(_) => {
                    os_error = IOError::last_os_error();
                    telio_log_warn!("Failed to get adapter state, last error: {os_error:?}");
                    continue;
                }
            };

            // Make this function idempotent
            if want_adapter_state == have_adapter_state {
                return Ok(());
            }

            telio_log_debug!(
                "Attempting to bring interface {:?}, currently it is: {:?}, enable_dynamic_wg_nt_control: {:?}",
                want_adapter_state,
                have_adapter_state,
                self.enable_dynamic_wg_nt_control
            );

            // The wireguard-nt-rust-wrapper here indicates success using
            // bool for `.up()` or `.down()` functions
            let success = match want_adapter_state {
                AdapterState::Up => self.adapter.up(),
                AdapterState::Down => self.adapter.down(),
            };

            // Terminate if we succeeded
            if success {
                return Ok(());
            }

            // Continue if we failed
            os_error = IOError::last_os_error();
            telio_log_warn!(
                "Failed to set adapter state to {want_adapter_state:?}, last error: {os_error:?}"
            );
            sleep(Duration::from_millis(200)).await;
        }
        telio_log_error!("Failed to set adapter state for 5 times. Giving up!");
        Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
            "Failed to set adapter's state to {want_adapter_state:?}, last error: {os_error:?}",
        ))))
    }

    fn cleanup(&self) {
        // Clean up like in InterfaceWatcher::Destroy() in /3rd-party/wireguard-go/interfacewatcher_windows.go
        if let Ok(mut cleaned_up) = self.cleaned_up.clone().lock() {
            if !*cleaned_up {
                telio_log_info!("wg-nt: net cfg cleanup start");
                crate::windows::cleanup::cleanup_network_config(self.luid);
                *cleaned_up = true;
                telio_log_info!("wg-nt: net cfg cleanup done");
            } else {
                telio_log_info!("wg-nt: net cfg already cleaned up");
            }
        }
    }
}

#[cfg(windows)]
#[async_trait::async_trait]
impl Adapter for WindowsNativeWg {
    async fn send_uapi_cmd(&mut self, cmd: &Cmd) -> Result<Response, AdapterError> {
        match cmd {
            Get => Ok(self.get_config_uapi().await),
            Set(set_cfg) => {
                // If we have any peers added -> bring the adapter up
                if self.enable_dynamic_wg_nt_control && !set_cfg.peers.is_empty() {
                    self.ensure_adapter_state(AdapterState::Up).await?;
                }

                let (resp, peer_cnt) = match self
                    .adapter
                    .set_config_uapi(set_cfg)
                    .map_err(|_| AdapterError::InternalError("Failed to set config"))
                {
                    Ok(()) => {
                        // Remember last successfully set configuration
                        if let Ok(mut interface_watcher) =
                            (self as &WindowsNativeWg).watcher.clone().lock()
                        {
                            interface_watcher.set_last_known_configuration(set_cfg);
                        }

                        let resp = self.get_config_uapi().await;
                        let peer_cnt = resp.interface.as_ref().map(|i| i.peers.len());
                        (Ok(resp), peer_cnt)
                    }
                    Err(_err) => (
                        Ok(Response {
                            errno: 1,
                            interface: None,
                        }),
                        None,
                    ),
                };

                // If all of the peers has been removed -> bring the adapter down
                if self.enable_dynamic_wg_nt_control && peer_cnt.map(|p| p == 0).unwrap_or(false) {
                    self.ensure_adapter_state(AdapterState::Down).await?;
                }

                resp
            }
        }
    }

    fn get_adapter_luid(&self) -> u64 {
        self.luid
    }

    async fn stop(&self) {
        telio_log_info!("wg-nt: stopping adapter");
        // Clear last known configuration and stop watcher
        if let Ok(mut interface_watcher) = self.watcher.clone().lock() {
            interface_watcher.clear_last_known_configuration();
            interface_watcher.stop();
        }
        self.adapter.down();
        self.cleanup();
    }
}

#[cfg(windows)]
impl Drop for WindowsNativeWg {
    fn drop(&mut self) {
        self.cleanup();
        telio_log_info!("wg-nt: deleting adapter: done");
    }
}
