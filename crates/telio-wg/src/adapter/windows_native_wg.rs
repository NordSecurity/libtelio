use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::uapi::{Cmd, Cmd::Get, Cmd::Set, Interface, Peer, Response};
#[cfg(windows)]
use crate::windows::service;
#[cfg(windows)]
use crate::windows::tunnel::interfacewatcher::InterfaceWatcher;
use async_trait::async_trait;
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::slice::Windows;
use std::sync::{Arc, Mutex, MutexGuard};
use std::{mem, option, result};
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};
#[cfg(windows)]
use wireguard_nt::{self, set_logger, SetInterface, SetPeer};
use wireguard_uapi::xplatform;

/// Telio wrapper around wireguard-nt
#[cfg(windows)]
pub struct WindowsNativeWg {
    // Object holding the adapter handle and associated wireguard functionality
    adapter: Arc<wireguard_nt::Adapter>,

    // Required for calling winipcfg API. Cannot be retrieved from the driver once the vNIC has failed / was removed.
    luid: u64,

    // Indicates whether the network configuration was cleaned up regularly
    // during Adapter::stop(), or needs to be done in drop()
    cleaned_up: Arc<Mutex<bool>>,
    watcher: Arc<Mutex<InterfaceWatcher>>,
}

/// Error type implementation for wg-nt
/// #[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wireguard-nt: {0}")]
    Fail(String),
}

// Windows native associated functions
#[cfg(windows)]
impl WindowsNativeWg {
    pub fn new(
        adapter: &Arc<wireguard_nt::Adapter>,
        luid: u64,
        watcher: &Arc<Mutex<InterfaceWatcher>>,
    ) -> Self {
        Self {
            adapter: adapter.clone(),
            luid,
            cleaned_up: Arc::new(Mutex::new(false)),
            watcher: watcher.clone(),
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

    /// Returns a wireguard adapter inside the pool `pool` with name `name`, loading dll from path 'path'
    ///
    /// # Errors
    /// Returns a wg-nt error if dll file couldn't be loaded or adapter couldn't be  created
    ///
    fn create(pool: &str, name: &str, path: &str) -> Result<Self, AdapterError> {
        unsafe {
            // try to load dll
            match wireguard_nt::load_from_path(path) {
                Ok(wg_dll) => {
                    // Someone to watch over me while I sleep
                    let watcher = Arc::new(Mutex::new(InterfaceWatcher::new()));
                    if let Ok(mut watcher) = watcher.lock() {
                        if let Err(monitoring_err) = watcher.start_monitoring() {
                            return Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                                "Failed to start watcher with err {}",
                                monitoring_err
                            ))));
                        }
                    } else {
                        return Err(AdapterError::WindowsNativeWg(Error::Fail(
                            "error obtaining lock".into(),
                        )));
                    }

                    // Try to create a new adapter
                    let adapter_guid = Self::get_adapter_guid_from_name_hash(name);
                    match wireguard_nt::Adapter::create(wg_dll, pool, name, Some(adapter_guid)) {
                        Ok(raw_adapter) => {
                            let adapter = Arc::new(raw_adapter);
                            let luid = adapter.get_luid();
                            let wgnt = WindowsNativeWg::new(&adapter, luid, &watcher);
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
    /// `_tun` is unused for Windows and might be set to `None`
    ///
    /// # Errors
    /// Returns a wg-nt error if adapter couldn't be created or started
    ///
    pub fn start(name: &str, _tun: Option<NativeTun>) -> Result<Self, AdapterError> {
        // Adapter name and pool name must be the same, because netsh
        // identifies interfaces by their pool name and not the adapter or device name.
        // This replicates the behavior of Wireguard-Go adapter which relies on WinTun.sys.
        // If the pool name does not match the passed adapter name, then netsh in the nat-lab
        // tests won't be able to find this adapter and the tests will fail.
        //let pool = "WireGuard";
        let pool = name;
        let dll_path = "wireguard.dll";
        let wg_dev = Self::create(pool, name, dll_path)?;
        telio_log_info!("Adapter '{}' created successfully", name);
        if !service::wait_for_service("WireGuard", service::DEFAULT_SERVICE_WAIT_TIMEOUT) {
            return Err(AdapterError::WindowsNativeWg(Error::Fail(
                "WireGuard service not running".to_string(),
            )));
        }
        if !wg_dev
            .adapter
            .set_logging(wireguard_nt::AdapterLoggingLevel::OnWithPrefix)
        {
            return Err(AdapterError::WindowsNativeWg(Error::Fail(
                "Failed to set logging for adapter".to_string(),
            )));
        }
        if !wg_dev.adapter.up() {
            return Err(AdapterError::WindowsNativeWg(Error::Fail(
                "Failed to start adapter".to_string(),
            )));
        }
        Ok(wg_dev)
    }

    fn get_config_uapi(&self) -> Response {
        match self.adapter.get_config_uapi() {
            Ok(device) => Response {
                errno: 0,
                interface: Some(Interface::from(device)),
            },
            Err(win32_error) => Response {
                errno: win32_error as i32,
                interface: None,
            },
        }
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
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> Result<Response, AdapterError> {
        match cmd {
            Get => Ok(self.get_config_uapi()),
            Set(set_cfg) => match self.adapter.set_config_uapi(set_cfg) {
                Ok(()) => {
                    // Remember last successfully set configuration
                    if let Ok(mut interface_watcher) =
                        (self as &WindowsNativeWg).watcher.clone().lock()
                    {
                        interface_watcher.set_last_known_configuration(set_cfg);
                    }

                    Ok(self.get_config_uapi())
                }
                Err(_err) => Ok(Response {
                    errno: 1,
                    interface: None,
                }),
            },
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
