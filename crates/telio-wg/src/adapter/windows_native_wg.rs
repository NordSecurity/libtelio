use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::{
    uapi::{Cmd, Cmd::Get, Cmd::Set, Interface, Peer, Response},
    windows::{service, tunnel::interfacewatcher::InterfaceWatcher},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Error as IOError,
    mem, option,
    ptr::{self, null},
    result,
    slice::Windows,
    sync::{Arc, Mutex},
    time::Duration,
};

use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};
use tokio::time::sleep;
use utf16_lit::utf16_null;
use uuid::Uuid;
use windows::core::GUID;
use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::GUID_DEVCLASS_NET;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Status, SetupDiCallClassInstaller, SetupDiEnumDeviceInfo,
    SetupDiGetDeviceRegistryPropertyW, SetupDiSetClassInstallParamsW, CM_DEVNODE_STATUS_FLAGS,
    CM_PROB, CR_SUCCESS, DIF_REMOVE, DI_REMOVEDEVICE_GLOBAL, DN_HAS_PROBLEM, SPDRP_FRIENDLYNAME,
    SP_CLASSINSTALL_HEADER, SP_REMOVEDEVICE_PARAMS,
};
use windows::Win32::NetworkManagement::Ndis::GUID_DEVINTERFACE_NET;
use winreg::{enums::*, RegKey, HKEY};
use wireguard_nt::{
    self, set_logger, Error as WireGuardNTError, SetInterface, SetPeer, WIREGUARD_STATE_UP,
};
use wireguard_uapi::xplatform;

const REMOVAL_SLEEP_SECS: u64 = 2;

/// Telio wrapper around wireguard-nt
pub struct WindowsNativeWg {
    // Object holding the adapter handle and associated wireguard functionality
    adapter: Arc<wireguard_nt::Adapter>,

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
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wireguard-nt: {0}")]
    Fail(String),
}

#[derive(Debug, PartialEq)]
enum AdapterState {
    Up,
    Down,
}

// Windows native associated functions
impl WindowsNativeWg {
    pub fn new(
        adapter: &Arc<wireguard_nt::Adapter>,
        luid: u64,
        watcher: &Arc<Mutex<InterfaceWatcher>>,
        enable_dynamic_wg_nt_control: bool,
    ) -> Self {
        Self {
            adapter: adapter.clone(),
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
        #[allow(clippy::indexing_slicing)]
        {
            guid_bytes[..16].copy_from_slice(&hash[..16]);
        }
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
    ) -> std::result::Result<Self, AdapterError> {
        // try to load dll
        match unsafe { wireguard_nt::load_from_path(path) } {
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
                match wireguard_nt::Adapter::create(&wg_dll, name, name, Some(adapter_guid)) {
                    Ok(raw_adapter) => {
                        let adapter = Arc::new(raw_adapter);
                        let luid = adapter.get_luid();
                        let wgnt = WindowsNativeWg::new(
                            &adapter,
                            luid,
                            &watcher,
                            enable_dynamic_wg_nt_control,
                        );
                        if let Ok(mut watcher) = watcher.lock() {
                            watcher.configure(wgnt.adapter.clone(), luid);
                            Ok(wgnt)
                        } else {
                            Err(AdapterError::WindowsNativeWg(Error::Fail(
                                "error obtaining lock".into(),
                            )))
                        }
                    }
                    Err(e) => Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                        "Failed to create adapter: {e:?}",
                    )))),
                }
            }
            Err(e) => Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                "Failed to load wireguard dll: {e:?}",
            )))),
        }
    }

    /// Remove orphaned WireGuard-NT devices from the system device list.
    ///
    /// This is a partial Rust port of `AdapterCleanupOrphanedDevices` from
    /// WireGuard-NT's `api/adapter.c`. It enumerates all `GUID_DEVCLASS_NET`
    /// devices created by the WireGuard software enumerator and removes any
    /// whose devnode has `DN_HAS_PROBLEM` set.
    async fn cleanup_orphaned_devices() {
        unsafe {
            // Get list of all WireGuard network adapters.
            let enumerator_utf16 = utf16_null!(service::WIREGUARD_ENUMERATOR);

            let mut dev_info_set = match service::ScopedDeviceInfoSet::from_class_devs_ex(
                Some(&GUID_DEVCLASS_NET),
                PCWSTR(enumerator_utf16.as_ptr()),
                Default::default(),
                None,
            ) {
                Ok(dev_info_set) => dev_info_set,
                Err(e) => {
                    telio_log_warn!("Failed to get adapters for orphaned device cleanup: {e:?}");
                    return;
                }
            };

            let dev_info_handle = match dev_info_set.handle {
                Some(h) => h,
                None => {
                    telio_log_warn!("Device info set handle is None");
                    return;
                }
            };

            let mut index: u32 = 0;
            const FRIENDLY_NAME_BUF_WCHARS: usize = 260;
            let mut name_buf = [0u8; FRIENDLY_NAME_BUF_WCHARS * 2];
            let mut removed = false;

            loop {
                if SetupDiEnumDeviceInfo(dev_info_handle, index, &mut dev_info_set.dev_info_data)
                    .is_err()
                {
                    break;
                }

                // Skip devices that are not marked as having problems.
                let mut status = CM_DEVNODE_STATUS_FLAGS(0);
                let mut code = CM_PROB(0);
                if CM_Get_DevNode_Status(
                    &mut status,
                    &mut code,
                    dev_info_set.dev_info_data.DevInst,
                    0,
                ) == CR_SUCCESS
                    && (status.0 & DN_HAS_PROBLEM.0) == 0
                {
                    index += 1;
                    continue;
                }

                // Best-effort: fetch device friendly name for logging.
                let name = if SetupDiGetDeviceRegistryPropertyW(
                    dev_info_handle,
                    &dev_info_set.dev_info_data,
                    SPDRP_FRIENDLYNAME,
                    None,
                    Some(&mut name_buf),
                    None,
                )
                .is_ok()
                {
                    let w = std::slice::from_raw_parts(
                        name_buf.as_ptr() as *const u16,
                        FRIENDLY_NAME_BUF_WCHARS,
                    );
                    let end = w
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(FRIENDLY_NAME_BUF_WCHARS);
                    let s = w
                        .get(..end)
                        .map(|s| String::from_utf16_lossy(s).trim().to_string())
                        .unwrap_or_default();
                    if s.is_empty() {
                        format!("devinst {}", dev_info_set.dev_info_data.DevInst)
                    } else {
                        s
                    }
                } else {
                    format!("devinst {}", dev_info_set.dev_info_data.DevInst)
                };

                let remove_params = SP_REMOVEDEVICE_PARAMS {
                    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                        cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                        InstallFunction: DIF_REMOVE,
                    },
                    Scope: DI_REMOVEDEVICE_GLOBAL,
                    HwProfile: 0,
                };

                let set_ok = SetupDiSetClassInstallParamsW(
                    dev_info_handle,
                    Some(&dev_info_set.dev_info_data),
                    Some(&remove_params.ClassInstallHeader),
                    std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
                )
                .is_ok();

                let call_ok = set_ok
                    && SetupDiCallClassInstaller(
                        DIF_REMOVE,
                        dev_info_handle,
                        Some(&dev_info_set.dev_info_data),
                    )
                    .is_ok();

                if !call_ok {
                    telio_log_warn!(
                        "Failed to remove orphaned WireGuard adapter \"{}\": {:?}",
                        name,
                        IOError::last_os_error()
                    );
                    index += 1;
                    continue;
                }
                removed = true;

                telio_log_info!("Removed orphaned WireGuard adapter \"{}\"", name);
                index += 1;
            }

            if removed {
                // TODO: Remove this sleep once we have a better way to track device removal/insertion
                // Note: windows messages (e.g. WM_DEVICECHANGE) cannot be used to track removal,
                // since those  messages does not arrive,
                // when we trigger removal and wait for messages on same thread
                std::thread::sleep(Duration::from_secs(REMOVAL_SLEEP_SECS));
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
    ) -> std::result::Result<Self, AdapterError> {
        const SWD_WIREGUARD: &str = r"SYSTEM\CurrentControlSet\Enum\SWD\WireGuard";
        telio_log_debug!("Print registry before adapter creation!");
        Self::print_registry_key_contents(HKEY_LOCAL_MACHINE, service::GUID_DEVINTERFACE_NET_STR);
        Self::print_registry_key_contents(HKEY_LOCAL_MACHINE, SWD_WIREGUARD);

        // Cleaning orphaned WireGuard-NT adapters inside the driver can be racey,
        // so we do it in a separate step, before creating a new adapter
        Self::cleanup_orphaned_devices().await;

        let dll_path = "wireguard.dll";
        let tmp_wg_dev = Self::create(name, dll_path, enable_dynamic_wg_nt_control);

        telio_log_debug!("Print registry after adapter creation!");
        Self::print_registry_key_contents(HKEY_LOCAL_MACHINE, service::GUID_DEVINTERFACE_NET_STR);
        Self::print_registry_key_contents(HKEY_LOCAL_MACHINE, SWD_WIREGUARD);

        let wg_dev = tmp_wg_dev?;
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

        if !service::wait_for_adapter_interface_ready(
            wg_dev.get_adapter_luid(),
            service::DEFAULT_SERVICE_WAIT_TIMEOUT,
        )
        .await
        {
            // TODO: Should we fail here if adapter interface is not ready?
            return Err(AdapterError::WindowsNativeWg(Error::Fail(
                "Adapter interface not ready".to_string(),
            )));
        }

        if !wg_dev.enable_dynamic_wg_nt_control {
            wg_dev.ensure_adapter_state(AdapterState::Up).await?;
        }

        Ok(wg_dev)
    }

    fn get_config_uapi(&self) -> Response {
        match self.adapter.get_config_uapi() {
            Ok(device) => Response {
                errno: 0,
                interface: Some(Interface::from(device)),
            },
            Err(win32_error) => {
                // get_config_uapi returns os errors so this should be okay
                let errno = match win32_error {
                    WireGuardNTError::Driver(e) => e.raw_os_error().unwrap_or_else(|| {
                        telio_log_warn!("Failed to get raw OS error, using default -1");
                        -1
                    }),
                    _ => -1,
                };
                Response {
                    errno,
                    interface: None,
                }
            }
        }
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
    ) -> std::result::Result<(), AdapterError> {
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
            if success.is_ok() {
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

    fn hive_to_str(hive: HKEY) -> &'static str {
        match hive {
            HKEY_LOCAL_MACHINE => "HKEY_LOCAL_MACHINE",
            HKEY_CURRENT_USER => "HKEY_CURRENT_USER",
            HKEY_CLASSES_ROOT => "HKEY_CLASSES_ROOT",
            HKEY_USERS => "HKEY_USERS",
            HKEY_CURRENT_CONFIG => "HKEY_CURRENT_CONFIG",
            _ => "UNKNOWN_HIVE",
        }
    }

    fn print_registry_key_contents(hive: HKEY, path: &str) {
        let root = RegKey::predef(hive);
        let key = match root.open_subkey(path) {
            Err(e) => {
                telio_log_debug!("Failed to open subkey {}! Err: {}", path, e);
                return;
            }
            Ok(key) => key,
        };

        telio_log_debug!("Path: {}\\{}", Self::hive_to_str(hive), path);

        for name_result in key.enum_keys() {
            let name = match name_result {
                Ok(n) => n,
                Err(e) => {
                    telio_log_error!("Failed to enumerate subkey: {}", e);
                    continue;
                }
            };

            telio_log_debug!("Subkey: {}", name);

            let subkey = match key.open_subkey(&name) {
                Ok(sk) => sk,
                Err(e) => {
                    telio_log_error!("   Failed to open subkey '{}': {}", name, e);
                    continue;
                }
            };

            for value_result in subkey.enum_values() {
                match value_result {
                    Ok((val_name, val_data)) => {
                        telio_log_debug!("   {} = {:?}", val_name, val_data);
                    }
                    Err(e) => telio_log_error!("   Failed to read value: {}", e),
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Adapter for WindowsNativeWg {
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> std::result::Result<Response, AdapterError> {
        match cmd {
            Get => Ok(self.get_config_uapi()),
            Set(set_cfg) => {
                // If we have any peers added -> bring the adapter up
                if self.enable_dynamic_wg_nt_control && !set_cfg.peers.is_empty() {
                    self.ensure_adapter_state(AdapterState::Up).await?;
                }

                let (resp, peer_cnt) = match self.adapter.set_config_uapi(set_cfg) {
                    Ok(()) => {
                        // Remember last successfully set configuration
                        if let Ok(mut interface_watcher) =
                            (self as &WindowsNativeWg).watcher.clone().lock()
                        {
                            interface_watcher.set_last_known_configuration(set_cfg);
                        }

                        let resp = self.get_config_uapi();
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
        if let Err(e) = self.adapter.down() {
            telio_log_warn!("Failure to turn off adapter {e}");
        }
        self.cleanup();
    }

    async fn set_tun(&self, _tun: super::Tun) -> std::result::Result<(), AdapterError> {
        Err(AdapterError::UnsupportedAdapter)
    }

    fn clone_box(&self) -> Option<Box<dyn Adapter>> {
        None
    }
}

impl Drop for WindowsNativeWg {
    fn drop(&mut self) {
        self.cleanup();
        telio_log_info!("wg-nt: deleting adapter: done");
    }
}
