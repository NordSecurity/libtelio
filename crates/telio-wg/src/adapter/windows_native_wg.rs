use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::uapi::{Cmd, Cmd::Get, Cmd::Set, Interface, Peer, Response};
#[cfg(windows)]
use crate::windows::service;
#[cfg(windows)]
use crate::windows::tunnel::interfacewatcher::InterfaceWatcher;
use async_trait::async_trait;
#[cfg(windows)]
use get_adapters_addresses::{AdaptersAddresses, Family, Flags, Result as AdaptersAddressesResult};
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::io::Error as IOError;
use std::slice::Windows;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use std::{mem, option, result};
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};
use tokio::time::sleep;
#[cfg(windows)]
use uuid::Uuid;
#[cfg(windows)]
use windows::{Win32::Foundation::*, Win32::NetworkManagement::IpHelper::*};
#[cfg(windows)]
use winreg::{enums::*, RegKey, HKEY};
#[cfg(windows)]
use wireguard_nt::{
    self, set_logger, Error as WireGuardNTError, SetInterface, SetPeer,
    Wireguard as WireGuardHandle, WIREGUARD_STATE_UP,
};
use wireguard_uapi::xplatform;

macro_rules! form_wgnt_adapter {
    ($raw_adapter:expr, $watcher:expr, $enable_dynamic_wg_nt_control:expr) => {{
        let adapter = Arc::new(($raw_adapter));
        let luid = adapter.get_luid();
        let wgnt = WindowsNativeWg::new(&adapter, luid, &($watcher), $enable_dynamic_wg_nt_control);

        if let Ok(mut watcher_guard) = ($watcher).lock() {
            watcher_guard.configure(wgnt.adapter.clone(), luid);
            Ok(wgnt)
        } else {
            Err(AdapterError::WindowsNativeWg(Error::Fail(
                "error obtaining lock".into(),
            )))
        }
    }};
}

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
}

#[derive(Debug, PartialEq)]
enum AdapterState {
    Up,
    Down,
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

    fn get_driver_info(adapter_guid: &str) -> (Option<String>, Option<String>, Option<String>) {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let net_class_path =
            r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
        if let Ok(net_class) = hklm.open_subkey(net_class_path) {
            for key_name in net_class.enum_keys().filter_map(|k| k.ok()) {
                if let Ok(subkey) = net_class.open_subkey(&key_name) {
                    // Check if this is our adapter
                    if let Ok(guid) = subkey.get_value::<String, _>("NetCfgInstanceId") {
                        if guid.eq_ignore_ascii_case(adapter_guid) {
                            return (
                                subkey.get_value("DriverDesc").ok(),
                                subkey.get_value("DriverVersion").ok(),
                                subkey.get_value("ProviderName").ok(),
                            );
                        }
                    }
                }
            }
        }
        (None, None, None)
    }

    fn fallback_retry(
        name: &str,
        path: &str,
        guid: u128,
        current_lib: &mut WireGuardHandle,
        watcher: Arc<Mutex<InterfaceWatcher>>,
        enable_dynamic_wg_nt_control: bool,
    ) -> result::Result<Self, AdapterError> {
        // Logic for the failure:
        // 1. Print all the adapter names in the system currently
        // 2. Match, which ones are using wireguard.dll
        // 3. Try to open() and close() all of them
        // 4. Try to delete the driver
        // 5. Try to load_library once again

        match AdaptersAddresses::try_new(Family::Unspec, *Flags::default().include_gateways()) {
            Ok(addrs) => {
                for adapter in &addrs {
                    let adapter_guid = adapter.adapter_name();
                    let (driver_desc, driver_version, provider_name) =
                        Self::get_driver_info(&adapter_guid);
                    telio_log_info!("adapter name: {:?}", adapter_guid);
                    telio_log_info!("friendly name: {:?}", adapter.friendly_name());
                    telio_log_info!("description: {:?}", adapter.description());
                    telio_log_info!("interface_type {:?}", adapter.interface_type());
                    telio_log_info!("driver description {:?}", driver_desc);
                    telio_log_info!("driver version {:?}", driver_version);
                    telio_log_info!("provider name {:?}", provider_name);

                    if provider_name == Some("WireGuard LLC".to_string()) {
                        match wireguard_nt::Adapter::open(current_lib, name) {
                            Ok(a) => {
                                telio_log_info!(
                                    "Opened and closing wg adapter with luid: {:?} {:?}",
                                    a.get_luid(), a.is_up()
                                );
                                telio_log_info!("a.down() {:?}", a.down());
                                drop(a);
                                
                                telio_log_info!("Listing adapters after drop:");
                                match AdaptersAddresses::try_new(Family::Unspec, *Flags::default().include_gateways()) {
                                    Ok(addrs) => {
                                        for adapter in &addrs {
                                            let adapter_guid = adapter.adapter_name();
                                            let (driver_desc, driver_version, provider_name) =
                                                Self::get_driver_info(&adapter_guid);
                                            telio_log_info!("adapter name: {:?}", adapter_guid);
                                            telio_log_info!("friendly name: {:?}", adapter.friendly_name());
                                            telio_log_info!("description: {:?}", adapter.description());
                                            telio_log_info!("interface_type {:?}", adapter.interface_type());
                                            telio_log_info!("driver description {:?}", driver_desc);
                                            telio_log_info!("driver version {:?}", driver_version);
                                            telio_log_info!("provider name {:?}", provider_name);
                                        }
                                    }
                                    Err(e) => {
                                        telio_log_error!("Error while getting adapters addresses 2: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                telio_log_info!(
                                    "Failed to open() wg adapter, guid: {:?}, name: {:?}, error {:?}",
                                    adapter_guid,
                                    adapter.friendly_name(),
                                    e,
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                telio_log_error!("Error while getting adapters addresses: {e}");
            }
        };

        if wireguard_nt::unload(current_lib.clone()) {
            match unsafe { wireguard_nt::load_from_path(path) } {
                Ok(wg_dll) => *current_lib = wg_dll,
                Err(e) => {
                    telio_log_error!("Failed to re-load wireguard dll: {e:?}");
                }
            }
        } else {
            telio_log_error!("Failed to unload wireguard dll ...");
        }

        match wireguard_nt::Adapter::create(current_lib, name, name, Some(guid)) {
            Ok(raw_adapter) => {
                form_wgnt_adapter!(raw_adapter, watcher, enable_dynamic_wg_nt_control)
            }
            Err(e) => {
                telio_log_error!("Failed to create adapter on second try");
                Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                    "Failed to create adapter: {e:?}",
                ))))
            }
        }
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
    ) -> result::Result<Self, AdapterError> {
        // try to load dll
        match unsafe { wireguard_nt::load_from_path(path) } {
            Ok(mut wg_dll) => {
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
                        form_wgnt_adapter!(raw_adapter, watcher, enable_dynamic_wg_nt_control)
                    }
                    Err(e) => {
                        telio_log_warn!(
                            "Failed to create adapter on first run: {e:?}, retrying ..."
                        );
                        Self::fallback_retry(
                            name,
                            path,
                            adapter_guid,
                            &mut wg_dll,
                            watcher,
                            enable_dynamic_wg_nt_control,
                        )
                    }
                }
            }
            Err(e) => Err(AdapterError::WindowsNativeWg(Error::Fail(format!(
                "Failed to load wireguard dll: {e:?}",
            )))),
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
        const GUID_DEVINTERFACE_NET: &str = r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{CAC88484-7515-4C03-82E6-71A87ABAC361}";
        const SWD_WIREGUARD: &str = r"SYSTEM\CurrentControlSet\Enum\SWD\WireGuard";
        telio_log_debug!("Print registry before adapter creation!");
        Self::print_registry_key_contents(HKEY_LOCAL_MACHINE, GUID_DEVINTERFACE_NET);
        Self::print_registry_key_contents(HKEY_LOCAL_MACHINE, SWD_WIREGUARD);

        let dll_path = "wireguard.dll";
        let tmp_wg_dev = Self::create(name, dll_path, enable_dynamic_wg_nt_control);

        telio_log_debug!("Print registry after adapter creation!");
        Self::print_registry_key_contents(HKEY_LOCAL_MACHINE, GUID_DEVINTERFACE_NET);
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

#[cfg(windows)]
#[async_trait::async_trait]
impl Adapter for WindowsNativeWg {
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> Result<Response, AdapterError> {
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

    async fn set_tun(&self, _tun: super::Tun) -> Result<(), AdapterError> {
        Err(AdapterError::UnsupportedAdapter)
    }

    fn clone_box(&self) -> Option<Box<dyn Adapter>> {
        None
    }
}

#[cfg(windows)]
impl Drop for WindowsNativeWg {
    fn drop(&mut self) {
        self.cleanup();
        telio_log_info!("wg-nt: deleting adapter: done");
    }
}
