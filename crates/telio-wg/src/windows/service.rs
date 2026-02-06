#![cfg(windows)]

use std::convert::{TryFrom, TryInto};
use std::mem;
use std::{ptr, time::Duration};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn, Instant};
use tokio::time::sleep;
use utf16_lit::utf16_null;
use windows::core::GUID;
use windows::core::{Error, Result as WindowsResult, HRESULT, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_GET_CLASS_DEVS_FLAGS;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Status, CM_Get_Device_Interface_ListW, CM_Get_Device_Interface_List_SizeW,
    SetupDiCreateDeviceInfoList, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsExW, SetupDiOpenDevRegKey, SetupDiOpenDeviceInfoW, CM_DEVNODE_STATUS_FLAGS,
    CM_GET_DEVICE_INTERFACE_LIST_PRESENT, CONFIGRET, CR_SUCCESS, DICS_FLAG_GLOBAL, DIGCF_PRESENT,
    DIREG_DRV, DN_DRIVER_LOADED, DN_STARTED, HDEVINFO, SP_DEVINFO_DATA,
};
use windows::Win32::Foundation::{GetLastError, ERROR_GEN_FAILURE, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::System::Registry::{RegCloseKey, RegQueryValueExW, HKEY};
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_STATUS,
};
use winreg::{enums::*, RegKey};

const KEY_QUERY_VALUE: u32 = 0x0001;

use windows::Win32::Devices::DeviceAndDriverInstallation::GUID_DEVCLASS_NET;
use windows::Win32::NetworkManagement::Ndis::GUID_DEVINTERFACE_NET;

pub const GUID_DEVINTERFACE_NET_STR: &str =
    r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{CAC88484-7515-4C03-82E6-71A87ABAC361}";
pub const WIREGUARD_ENUMERATOR: &str = "SWD\\WireGuard";
pub const DEFAULT_SERVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

struct ScopedDeviceInfoList {
    handle: Option<HDEVINFO>,
    dev_info_data: SP_DEVINFO_DATA,
}

impl ScopedDeviceInfoList {
    fn new(device_instance_id: &[u16]) -> Result<Self, AdapterInterfaceReadyError> {
        let mut dev_info_data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        dev_info_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

        let dev_info = unsafe { SetupDiCreateDeviceInfoList(None, None) }
            .map_err(|_| AdapterInterfaceReadyError::Other(unsafe { GetLastError().0 }))?;

        unsafe {
            SetupDiOpenDeviceInfoW(
                dev_info,
                PCWSTR::from_raw(device_instance_id.as_ptr()),
                None,
                0,
                Some(&mut dev_info_data),
            )
        }
        .map_err(|_| AdapterInterfaceReadyError::Other(unsafe { GetLastError().0 }))?;

        Ok(Self {
            handle: Some(dev_info),
            dev_info_data,
        })
    }
}

impl Drop for ScopedDeviceInfoList {
    fn drop(&mut self) {
        if let Some(h) = mem::take(&mut self.handle) {
            unsafe {
                let _ = SetupDiDestroyDeviceInfoList(h);
            };
        }
    }
}

struct ScopedRegKey(Option<HKEY>);

impl ScopedRegKey {
    fn new(dev_info: &mut ScopedDeviceInfoList) -> Result<Self, AdapterInterfaceReadyError> {
        let dev_info_handle = dev_info
            .handle
            .ok_or(AdapterInterfaceReadyError::FailedToOpenRegistryKey)?;
        let hkey = unsafe {
            SetupDiOpenDevRegKey(
                dev_info_handle,
                &dev_info.dev_info_data,
                DICS_FLAG_GLOBAL.0,
                0,
                DIREG_DRV,
                KEY_QUERY_VALUE,
            )
        }
        .map_err(|_| AdapterInterfaceReadyError::FailedToOpenRegistryKey)?;
        Ok(Self(Some(hkey)))
    }
}

impl Drop for ScopedRegKey {
    fn drop(&mut self) {
        if let Some(h) = mem::take(&mut self.0) {
            unsafe {
                let _ = RegCloseKey(h);
            };
        }
    }
}

#[derive(Clone)]
pub struct ScopedDeviceInfoSet {
    pub handle: Option<HDEVINFO>,
    pub dev_info_data: SP_DEVINFO_DATA,
}

impl ScopedDeviceInfoSet {
    pub fn from_class_devs_ex(
        class_guid: Option<*const GUID>,
        enumerator: PCWSTR,
        flags: SETUP_DI_GET_CLASS_DEVS_FLAGS,
        index: Option<u32>,
    ) -> Result<Self, AdapterInterfaceReadyError> {
        // Create the device info set for the given class + enumerator.
        let dev_info = unsafe {
            SetupDiGetClassDevsExW(
                class_guid,
                enumerator,
                None,
                flags,
                Some(HDEVINFO::default()),
                PCWSTR(ptr::null()),
                None,
            )
        }
        .map_err(|_| AdapterInterfaceReadyError::DriverNotInitialized)?;

        // Enumerate the first device and cache its SP_DEVINFO_DATA so callers
        // can use the DevInst without having to enumerate again.
        let mut dev_info_data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        dev_info_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

        if let Some(idx) = index {
            unsafe { SetupDiEnumDeviceInfo(dev_info, idx, &mut dev_info_data) }.map_err(|_| {
                unsafe {
                    let _ = SetupDiDestroyDeviceInfoList(dev_info);
                };
                AdapterInterfaceReadyError::DriverNotInitialized
            })?;
        }

        Ok(Self {
            handle: Some(dev_info),
            dev_info_data,
        })
    }
}

impl Drop for ScopedDeviceInfoSet {
    fn drop(&mut self) {
        if let Some(h) = mem::take(&mut self.handle) {
            unsafe {
                let _ = SetupDiDestroyDeviceInfoList(h);
            };
        }
    }
}

unsafe impl Send for ScopedDeviceInfoSet {}
unsafe impl Sync for ScopedDeviceInfoSet {}

#[derive(Debug)]
enum WinServiceStatus {
    Stopped = 1,
    Starting = 2,
    Stopping = 3,
    Running = 4,
    Continuing = 5,
    Pausing = 6,
    Paused = 7,
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterInterfaceReadyError {
    #[error("Driver not initialized")]
    DriverNotInitialized,
    #[error("Device instance ID not found")]
    DeviceInstanceIdNotFound,
    #[error("NetCfgInstanceId not set")]
    NetCfgInstanceIdNotSet,
    #[error("NetLuidIndex not set")]
    NetLuidIndexNotSet,
    #[error("IfType not set")]
    IfTypeNotSet,
    #[error("NDIS device interface not exists")]
    NDISDeviceInterfaceNotExists,
    #[error("Device interface not exists in IP stack")]
    DeviceInterfaceNotExistsInIpStack,
    #[error("Failed to open registry key")]
    FailedToOpenRegistryKey,
    #[error("Error: {0}")]
    Other(u32),
}

impl TryFrom<u32> for WinServiceStatus {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(WinServiceStatus::Stopped),
            2 => Ok(WinServiceStatus::Starting),
            3 => Ok(WinServiceStatus::Stopping),
            4 => Ok(WinServiceStatus::Running),
            5 => Ok(WinServiceStatus::Continuing),
            6 => Ok(WinServiceStatus::Pausing),
            7 => Ok(WinServiceStatus::Paused),
            _ => Err("Unknown service state"),
        }
    }
}

pub fn wait_for_service(service_name: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match is_service_running(service_name) {
            Ok(res) => {
                telio_log_debug!("\"{}\" service is {:?}", service_name, res);
                // TODO: do we need to know, in what exact state is service, or is it enough to know that it is loaded into OS ..?
                return true;
            }
            Err(err) => {
                telio_log_warn!(
                    "Failed to check \"{}\" service status: {:?}",
                    service_name,
                    err
                );
            }
        }
    }

    false
}

pub async fn wait_for_adapter_interface_ready(adapter_luid: u64, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match is_network_adapter_interface_ready(adapter_luid) {
            Ok(_) => return true,
            Err(err) => {
                telio_log_warn!("Failed to check adapter interface ready: {:?}", err);
                sleep(timeout / 10).await;
            }
        }
    }

    false
}

fn is_service_running(service_name: &str) -> WindowsResult<WinServiceStatus> {
    let service_name_wide: Vec<u16> = str_to_utf16(service_name);
    let service_name_wide = PCWSTR(service_name_wide.as_ptr());

    unsafe {
        // Open a handle to the Service Control Manager
        let sc_manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)?;

        // Open a handle to the service
        let service = OpenServiceW(sc_manager, service_name_wide, SERVICE_QUERY_STATUS)?;

        // Query the service status
        let mut status = SERVICE_STATUS::default();
        QueryServiceStatus(service, &mut status)?;

        // Check the current state
        match WinServiceStatus::try_from(status.dwCurrentState.0) {
            Ok(res) => Ok(res),
            Err(e) => Err(Error::new(HRESULT(1), e)),
        }
    }
}

/// Returns the LUID for the device identified by `device_instance_id`, if the driver
/// has registered (NetLuidIndex and *IfType are present in the driver registry). Returns
/// `None` if the device cannot be opened or the values are not yet set.
pub fn get_luid_for_device_instance(device_instance_id: &[u16]) -> Option<u64> {
    if device_instance_id.is_empty() {
        return None;
    }

    let mut dev_info = ScopedDeviceInfoList::new(device_instance_id)
        .map_err(|_| None::<u64>)
        .ok()?;
    let drv_key = ScopedRegKey::new(&mut dev_info)
        .map_err(|_| None::<u64>)
        .ok()?;

    let mut net_luid_index: u32 = 0;
    let mut val_size = std::mem::size_of::<u32>() as u32;
    let net_luid_name: Vec<u16> = str_to_utf16("NetLuidIndex");
    if unsafe {
        query_registry_status(
            &drv_key,
            &mut net_luid_index as *mut u32 as *mut u8,
            &mut val_size,
            &net_luid_name,
        )
    }
    .is_err()
    {
        return None;
    }
    let mut if_type: u32 = 0;
    val_size = std::mem::size_of::<u32>() as u32;
    let if_type_name: Vec<u16> = str_to_utf16("*IfType");
    if unsafe {
        query_registry_status(
            &drv_key,
            &mut if_type as *mut u32 as *mut u8,
            &mut val_size,
            &if_type_name,
        )
    }
    .is_err()
    {
        return None;
    }
    let luid_value = (net_luid_index as u64) << 24 | ((if_type as u64) & 0xFFFF) << 48;
    Some(luid_value)
}

fn get_wireguard_device_instance_ids_from_registry() -> Vec<String> {
    const WIREGUARD_SUBKEY_PREFIX: &str = "##?#SWD#WireGuard#";

    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match root.open_subkey(GUID_DEVINTERFACE_NET_STR) {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };
    key.enum_keys()
        .filter_map(|r| r.ok())
        .filter(|name| name.starts_with(WIREGUARD_SUBKEY_PREFIX))
        .filter_map(|name| {
            name.strip_prefix("##?#").map(|s| {
                let path = s.replace('#', "\\");
                // Extract instance ID: strip trailing \{interface-class-guid}
                path.rsplit_once('\\')
                    .map(|(prefix, _)| prefix.to_string())
                    .unwrap_or(path)
            })
        })
        .collect()
}

fn cm_map_cr_to_win32_err(cr: CONFIGRET, default_error: u32) -> u32 {
    if cr == CR_SUCCESS {
        0
    } else {
        default_error
    }
}

pub fn str_to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn get_device_instance_id_for_adapter_luid(
    adapter_luid: u64,
) -> Result<Vec<u16>, AdapterInterfaceReadyError> {
    let candidates = get_wireguard_device_instance_ids_from_registry();
    let mut found = None;
    for instance_id_str in &candidates {
        let id = str_to_utf16(instance_id_str);
        if get_luid_for_device_instance(&id) == Some(adapter_luid) {
            found = Some(id);
            break;
        }
    }
    if let Some(id) = found {
        if !id.is_empty() {
            return Ok(id);
        }
    }
    Err(AdapterInterfaceReadyError::DeviceInstanceIdNotFound)
}

fn is_network_driver_initialized() -> Result<(), AdapterInterfaceReadyError> {
    let enumerator_utf16 = utf16_null!(WIREGUARD_ENUMERATOR);

    let dev_info_set = ScopedDeviceInfoSet::from_class_devs_ex(
        Some(&GUID_DEVCLASS_NET),
        PCWSTR(enumerator_utf16.as_ptr()),
        DIGCF_PRESENT,
        Some(0),
    )?;

    let mut status = CM_DEVNODE_STATUS_FLAGS(0);
    let mut problem = windows::Win32::Devices::DeviceAndDriverInstallation::CM_PROB(0);
    let dev_inst = dev_info_set.dev_info_data.DevInst;

    let cr = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, dev_inst, 0) };
    if cr != CR_SUCCESS {
        return Err(AdapterInterfaceReadyError::DriverNotInitialized);
    }

    if status.0 & DN_DRIVER_LOADED.0 != 0 && status.0 & DN_STARTED.0 != 0 {
        return Ok(());
    }

    Err(AdapterInterfaceReadyError::DriverNotInitialized)
}

unsafe fn query_registry_status(
    key: &ScopedRegKey,
    result: *mut u8,
    result_size: &mut u32,
    name: &[u16],
) -> Result<(), AdapterInterfaceReadyError> {
    let unwrapped_key = key
        .0
        .ok_or(AdapterInterfaceReadyError::FailedToOpenRegistryKey)?;

    let err = RegQueryValueExW(
        unwrapped_key,
        PCWSTR::from_raw(name.as_ptr()),
        None,
        None,
        Some(result),
        Some(result_size),
    );
    if err != ERROR_SUCCESS {
        return Err(AdapterInterfaceReadyError::NetCfgInstanceIdNotSet);
    }
    Ok(())
}

/// Checks whether the network adapter identified by `device_instance_id` has completed
/// miniport initialization: driver is started, NDIS has registered the miniport
/// (NetCfgInstanceId/NetLuidIndex are set), and the NDIS device interface
/// (GUID_DEVINTERFACE_NET) exists. Optionally verifies the interface appears in
/// the IP stack via GetIfEntry2.
///
/// This corresponds to the state after the driver has logged "Interface created"
/// (i.e. after InitializeEx returns NDIS_STATUS_SUCCESS and RegisterAdapter has
/// completed). Use this instead of only checking DN_DRIVER_LOADED | DN_STARTED,
/// which becomes true earlier (when the device is started, before NDIS calls
/// InitializeEx and the miniport is registered).
///
/// # Arguments
/// * `device_instance_id` - Device instance ID (e.g. `SWD\\WireGuard\\...`)
///   GetIfEntry2 (IP stack). Slightly stricter/later.
///
/// # Returns
/// * `Ok(())` if the adapter interface is created and registered.
/// * `Err(win32_error)` on failure (e.g. ERROR_DEVICE_NOT_READY).
fn is_network_adapter_interface_ready(adapter_luid: u64) -> Result<(), AdapterInterfaceReadyError> {
    // 1. Network driver must be initialized.
    is_network_driver_initialized()?;
    telio_log_debug!("Network driver initialized");

    // 2) Driver registry must have NetCfgInstanceId and NetLuidIndex (written by NDIS
    //    when the miniport registers).
    let device_instance_id: Vec<u16> = get_device_instance_id_for_adapter_luid(adapter_luid)?;
    let mut dev_info = ScopedDeviceInfoList::new(&device_instance_id)?;
    let drv_key = ScopedRegKey::new(&mut dev_info)?;

    let mut net_cfg_buf = [0u16; 64];
    let mut net_cfg_len = (net_cfg_buf.len() * 2) as u32;
    let net_cfg_name: Vec<u16> = str_to_utf16("NetCfgInstanceId");
    unsafe {
        query_registry_status(
            &drv_key,
            net_cfg_buf.as_mut_ptr() as *mut u8,
            &mut net_cfg_len,
            &net_cfg_name,
        )
    }
    .map_err(|_| AdapterInterfaceReadyError::NetCfgInstanceIdNotSet)?;
    telio_log_debug!("NetCfgInstanceId set");

    let mut net_luid_index: u32 = 0;
    let mut val_size = std::mem::size_of::<u32>() as u32;
    let net_luid_name: Vec<u16> = str_to_utf16("NetLuidIndex");
    unsafe {
        query_registry_status(
            &drv_key,
            &mut net_luid_index as *mut u32 as *mut u8,
            &mut val_size,
            &net_luid_name,
        )
    }
    .map_err(|_| AdapterInterfaceReadyError::NetLuidIndexNotSet)?;
    telio_log_debug!("NetLuidIndex set");

    let mut if_type: u32 = 0;
    val_size = std::mem::size_of::<u32>() as u32;
    let if_type_name: Vec<u16> = str_to_utf16("*IfType");
    unsafe {
        query_registry_status(
            &drv_key,
            &mut if_type as *mut u32 as *mut u8,
            &mut val_size,
            &if_type_name,
        )
    }
    .map_err(|_| AdapterInterfaceReadyError::IfTypeNotSet)?;
    telio_log_debug!("IfType set");

    // 3) NDIS device interface (GUID_DEVINTERFACE_NET) must exist.
    let mut list_len: u32 = 0;
    let cr: CONFIGRET = unsafe {
        CM_Get_Device_Interface_List_SizeW(
            &mut list_len,
            &GUID_DEVINTERFACE_NET,
            PCWSTR::from_raw(device_instance_id.as_ptr()),
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        )
    };
    if cr != CR_SUCCESS || list_len < 1 {
        return Err(if cr != CR_SUCCESS {
            telio_log_error!("Failed to get device interface list: {cr:?} {list_len}");
            AdapterInterfaceReadyError::Other(cm_map_cr_to_win32_err(cr, ERROR_GEN_FAILURE.0))
        } else {
            AdapterInterfaceReadyError::NDISDeviceInterfaceNotExists
        });
    }

    let list_len_chars = (list_len * 2) as usize; // list_len is in bytes, convert to u16 count
    let mut interface_list = vec![0u16; list_len_chars];
    let cr: CONFIGRET = unsafe {
        CM_Get_Device_Interface_ListW(
            &GUID_DEVINTERFACE_NET,
            PCWSTR::from_raw(device_instance_id.as_ptr()),
            &mut interface_list,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
        )
    };
    if cr != CR_SUCCESS {
        telio_log_error!("Failed to get device interface list: {cr:?} {list_len}");
        return Err(AdapterInterfaceReadyError::Other(cm_map_cr_to_win32_err(
            cr,
            ERROR_GEN_FAILURE.0,
        )));
    }
    if interface_list.first().copied() == Some(0) {
        return Err(AdapterInterfaceReadyError::NDISDeviceInterfaceNotExists);
    }
    telio_log_debug!("NDIS device interface exists");

    // 4) Optional: require the interface to be visible in the IP stack.
    // NET_LUID: Reserved (0-23), NetLuidIndex (24-47), IfType (48-63)
    let luid_value = (net_luid_index as u64) << 24 | ((if_type as u64) & 0xFFFF) << 48;
    let luid = NET_LUID_LH { Value: luid_value };
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = luid;
    if unsafe { GetIfEntry2(&mut row) } != ERROR_SUCCESS {
        return Err(AdapterInterfaceReadyError::DeviceInterfaceNotExistsInIpStack);
    }
    telio_log_debug!("Interface exists in IP stack");

    Ok(())
}
