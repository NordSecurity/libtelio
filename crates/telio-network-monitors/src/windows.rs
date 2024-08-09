use crate::monitor::PATH_CHANGE_BROADCAST;
use std::os::raw::c_ulong;
use std::ptr;
use telio_utils::{telio_log_debug, telio_log_warn};
use winapi::shared::netioapi::{
    CancelMibChangeNotify2, NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW,
};
use winapi::shared::ntdef::{HANDLE, PVOID};
use winapi::shared::ws2def::AF_UNSPEC;

unsafe extern "system" fn callback(
    caller_context: PVOID,
    row: *mut MIB_IPINTERFACE_ROW,
    notification_type: c_ulong,
) {
    if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
        telio_log_warn!("Failed to notify about changed path {e}");
    }
    telio_log_debug!("Network interface change detected.");
}

/// Method to setup network monitoring for Windows
pub fn setup_network_monitor() {
    unsafe {
        let mut handle: HANDLE = ptr::null_mut();

        let result = NotifyIpInterfaceChange(
            AF_UNSPEC as u16, // Family: AF_UNSPEC for all, or AF_INET, AF_INET6 for specific
            Some(callback),   // Callback function
            ptr::null_mut(),  // Caller context
            0,                // Initial notification
            &mut handle,      // Notification handle
        );

        if result == 0 {
            telio_log_debug!("NotifyIpInterfaceChange call succeeded.");
        } else {
            telio_log_debug!(
                "NotifyIpInterfaceChange call failed with error code: {}",
                result
            );
        }

        // Clean up the notification
        // let cancel_result = CancelMibChangeNotify2(handle);
        // if cancel_result == 0 {
        //     println!("Notification canceled successfully.");
        // } else {
        //     println!(
        //         "Failed to cancel notification with error code: {}",
        //         cancel_result
        //     );
        // }
    }
}
