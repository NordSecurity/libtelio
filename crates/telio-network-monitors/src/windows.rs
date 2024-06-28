use crate::monitor::PATH_CHANGE_BROADCAST;
use std::os::raw::c_ulong;
use std::ptr;
use telio_utils::{telio_log_error, telio_log_trace, telio_log_warn};
use winapi::shared::{
    netioapi::{CancelMibChangeNotify2, NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW},
    ntdef::{HANDLE, PVOID},
    winerror::NO_ERROR,
    ws2def::AF_UNSPEC,
};

#[derive(Clone, Debug)]
/// Wrapper around HANDLE to pass between threads
pub struct SafeHandle(
    /// Making HANDLE publically accessible in monitor
    pub HANDLE,
);
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

unsafe extern "system" fn callback(
    _caller_context: PVOID,
    _row: *mut MIB_IPINTERFACE_ROW,
    _notification_type: c_ulong,
) {
    if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
        telio_log_warn!("Failed to notify about changed path {e}");
    }
}

/// Method to setup network monitoring for Windows
pub fn setup_network_monitor() -> SafeHandle {
    unsafe {
        let mut handle: HANDLE = ptr::null_mut();

        let result = NotifyIpInterfaceChange(
            AF_UNSPEC as u16, // Family: AF_UNSPEC for all, or AF_INET, AF_INET6 for specific
            Some(callback),   // Callback function
            ptr::null_mut(),  // Caller context
            0,                // Initial notification
            &mut handle,      // Notification handle
        );

        if result != NO_ERROR {
            telio_log_error!(
                "NotifyIpInterfaceChange call failed with error code: {}",
                result
            );
        }

        SafeHandle(handle)
    }
}

/// Clean up the network notification
pub fn deregister_network_monitor(safe_handle: SafeHandle) {
    // Denotification has to be done in a separate thread
    // otherwise would lead to deadlock
    tokio::spawn({
        async move {
            unsafe {
                let cancel_result = CancelMibChangeNotify2(safe_handle.0);
                if cancel_result == NO_ERROR {
                    telio_log_trace!("Notification cancelled successfully.");
                } else {
                    telio_log_error!(
                        "Failed to cancel notification with error code: {}",
                        cancel_result
                    );
                }
            }
        }
    });
}
