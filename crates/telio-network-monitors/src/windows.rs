use std::ptr;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GetIpInterfaceEntry, NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE,
};
use windows::Win32::{Foundation::HANDLE, Networking::WinSock::AF_UNSPEC};

#[derive(Clone, Debug)]
/// Wrapper around HANDLE to pass between threads
pub struct SafeHandle(
    /// Making HANDLE publically accessible in monitor
    pub HANDLE,
);
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

impl SafeHandle {
    /// Check in the underlying pointer is null
    pub fn is_null(&self) -> bool {
        self.0 .0.is_null()
    }
}

unsafe extern "system" fn callback(
    context: *const core::ffi::c_void,
    row: *const MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    let row: &MIB_IPINTERFACE_ROW = if row.is_null() {
        telio_log_warn!("MIB_IPINTERFACE_ROW is null, callback can't continue");
        return;
    } else {
        &*row
    };

    // The row passed to the callback by Windows has most fields zeroed out.
    // We need to call GetIpInterfaceEntry to get the actual current state.
    let mut populated_row = MIB_IPINTERFACE_ROW {
        Family: row.Family,
        InterfaceLuid: row.InterfaceLuid,
        ..Default::default()
    };
    let result = GetIpInterfaceEntry(&mut populated_row);
    if result == NO_ERROR {
        let MIB_IPINTERFACE_ROW {
            InterfaceIndex,
            Family,
            Metric,
            NlMtu,
            Connected,
            ..
        } = populated_row;
        telio_log_debug!(
            "Windows IP interface monitor received {notification_type:?} for \
             InterfaceIndex={InterfaceIndex}, Family={Family:?}, Metric={Metric}, NlMtu={NlMtu}, Connected={Connected} \
             (CallerContext={context:?})"
        );
    } else {
        let MIB_IPINTERFACE_ROW {
            InterfaceIndex,
            Family,
            ..
        } = row;
        telio_log_warn!(
            "Windows IP interface monitor received {notification_type:?} for \
             InterfaceIndex={InterfaceIndex}, Family={Family:?} (CallerContext={context:?}), \
             but GetIpInterfaceEntry failed: {result:?}"
        );
    }

    crate::monitor::notify();
}

/// Method to setup network monitoring for Windows
pub fn setup_network_monitor() -> SafeHandle {
    let mut handle = HANDLE(ptr::null_mut());

    let result =
        unsafe { NotifyIpInterfaceChange(AF_UNSPEC, Some(callback), None, false, &mut handle) };

    if result.is_err() {
        telio_log_error!(
            "NotifyIpInterfaceChange call failed with error code: {:?}",
            result
        );
    }

    SafeHandle(handle)
}

/// Clean up the network notification
pub fn deregister_network_monitor(safe_handle: SafeHandle) {
    // Denotification has to be done in a separate thread
    // otherwise would lead to deadlock
    tokio::task::spawn_blocking({
        move || {
            let cancel_result = unsafe { CancelMibChangeNotify2(safe_handle.0) };
            if cancel_result.is_ok() {
                telio_log_trace!("Notification cancelled successfully.");
            } else {
                telio_log_error!(
                    "Failed to cancel notification with error code: {cancel_result:?}"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unregister_callback() {
        let handle = setup_network_monitor();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        tokio::spawn({
            async move {
                assert!(unsafe { CancelMibChangeNotify2(handle.0) } == NO_ERROR);
            }
        })
        .await;
    }
}
