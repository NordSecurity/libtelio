use crate::monitor::PATH_CHANGE_BROADCAST;
use std::ptr;
use telio_utils::{telio_log_error, telio_log_trace, telio_log_warn};
pub use winapi::shared::netioapi::MIB_NOTIFICATION_TYPE;
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
    context: PVOID,
    _row: *mut MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    telio_log_trace!(
        "Windows IP interface monitor received a {} (NotificationType) for {} (CallerContext).",
        notification_type,
        context as usize
    );

    if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
        telio_log_warn!("Failed to notify about changed path {e}");
    }
}

/// Method to setup network monitoring for Windows
pub fn setup_network_monitor() -> SafeHandle {
    let mut handle: HANDLE = ptr::null_mut();

    let result = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC as u16,
            Some(callback),
            ptr::null_mut(),
            0,
            &mut handle,
        )
    };

    if result != NO_ERROR {
        telio_log_error!(
            "NotifyIpInterfaceChange call failed with error code: {}",
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
            if cancel_result == NO_ERROR {
                telio_log_trace!("Notification cancelled successfully.");
            } else {
                telio_log_error!(
                    "Failed to cancel notification with error code: {}",
                    cancel_result
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
