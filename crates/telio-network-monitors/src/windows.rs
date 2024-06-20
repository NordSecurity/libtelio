use std::ffi::c_void;
use std::ffi::c_void;
use std::os::raw::c_ulong;
use std::ptr;
use std::ptr;
use telio_utils::{telio_log_debug, telio_log_error};
use winapi::shared::minwindef::{BOOL, DWORD, TRUE};
use winapi::shared::ws2def::AF_UNSPEC;
use winapi::um::iptypes::MIB_IPINTERFACE_ROW;
use winapi::um::netioapi::{CancelMibChangeNotify2, NotifyIpInterfaceChange};
use winapi::um::winnt::{HANDLE, PVOID};
use winapi::um::{iphlpapi::NotifyAddrChange, minwinbase::OVERLAPPED, Foundation::HANDLE};

unsafe extern "system" fn callback(
    caller_context: PVOID,
    row: *mut MIB_IPINTERFACE_ROW,
    notification_type: c_ulong,
) {
    println!("Network interface change detected.");
}

fn handle_windows() {
    unsafe {
        let mut handle: HANDLE = ptr::null_mut();

        let result = NotifyIpInterfaceChange(
            AF_UNSPEC as u16, // Family: AF_UNSPEC for all, or AF_INET, AF_INET6 for specific
            Some(callback),   // Callback function
            ptr::null(),      // Caller context
            false,            // Initial notification
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
        let cancel_result = CancelMibChangeNotify2(handle);
        if cancel_result == 0 {
            println!("Notification canceled successfully.");
        } else {
            println!(
                "Failed to cancel notification with error code: {}",
                cancel_result
            );
        }
    }
}
