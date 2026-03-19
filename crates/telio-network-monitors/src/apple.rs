//! Module to monitor network changes in Apple

use network_framework_sys::{
    nw_path_monitor_create, nw_path_monitor_set_queue, nw_path_monitor_start, nw_path_monitor_t,
    nw_path_t,
};
use std::ffi::{c_long, c_void};
use telio_utils::{telio_log_debug, telio_log_info, telio_log_warn};

/// Dispatch queue priority as high priority queue
pub const DISPATCH_QUEUE_PRIORITY_HIGH: c_long = 2;
/// Dispatch queue priority as default queue
pub const DISPATCH_QUEUE_PRIORITY_DEFAULT: c_long = 0;
/// Dispatch queue priority as low priority queue
pub const DISPATCH_QUEUE_PRIORITY_LOW: c_long = -2;
/// Dispatch queue priority as background queue
pub const DISPATCH_QUEUE_PRIORITY_BACKGROUND: c_long = -1 << 15;

extern "C" {
    /// Obj-c signature:
    /// void nw_path_monitor_set_update_handler(nw_path_monitor_t monitor, nw_path_monitor_update_handler_t update_handler);
    /// typedef void (^nw_path_monitor_update_handler_t)(nw_path_t path);
    pub fn nw_path_monitor_set_update_handler(
        monitor: nw_path_monitor_t,
        update_handler: *const c_void,
    );
    /// Obj-c signature:
    /// void nw_path_enumerate_interfaces(nw_path_t path, nw_path_enumerate_interfaces_block_t enumerate_block);
    /// typedef bool (^nw_path_enumerate_interfaces_block_t)(nw_interface_t interface);
    pub fn nw_path_enumerate_interfaces(path: nw_path_t, enumerate_block: *const c_void);
}

/// This function configuresa a network path monitor using Apple's networking framework that tracks
/// changes in the network path and updates the local interface cache.
///
/// # How it Works
///
/// 1. **Objective-C Blocks**: The Apple `Network.framework` uses blocks as callbacks
///    for handling asynchronous events.
///
/// 3. **Global Queue Setup**: The monitor runs on a background queue using Grand Central Dispatch (GCD).
///    This allows it to handle updates without blocking the main thread.
///
/// 4. **Broadcast Notification**: After the interfaces are updated, a notification is sent via a broadcast channel
///    (`PATH_CHANGE_BROADCAST`) to inform other parts of the system that the path has changed.
///
/// For more details on Apple's `Network.framework` see:
/// - [Apple Network.framework Documentation](https://developer.apple.com/documentation/network)
pub fn setup_network_monitor() {
    #[cfg(target_os = "macos")]
    std::thread::spawn(start_sc_dynamic_store_monitor);

    let update_handler =
        block::ConcreteBlock::new(|_path: nw_path_t| crate::monitor::notify()).copy();

    let monitor = unsafe { nw_path_monitor_create() };
    if monitor.is_null() {
        telio_log_warn!("Failed to start network path monitor");
        return;
    }

    let queue =
        unsafe { dispatch::ffi::dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0) };
    if queue.is_null() {
        telio_log_warn!("Failed to get global background queue");
        return;
    }
    unsafe {
        nw_path_monitor_set_queue(
            monitor,
            std::mem::transmute::<
                *mut dispatch::ffi::dispatch_object_s,
                *mut network_framework_sys::dispatch_queue,
            >(queue),
        );

        nw_path_monitor_set_update_handler(
            monitor,
            &*update_handler as *const block::Block<_, _> as *const c_void,
        );
        nw_path_monitor_start(monitor);
    }
}

#[cfg(target_os = "macos")]
fn start_sc_dynamic_store_monitor() {
    use core_foundation::runloop::{kCFRunLoopDefaultMode, CFRunLoop};
    use system_configuration::{
        core_foundation::{array::CFArray, string::CFString},
        dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext},
    };

    fn callout(_store: SCDynamicStore, changed_keys: CFArray<CFString>, _info: &mut ()) {
        for key in changed_keys.iter() {
            telio_log_debug!("changed key: {}", *key);
        }
        crate::monitor::notify();
    }

    telio_log_info!("Starting registration in SCDynamicStore");

    let callback_context = SCDynamicStoreCallBackContext { callout, info: () };
    let Some(store) = SCDynamicStoreBuilder::new("telio-network-monitors")
        .callback_context(callback_context)
        .build()
    else {
        telio_log_warn!("Failed to create SCDynamicStore instance");
        return;
    };

    let keys: CFArray<CFString> = CFArray::from_CFTypes(&[]);

    // The pattern is a result of:
    // SCDynamicStoreKeyCreateNetworkInterfaceEntity(nil, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4)
    // The SCDynamicStoreKeyCreateNetworkInterfaceEntity is not exported in
    // system-configuration-rs
    let patterns: CFArray<CFString> =
        CFArray::from_CFTypes(&[CFString::new("State:/Network/Interface/[^/]+/IPv4")]);

    let result = store.set_notification_keys(&keys, &patterns);

    if !result {
        // Debug output for CFArray is multiline, which is why we 'flatten' it
        // into one line
        telio_log_warn!(
            "Failed to add patterns '{}' to the store",
            format!("{patterns:?}").replace('\n', "")
        );
        return;
    }

    let Some(run_loop_source) = store.create_run_loop_source() else {
        telio_log_warn!("Failed to create CFRunLoopSource");
        return;
    };
    let run_loop = CFRunLoop::get_current();
    run_loop.add_source(&run_loop_source, unsafe { kCFRunLoopDefaultMode });

    telio_log_info!("Completed registration in SCDynamicStore");
    CFRunLoop::run_current();
}
