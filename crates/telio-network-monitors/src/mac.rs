//! Module to monitor network changes in Apple

use network_framework_sys::{
    nw_interface_get_name, nw_interface_t, nw_path_monitor_create, nw_path_monitor_set_queue,
    nw_path_monitor_start, nw_path_monitor_t, nw_path_t,
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::{Arc, Mutex as StdMutex};
use std::{
    cell::RefCell,
    ffi::{c_long, c_void, CStr},
    io,
    rc::Rc,
};
use telio_utils::{
    local_interfaces, telio_log_info, telio_log_warn, Error, GetIfAddrs, SystemGetIfAddrs,
};
use tokio::{sync::broadcast::Sender, task::JoinHandle};

/// Dispatch queue priority as high priority queue
pub const DISPATCH_QUEUE_PRIORITY_HIGH: c_long = 2;
/// Dispatch queue priority as default queue
pub const DISPATCH_QUEUE_PRIORITY_DEFAULT: c_long = 0;
/// Dispatch queue priority as low priority queue
pub const DISPATCH_QUEUE_PRIORITY_LOW: c_long = -2;
/// Dispatch queue priority as background queue
pub const DISPATCH_QUEUE_PRIORITY_BACKGROUND: c_long = -1 << 15;

/// Vector containing interface names in OS order
pub static INTERFACE_NAMES_IN_OS_PREFERENCE_ORDER: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Sender to notify if there is a change in OS interface order
pub static PATH_CHANGE_BROADCAST: Lazy<Sender<()>> = Lazy::new(|| Sender::new(2));
/// Vector containing all local interfaces
pub static LOCAL_ADDRS_CACHE: Lazy<Arc<StdMutex<Vec<if_addrs::Interface>>>> =
    Lazy::new(|| Arc::new(StdMutex::new(Vec::new())));

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

#[derive(Debug, Default)]
/// Struct to monitor network
pub struct NetworkMonitor<G: GetIfAddrs = SystemGetIfAddrs> {
    nw_path_monitor_monitor_handle: Option<JoinHandle<io::Result<()>>>,
    get_if_addr: G,
}

impl<G: GetIfAddrs + Clone> NetworkMonitor<G> {
    /// Sets up and spawns network monitor
    pub fn new(if_addr: G) -> Result<NetworkMonitor<G>, Error> {
        if let Ok(mut guard) = LOCAL_ADDRS_CACHE.lock() {
            *guard = local_interfaces::gather_local_interfaces(&if_addr)?;
        }

        Ok(Self {
            nw_path_monitor_monitor_handle: None,
            get_if_addr: if_addr,
        })
    }

    /// Starts Network Monitoring IP cache
    pub fn start(&mut self) {
        let get_if_addr = self.get_if_addr.clone();
        self.nw_path_monitor_monitor_handle = Some(tokio::spawn({
            let mut notify = PATH_CHANGE_BROADCAST.subscribe();
            async move {
                loop {
                    match notify.recv().await {
                        Ok(()) => match local_interfaces::gather_local_interfaces(&get_if_addr) {
                            Ok(v) => {
                                if let Ok(mut guard) = LOCAL_ADDRS_CACHE.lock() {
                                    *guard = v;
                                }
                            }
                            Err(e) => telio_log_warn!("Unable to get local interfaces {e}"),
                        },
                        Err(e) => {
                            telio_log_warn!("Failed to receive new path for sockets ({e}): ");
                        }
                    }
                }
            }
        }));
    }
}

impl<G: GetIfAddrs> Drop for NetworkMonitor<G> {
    fn drop(&mut self) {
        if let Some(handle) = &self.nw_path_monitor_monitor_handle {
            handle.abort();
        }
    }
}

/// Setup network path monitor in Apple framework
pub fn setup_network_path_monitor() {
    let update_handler = block::ConcreteBlock::new(|path: nw_path_t| {
        let names = Rc::new(RefCell::new(vec![]));
        let names_copy = names.clone();

        let enumerate_callback =
            block::ConcreteBlock::new(move |interface: nw_interface_t| -> bool {
                let c_name = unsafe { nw_interface_get_name(interface) };
                if !c_name.is_null() {
                    let name = unsafe { CStr::from_ptr(c_name) };
                    if let Ok(name) = name.to_str() {
                        names_copy.borrow_mut().push(name.to_owned());
                    }
                }
                true
            })
            .copy();

        unsafe {
            nw_path_enumerate_interfaces(
                path,
                &*enumerate_callback as *const block::Block<_, _> as *const c_void,
            )
        };

        *INTERFACE_NAMES_IN_OS_PREFERENCE_ORDER.lock() = names.borrow().clone();
        if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
            telio_log_warn!(
                "Failed to notify about changed path, error: {e}, path: {:?}",
                names.borrow()
            );
        }

        telio_log_info!(
            "Path change notification sent, current network path in os preference order: {:?}",
            names.borrow()
        );
    })
    .copy();
    unsafe {
        let monitor = nw_path_monitor_create();
        if monitor.is_null() {
            telio_log_warn!("Failed to start network path monitor");
            return;
        }

        let queue = dispatch::ffi::dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
        if queue.is_null() {
            telio_log_warn!("Failed to get global background queue");
            return;
        }
        nw_path_monitor_set_queue(monitor, std::mem::transmute(queue));

        nw_path_monitor_set_update_handler(
            monitor,
            &*update_handler as *const block::Block<_, _> as *const c_void,
        );
        nw_path_monitor_start(monitor);
    }
}
