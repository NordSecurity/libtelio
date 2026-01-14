use debug_panic::debug_panic;
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};

use std::{
    cell::RefCell,
    ffi::{c_long, c_void, CStr},
    io,
    num::NonZeroU32,
    os::fd::BorrowedFd,
    rc::Rc,
    sync::{Arc, Weak},
};

use system_configuration::{
    self,
    core_foundation::{
        self,
        array::CFArray,
        base::{CFType, TCFType, ToVoid},
        dictionary::CFDictionary,
        propertylist::CFPropertyList,
        string::{CFString, CFStringRef},
    },
    dynamic_store::{self, SCDynamicStore},
    sys::schema_definitions,
};
use tokio::{
    self,
    sync::{broadcast::Sender, Notify},
    task::JoinHandle,
    time::Duration,
};

use crate::native::{interface_index_from_name, NativeSocket};
use crate::Protector;
use network_framework_sys::{
    nw_interface_get_name, nw_interface_t, nw_path_get_status, nw_path_monitor_create,
    nw_path_monitor_set_queue, nw_path_monitor_start, nw_path_monitor_t, nw_path_status_satisfied,
    nw_path_t,
};
use nix::sys::socket::{getsockname, AddressFamily, SockaddrLike, SockaddrStorage};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_info, telio_log_warn};

extern "C" {
    // Obj-c signature:
    // void nw_path_monitor_set_update_handler(nw_path_monitor_t monitor, nw_path_monitor_update_handler_t update_handler);
    // typedef void (^nw_path_monitor_update_handler_t)(nw_path_t path);
    pub fn nw_path_monitor_set_update_handler(
        monitor: nw_path_monitor_t,
        update_handler: *const c_void,
    );
    // Obj-c signature:
    // void nw_path_enumerate_interfaces(nw_path_t path, nw_path_enumerate_interfaces_block_t enumerate_block);
    // typedef bool (^nw_path_enumerate_interfaces_block_t)(nw_interface_t interface);
    pub fn nw_path_enumerate_interfaces(path: nw_path_t, enumerate_block: *const c_void);
}

pub const DISPATCH_QUEUE_PRIORITY_HIGH: c_long = 2;
pub const DISPATCH_QUEUE_PRIORITY_DEFAULT: c_long = 0;
pub const DISPATCH_QUEUE_PRIORITY_LOW: c_long = -2;
pub const DISPATCH_QUEUE_PRIORITY_BACKGROUND: c_long = -1 << 15;

static INTERFACE_NAMES_IN_OS_PREFERENCE_ORDER: Mutex<Vec<String>> = Mutex::new(Vec::new());
static PROTECTOR_PATH_CHANGE_BROADCAST: Lazy<Sender<()>> = Lazy::new(|| Sender::new(1));

#[cfg(any(target_os = "ios", target_os = "tvos"))]
use objc::{class, msg_send, runtime::Object, sel, sel_impl};
#[cfg(any(target_os = "ios", target_os = "tvos"))]
use objc_foundation::{INSString, NSString};
#[cfg(any(target_os = "ios", target_os = "tvos"))]
use version_compare::{compare_to, Cmp};

pub(crate) fn bind_to_tun(sock: NativeSocket, tunnel_interface: u64) -> io::Result<()> {
    telio_log_debug!(
        "Binding socket {} to tunnel interface: {}",
        sock,
        tunnel_interface
    );
    let res = bind(tunnel_interface as u32, sock);
    if let Err(e) = &res {
        telio_log_error!(
            "failed to bind socket {} to tunnel interface: {}: {}",
            sock,
            tunnel_interface,
            e
        );
    }

    res
}

pub(crate) fn bind(interface_index: u32, native_socket: NativeSocket) -> io::Result<()> {
    let socket = unsafe { BorrowedFd::borrow_raw(native_socket) };
    let socket = socket2::SockRef::from(&socket);
    let interface_index: NonZeroU32 = match NonZeroU32::new(interface_index) {
        Some(index) => index,
        None => return Err(std::io::Error::other("Invalid interface index")),
    };

    if let Some(sock_addr) = getsockname::<SockaddrStorage>(native_socket)?.family() {
        match sock_addr {
            AddressFamily::Inet => {
                socket.bind_device_by_index_v4(Some(interface_index))?;
            }
            AddressFamily::Inet6 => {
                socket.bind_device_by_index_v6(Some(interface_index))?;
            }
            _ => return Err(std::io::Error::other("Invalid IP family type")),
        }
    }

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum Error {}

pub struct SocketWatcher {
    sockets: Arc<Mutex<Sockets>>,
    monitor: JoinHandle<io::Result<()>>,
    nw_monitor: JoinHandle<io::Result<()>>,
}

#[cfg(any(target_os = "ios", target_os = "tvos"))]
// TODO: Adjust to tvOS
const SOCKET_WATCHER_MIN_IOS: &str = "15.7.1";
pub struct NativeProtector {
    /// This is used to bind sockets to external interface
    /// It will save provided sockets and rebind them when network changes
    ///
    /// LLT-3777 socket_watcher should be created only for iOS newer than 15.7.1
    /// With older iOS versions iOS handled rebinding by itself. It's not exactly
    /// clear in which version the implementation changed, 15.7.1 was tested as set
    /// as a reference point.
    socket_watcher: Option<SocketWatcher>,

    /// This is used to bind sockets to tunnel interface
    /// This is needed for macos/ios appstore apps as apple's Network Extension seems to
    /// exclude all sockets created by tunnel process, via setting NECP rules
    tunnel_interface: RwLock<Option<u64>>,
}

impl NativeProtector {
    pub fn new(#[cfg(target_os = "macos")] is_test_env: bool) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        let should_create_socket_watcher = !is_test_env;

        #[cfg(any(target_os = "ios", target_os = "tvos"))]
        let should_create_socket_watcher = NativeProtector::should_create_socket_watcher();

        if should_create_socket_watcher {
            let sockets = Arc::new(Mutex::new(Sockets::new()));
            let (monitor, nw_monitor) = spawn_monitors(sockets.clone());
            Ok(Self {
                socket_watcher: Some(SocketWatcher {
                    sockets,
                    monitor,
                    nw_monitor,
                }),
                tunnel_interface: RwLock::new(None),
            })
        } else {
            Ok(Self {
                socket_watcher: None,
                tunnel_interface: RwLock::new(None),
            })
        }
    }

    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    fn should_create_socket_watcher() -> bool {
        matches!(
            compare_to(
                NativeProtector::get_ios_version().as_str(),
                SOCKET_WATCHER_MIN_IOS,
                Cmp::Gt,
            ),
            Ok(true)
        )
    }

    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    fn get_ios_version() -> String {
        let ui_device = class!(UIDevice);

        let system_version_unsafe_str = unsafe {
            let current_device: *const Object = msg_send![ui_device, currentDevice];
            let system_version: *const Object = msg_send![current_device, systemVersion];
            &*(system_version as *const NSString)
        };

        system_version_unsafe_str.as_str().to_owned()
    }
}

impl Drop for NativeProtector {
    fn drop(&mut self) {
        if let Some(ref sw) = self.socket_watcher {
            sw.monitor.abort();
            sw.nw_monitor.abort();
        }
    }
}

impl Protector for NativeProtector {
    fn make_external(&self, socket: NativeSocket) -> io::Result<()> {
        if let Some(ref sw) = self.socket_watcher {
            let mut socks = sw.sockets.lock();
            socks.sockets.push(socket);
            socks.rebind(socket, true);
        }
        Ok(())
    }

    fn make_internal(&self, socket: NativeSocket) -> io::Result<()> {
        if let Some(index) = *self.tunnel_interface.read() {
            return bind_to_tun(socket, index);
        }

        Ok(())
    }

    fn clean(&self, socket: NativeSocket) {
        if let Some(ref sw) = self.socket_watcher {
            let mut socks = sw.sockets.lock();
            socks.sockets.retain(|s| s != &socket);
        }
    }

    fn set_tunnel_interface(&self, interface: u64) {
        *self.tunnel_interface.write() = Some(interface);

        if let Some(ref sw) = self.socket_watcher {
            let mut socks = sw.sockets.lock();
            socks.tunnel_interface = Some(interface);
            socks.notify.notify_waiters();
        }
    }

    /// This is a no-op on apple platforms.
    fn set_fwmark(&self, _fwmark: u32) {}

    /// This is a no-op on apple platforms.
    fn set_ext_if_filter(&self, _list: &[String]) {}
}

#[derive(Debug)]
struct Sockets {
    sockets: Vec<NativeSocket>,
    tunnel_interface: Option<u64>,
    default_interface: Option<u64>,
    notify: Arc<Notify>,
}

impl Sockets {
    fn new() -> Self {
        Self {
            sockets: Vec::new(),
            tunnel_interface: None,
            default_interface: None,
            notify: Arc::new(Notify::new()),
        }
    }

    fn rebind_all(&mut self) {
        telio_log_debug!("Rebinding all relay sockets");

        if !self.set_new_default_interface(true) {
            telio_log_info!(
                "Will not rebind relay sockets for {:?}",
                self.default_interface
            );
            return;
        }
        telio_log_info!("Will rebind relay sockets for {:?}", self.default_interface);

        if let Some(&interface) = self.default_interface.as_ref() {
            for socket in &self.sockets {
                Sockets::bind(interface as u32, socket);

                // NMACOS-8047 Writing an empty packet to the socket unblocks the sockets when
                // `includeAllNetworks` flag is enabled.
                #[cfg(target_os = "macos")]
                unsafe {
                    _ = libc::write(*socket, std::ptr::null(), 0);
                }
            }
        }
    }

    fn rebind(&mut self, sock: i32, force: bool) {
        telio_log_debug!("Rebinding socket {}, force: {}", sock, force);

        if !self.set_new_default_interface(force) {
            return;
        }

        if let Some(&interface) = self.default_interface.as_ref() {
            Sockets::bind(interface as u32, &sock);
        }
    }

    fn set_new_default_interface(&mut self, force: bool) -> bool {
        let tunnel_interface = match self.tunnel_interface {
            Some(tun_if) => tun_if,
            None => return false,
        };
        if self.sockets.is_empty() {
            return false;
        }
        let new_default_interface = get_primary_interface(tunnel_interface);

        if !force && self.default_interface == new_default_interface {
            return false;
        }

        self.default_interface = new_default_interface;

        true
    }

    fn bind(interface: u32, socket: &i32) {
        telio_log_debug!(
            "Binding relay socket {} to default interface: {}",
            socket,
            interface
        );
        if let Err(e) = bind(interface, *socket) {
            telio_log_debug!(
                "failed to bind relay socket {} to default interface: {}: {}",
                socket,
                interface,
                e
            );
        }
    }
}

#[allow(unreachable_code)]
fn spawn_monitors(
    sockets: Arc<Mutex<Sockets>>,
) -> (JoinHandle<io::Result<()>>, JoinHandle<io::Result<()>>) {
    spawn_dynamic_store_loop(Arc::downgrade(&sockets));
    let nw_path_monitor_monitor_handle = tokio::spawn({
        let sockets = sockets.clone();
        let mut notify = PROTECTOR_PATH_CHANGE_BROADCAST.subscribe();
        async move {
            // NMACOS-8047 When `includeAllNetworks` is set on the Apple platform, it happens that the user
            // experiences no-net after rebinding the sockets. We have not foud a better way of dealing with
            // that problem as to do delayed rebinding.
            let mut apple_bug_aks_workaround_rebind = false;
            let apple_bug_aks_workaround_delay = Duration::from_secs(5);
            loop {
                tokio::select! {
                    recv = notify.recv() => {
                        match recv {
                            Ok(()) => {
                                let mut sockets = sockets.lock();
                                sockets.rebind_all();
                                apple_bug_aks_workaround_rebind = true;
                            }
                            Err(e) => {
                                telio_log_warn!(
                                    "Failed to receive new path for sockets ({sockets:?}): {e}"
                                );
                            }
                        }
                    }
                    _ = tokio::time::sleep(apple_bug_aks_workaround_delay), if apple_bug_aks_workaround_rebind => {
                        #[cfg(target_os = "macos")]
                        {
                            telio_log_info!("Apple AKS Bug workaround timer expired. Rebinding sockets on");
                            sockets.lock().rebind_all();
                            apple_bug_aks_workaround_rebind = false
                        }
                    }
                }
            }
        }
    });
    (
        tokio::spawn(async move {
            loop {
                let update = {
                    let sockets = sockets.lock();
                    sockets.notify.clone()
                };

                update.notified().await;
                let mut sockets = sockets.lock();
                sockets.rebind_all();
            }
        }),
        nw_path_monitor_monitor_handle,
    )
}

fn get_service_order(store: &SCDynamicStore) -> Option<Vec<String>> {
    let service_order_dictionary = store
        .get("Setup:/Network/Global/IPv4")
        .and_then(CFPropertyList::downcast_into::<CFDictionary>)?;

    let service_order: Vec<String> = service_order_dictionary
        .find(unsafe { schema_definitions::kSCPropNetServiceOrder }.to_void())
        .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
        .and_then(CFType::downcast_into::<CFArray>)?
        .iter()
        .filter_map(|x| unsafe { CFType::wrap_under_get_rule(*x) }.downcast_into::<CFString>())
        .map(|x| x.to_string())
        .collect();

    Some(service_order)
}

fn get_primary_interface_names() -> Vec<String> {
    let mut primary_ipv4_interface_names = Vec::new();
    let store = dynamic_store::SCDynamicStoreBuilder::new("primary-service-store").build();

    if let Some(service_order) = get_service_order(&store) {
        for service in service_order {
            let primary_service_dictionary = store
                .get(format!("State:/Network/Service/{service}/IPv4").as_str())
                .and_then(CFPropertyList::downcast_into::<CFDictionary>);

            if let Some(primary_service_dictionary) = primary_service_dictionary {
                let interface_name = primary_service_dictionary
                    .find(unsafe { schema_definitions::kSCPropInterfaceName }.to_void())
                    .map(|ptr| unsafe { CFString::wrap_under_get_rule(*ptr as CFStringRef) });
                if let Some(interface_name) = interface_name {
                    primary_ipv4_interface_names.push(interface_name.to_string());
                }
            }
        }
    }

    let mut interface_names_in_os_preference_order: Vec<String> =
        INTERFACE_NAMES_IN_OS_PREFERENCE_ORDER.lock().clone();
    telio_log_info!(
        "Discovered these primary IPv4 interfaces for use in socket binding: {:?} (OS pereference order: {interface_names_in_os_preference_order:?})",
        primary_ipv4_interface_names
    );

    interface_names_in_os_preference_order
        .retain(|name| primary_ipv4_interface_names.contains(name));
    interface_names_in_os_preference_order
}

fn get_primary_interface(tunnel_interface: u64) -> Option<u64> {
    for primary_interface_name in get_primary_interface_names() {
        if let Ok(primary_interface_index) = interface_index_from_name(&primary_interface_name) {
            if primary_interface_index != tunnel_interface {
                return Some(primary_interface_index);
            }
        }
    }

    None
}

#[allow(dead_code)]
struct Context {
    sockets: Weak<Mutex<Sockets>>,
}

#[allow(clippy::needless_pass_by_value)]
fn dynamic_store_callback(
    _store: SCDynamicStore,
    changed_keys: CFArray<CFString>,
    _context: &mut Context,
) {
    // NMACOS-8047 The callback is executed when specified keys in the DynamicStore change.
    // In such case we should force rebind the sockets to avoid no-net when `includeAllNetworks` is set.
    telio_log_info!("Force rebinding the sockets because of DynamicStore key change");
    telio_log_debug!("DynamicStore key changed: {:?}", changed_keys);

    let primary_interfaces = get_primary_interface_names();

    let must_broadcast = must_broadcast_path_change(changed_keys, primary_interfaces);

    if !must_broadcast {
        telio_log_info!("Will not notify about DynamicStore key change");
        return;
    }

    if let Err(_e) = PROTECTOR_PATH_CHANGE_BROADCAST.send(()) {
        telio_log_warn!("Failed to notify about Dynamic Store change");
    } else {
        telio_log_info!("Notify about DynamicStore key change");
    }
}

/// Given a set of keys changed in Dynamic Store and a set of primary network interafaces, returns whether the path
/// change broadcast must happen.
fn must_broadcast_path_change(
    changed_keys: CFArray<CFString>,
    primary_interfaces: Vec<String>,
) -> bool {
    // Returns true if the given interface is primary.
    let is_primary =
        |interface: &str| -> bool { primary_interfaces.iter().any(|x| x == interface) };

    let mut must_broadcast = false;
    for changed_key in &changed_keys {
        let changed_key = changed_key.to_string();
        let mut key_path = changed_key.split('/');
        match key_path.next_back() {
            // One of:
            //  State:/Network/Interface/<interface>/IPConfigurationBusy
            Some("IPConfigurationBusy") => {
                // Is an <interface> the one we actually care about?
                if let Some(interface) = key_path.next_back() {
                    // If it is primary, then we do.
                    if is_primary(interface) {
                        must_broadcast = true;
                        break;
                    }
                    // Otherwise we must not broadcast the event.
                }
            }
            // One of:
            //  State:/Network/Global/IPv4
            //  State:/Network/Interface/<interface>/IPv4
            //  State:/Network/Interface/<service-UUID>/IPv4
            Some("IPv4") => {
                // Is an <interface> the one we actually care about?
                match key_path.next_back() {
                    // If it is Global, then we do.
                    Some("Global") => {
                        must_broadcast = true;
                        break;
                    }
                    // If it is primary, then we do.
                    Some(interface) => {
                        if is_primary(interface) {
                            must_broadcast = true;
                            break;
                        }
                    }
                    // Otherwise we must not broadcast the event.
                    None => {}
                }
            }
            // Unknown key, don't broadcast the event.
            _ => {}
        }
    }
    must_broadcast
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    mod broadcasting_path_change_notifications {
        use system_configuration::core_foundation::{array::CFArray, string::CFString};

        use crate::protector::platform::must_broadcast_path_change;

        #[test]
        fn broadcast_when_primary_network_interface_is_being_configured() {
            let changed_keys = vec![CFString::new(
                "State:/Network/Interface/en0/IPConfigurationBusy",
            )];
            let primary_interfaces = vec![String::from("en0")];
            assert_eq!(
                must_broadcast_path_change(
                    CFArray::from_CFTypes(&changed_keys),
                    primary_interfaces
                ),
                true
            );
        }

        #[test]
        fn dont_broadcast_when_secondary_network_interface_is_being_configured() {
            let changed_keys = vec![CFString::new(
                "State:/Network/Interface/en1/IPConfigurationBusy",
            )];
            let primary_interfaces = vec![String::from("en0")];
            assert_eq!(
                must_broadcast_path_change(
                    CFArray::from_CFTypes(&changed_keys),
                    primary_interfaces
                ),
                false
            );
        }

        #[test]
        fn broadcast_when_systemwide_ipv4_routing_is_being_changed() {
            let changed_keys = vec![CFString::new("State:/Network/Global/IPv4")];
            assert_eq!(
                must_broadcast_path_change(
                    CFArray::from_CFTypes(&changed_keys),
                    vec![] // The information about primary interfaces is irrelevant for this case.
                ),
                true
            );
        }

        #[test]
        fn broadcast_when_ipv4_primary_network_interface_is_being_configured() {
            let changed_keys = vec![CFString::new("State:/Network/Interface/en0/IPv4")];
            let primary_interfaces = vec![String::from("en0")];
            assert_eq!(
                must_broadcast_path_change(
                    CFArray::from_CFTypes(&changed_keys),
                    primary_interfaces
                ),
                true
            );
        }

        #[test]
        fn dont_broadcast_when_ipv4_secondary_network_interface_is_being_configured() {
            let changed_keys = vec![CFString::new("State:/Network/Interface/en0/IPv4")];
            let primary_interfaces = vec![String::from("en1")];
            assert_eq!(
                must_broadcast_path_change(
                    CFArray::from_CFTypes(&changed_keys),
                    primary_interfaces
                ),
                false
            );
        }
    }
}

fn get_dynamic_store(sockets: Weak<Mutex<Sockets>>) -> SCDynamicStore {
    let callback_context = dynamic_store::SCDynamicStoreCallBackContext {
        callout: dynamic_store_callback,
        info: Context { sockets },
    };
    let store = dynamic_store::SCDynamicStoreBuilder::new("primary-service-update-store")
        .callback_context(callback_context)
        .build();
    let watch_keys: CFArray<CFString> =
        CFArray::from_CFTypes(&[CFString::from("State:/Network/Global/IPv4")]);
    let watch_patterns = CFArray::from_CFTypes(&[CFString::from(
        "State:/Network/Interface/.*/IPConfigurationBusy",
    )]);
    if !store.set_notification_keys(&watch_keys, &watch_patterns) {
        debug_panic!("Unable to register notifications for primary service update dynamic store");
    }

    store
}

fn spawn_dynamic_store_loop(sockets: Weak<Mutex<Sockets>>) {
    std::thread::spawn(|| {
        let store = get_dynamic_store(sockets);
        let run_loop_source = store.create_run_loop_source();
        let run_loop = core_foundation::runloop::CFRunLoop::get_current();
        run_loop.add_source(&run_loop_source, unsafe {
            core_foundation::runloop::kCFRunLoopCommonModes
        });

        core_foundation::runloop::CFRunLoop::run_current();
    });
}

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

        let path_status = unsafe { nw_path_get_status(path) };

        // Rebind only on satisfied paths
        if path_status == nw_path_status_satisfied {
            *INTERFACE_NAMES_IN_OS_PREFERENCE_ORDER.lock() = names.borrow().clone();
            if let Err(e) = PROTECTOR_PATH_CHANGE_BROADCAST.send(()) {
                telio_log_warn!(
                    "Failed to notify about changed path, error: {e}, path: {:?}",
                    names.borrow()
                );
            } else {
                telio_log_info!("Notify about changed path: {:?}", names.borrow())
            }
        }

        telio_log_info!(
            "Path change notification sent, current network path in os preference order: {:?}",
            names.borrow()
        );
    })
    .copy();

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
