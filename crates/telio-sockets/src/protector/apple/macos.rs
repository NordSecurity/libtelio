use libc;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::result::Result;
use std::{
    io,
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
use tokio::{self, sync::Notify, task::JoinHandle};

mod common;
use common::{bind, bind_to_tun};

use crate::native::interface_index_from_name;
use crate::native::NativeSocket;
use crate::Protector;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};

#[derive(thiserror::Error, Debug)]
pub enum Error {}

pub struct SocketWatcher {
    sockets: Arc<Mutex<Sockets>>,
    monitor: JoinHandle<io::Result<()>>,
}
pub struct NativeProtector {
    /// This is used to bind sockets to external interface
    /// It will save provided sockets and rebind them when network changes
    socket_watcher: Option<SocketWatcher>,

    /// This is used to bind sockets to tunnel interface
    /// This is needed for macos/ios appstore apps as apple's Network Extension seems to
    /// exclude all sockets created by tunnel process, via setting NECP rules
    tunnel_interface: RwLock<Option<u64>>,
}

impl NativeProtector {
    pub fn new(macos_sideload: bool) -> Result<Self, Error> {
        if macos_sideload {
            let sockets = Arc::new(Mutex::new(Sockets::new()));
            Ok(Self {
                socket_watcher: Some(SocketWatcher {
                    sockets: sockets.clone(),
                    monitor: spawn_monitor(sockets),
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
}

impl Drop for NativeProtector {
    fn drop(&mut self) {
        if let Some(ref sw) = self.socket_watcher {
            sw.monitor.abort();
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
            socks.notify.notify_waiters();
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
}

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

    fn rebind_all(&mut self, force: bool) {
        let tunnel_interface = match self.tunnel_interface {
            Some(tun_if) => tun_if,
            None => return,
        };
        if self.sockets.is_empty() {
            return;
        }
        let new_default_interface = get_primary_interface(tunnel_interface);
        if !force && self.default_interface == new_default_interface {
            return;
        }
        self.default_interface = new_default_interface;
        if let Some(&interface) = self.default_interface.as_ref() {
            for sock in &self.sockets {
                telio_log_debug!(
                    "Binding relay socket {} to default interface: {}",
                    sock,
                    interface
                );
                if let Err(e) = bind(interface as u32, *sock, libc::AF_INET) {
                    telio_log_debug!(
                        "failed to bind relay socket {} to default interface: {}: {}",
                        sock,
                        interface,
                        e
                    );
                }
            }
        };
    }

    fn rebind(&mut self, sock: i32, force: bool) {
        let tunnel_interface = match self.tunnel_interface {
            Some(tun_if) => tun_if,
            None => return,
        };
        if self.sockets.is_empty() {
            return;
        }
        let new_default_interface = get_primary_interface(tunnel_interface);
        if !force && self.default_interface == new_default_interface {
            return;
        }
        self.default_interface = new_default_interface;
        if let Some(&interface) = self.default_interface.as_ref() {
            telio_log_debug!(
                "Binding socket {} to default interface: {}",
                sock,
                interface
            );
            if let Err(e) = bind(interface as u32, sock, libc::AF_INET) {
                telio_log_error!(
                    "failed to bind socket {} to default interface: {}: {}",
                    sock,
                    interface,
                    e
                );
            }
        }
    }
}

fn spawn_monitor(sockets: Arc<Mutex<Sockets>>) -> JoinHandle<io::Result<()>> {
    spawn_dynamic_store_loop(Arc::downgrade(&sockets));
    tokio::spawn(async move {
        loop {
            let update = {
                let sockets = sockets.lock();
                sockets.notify.clone()
            };

            update.notified().await;
            let mut sockets = sockets.lock();
            sockets.rebind_all(true);
        }

        telio_log_warn!("Sockets monitor returned early");
        Ok(())
    })
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
    let mut primary_interface_names = Vec::new();
    let store = dynamic_store::SCDynamicStoreBuilder::new("primary-service-store").build();

    if let Some(service_order) = get_service_order(&store) {
        for service in service_order {
            let primary_service_dictionary = store
                .get(format!("State:/Network/Service/{}/IPv4", service).as_str())
                .and_then(CFPropertyList::downcast_into::<CFDictionary>);
            if let Some(primary_service_dictionary) = primary_service_dictionary {
                let interface_name = primary_service_dictionary
                    .find(unsafe { schema_definitions::kSCPropInterfaceName }.to_void())
                    .map(|ptr| unsafe { CFString::wrap_under_get_rule(*ptr as CFStringRef) });
                if let Some(interface_name) = interface_name {
                    primary_interface_names.push(interface_name.to_string());
                }
            }
        }
    }

    primary_interface_names
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

struct Context {
    sockets: Weak<Mutex<Sockets>>,
}

#[allow(clippy::needless_pass_by_value)]
fn dynamic_store_callback(
    _store: SCDynamicStore,
    _changed_keys: CFArray<CFString>,
    context: &mut Context,
) {
    if let Some(sockets) = context.sockets.upgrade() {
        sockets.lock().rebind_all(false);
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
    let watch_keys: CFArray<CFString> = CFArray::from_CFTypes(&[]);
    let watch_patterns = CFArray::from_CFTypes(&[CFString::from("State:/Network/Service/.*/IPv4")]);
    if !store.set_notification_keys(&watch_keys, &watch_patterns) {
        panic!("Unable to register notifications for primary service update dynamic store");
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
