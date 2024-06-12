use libc::setsockopt;
use std::io::{self, Result};
use std::net::Ipv4Addr;
use std::os::windows::io::RawSocket;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use winapi::shared::{
    ifdef::IfOperStatusUp,
    netioapi::*,
    ntdef::{HANDLE, PVOID},
    winerror::{ERROR_BUFFER_OVERFLOW, NO_ERROR},
    ws2def::{ADDRESS_FAMILY, AF_INET, AF_INET6},
};
use winapi::um::{iphlpapi::GetAdaptersInfo, iptypes::IP_ADAPTER_INFO};

use crate::{NativeSocket, Protector};

// Protector implementation

pub struct NativeProtector {
    sockets: Arc<Mutex<Sockets>>,
    monitor: JoinHandle<()>,
}

impl NativeProtector {
    pub fn new() -> io::Result<Self> {
        let sockets = Arc::new(Mutex::new(Sockets::new()));
        Ok(Self {
            sockets: sockets.clone(),
            monitor: spawn_monitor(sockets)?,
        })
    }

    /// # Safety
    /// The tunnel `interface_luid` must be valid
    pub unsafe fn set_tunnel_interface(&self, interface_luid: u64) {
        #[allow(clippy::expect_used)]
        let mut socks = self.sockets.lock().expect("Mutex should not be poisoned");
        socks.tunnel_interface = Some(interface_luid);
        socks.notify.notify_waiters();
    }
}

impl Drop for NativeProtector {
    fn drop(&mut self) {
        self.monitor.abort();
    }
}

impl Protector for NativeProtector {
    unsafe fn make_external(&self, socket: NativeSocket) -> io::Result<()> {
        #[allow(clippy::expect_used)]
        let mut socks = self.sockets.lock().expect("Mutex should not be poisoned");
        socks.sockets.push(socket);
        socks.rebind(true);
        Ok(())
    }

    unsafe fn clean(&self, socket: NativeSocket) {
        #[allow(clippy::expect_used)]
        let mut socks = self.sockets.lock().expect("Mutex should not be poisoned");
        socks.sockets.retain(|s| s != &socket);
        socks.notify.notify_waiters();
    }
}

struct Sockets {
    sockets: Vec<NativeSocket>,
    tunnel_interface: Option<u64>,
    default_interface: Option<Interface>,
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

    fn rebind(&mut self, force: bool) {
        let tunnel_interface = match self.tunnel_interface {
            Some(tun_if) => tun_if,
            None => return,
        };
        if self.sockets.is_empty() {
            return;
        }
        let new_default_interface = match get_default_interface(tunnel_interface) {
            Ok(def) => Some(def),
            Err(e) => {
                log::warn!("Failed to get default interface {}", e);
                return;
            }
        };
        if !force && self.default_interface == new_default_interface {
            return;
        }
        self.default_interface = new_default_interface;

        // TODO: dont rebind all sockets if new socket is added
        for sock in &self.sockets {
            if let Some(interface) = self.default_interface.as_ref() {
                log::debug!(
                    "Binding relay socket to default interface: {}",
                    interface.index
                );
                let _ = interface.bind(*sock, AF_INET as u16);
            }
        }
    }
}

// Windows logic

fn spawn_monitor(sockets: Arc<Mutex<Sockets>>) -> io::Result<JoinHandle<()>> {
    let (iface_tx, mut iface_rx) = mpsc::channel(100);
    let _watcher = IfWatcher::new(iface_tx)?;

    Ok(tokio::spawn(async move {
        let _watcher = _watcher;
        let mut on = true;
        while on {
            let (ready, update) = {
                #[allow(clippy::expect_used)]
                let sockets = sockets.lock().expect("Mutex should not be poisoned");
                (
                    sockets.tunnel_interface.is_some() && !sockets.sockets.is_empty(),
                    sockets.notify.clone(),
                )
            };

            tokio::select! {
                iface_rx = iface_rx.recv(), if on && ready => {
                    if let Some(iface_rx) = iface_rx {
                        if iface_rx.index != 0 {
                            #[allow(clippy::expect_used)]
                            let mut socks = sockets.lock().expect("Mutex should not be poisoned");
                            socks.rebind(false);
                        }
                    } else {
                        log::error!("Interface watcher died.");
                        on = false;
                    }
                }
                _ = update.notified() => {
                    #[allow(clippy::expect_used)]
                    let mut socks = sockets.lock().expect("Mutex should not be poisoned");
                    socks.rebind(true);
                }
            }
        }
    }))
}

struct IfWatcher {
    _notif: ChangeNotification,
}

#[derive(Clone)]
struct Interface {
    index: u32,
    ip: Ipv4Addr,
}

impl Default for Interface {
    fn default() -> Self {
        Interface {
            index: 0,
            ip: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl IfWatcher {
    fn new(tx: Sender<Interface>) -> Result<Self> {
        Ok(Self {
            _notif: ChangeNotification::new(tx)?,
        })
    }
}

struct ChangeNotification {
    _tx: Box<Sender<Interface>>,
    route_cb_handle: HANDLE,
    iface_cb_handle: HANDLE,
}

impl Interface {
    fn bind(&self, socket: RawSocket, family: ADDRESS_FAMILY) -> i32 {
        let ip_unicast_if = 31;
        let level = if family == AF_INET6 as u16 { 41 } else { 0 };
        let array: [i8; 4] = unsafe { std::mem::transmute(self.index.to_be()) };
        unsafe {
            setsockopt(
                socket as usize,
                level,
                ip_unicast_if,
                &array as *const i8,
                4,
            )
        }
    }
}

#[allow(non_snake_case)]
unsafe extern "system" fn global_route_callback(
    CallerContext: PVOID,
    Row: *mut MIB_IPFORWARD_ROW2,
    NotificationType: MIB_NOTIFICATION_TYPE,
) {
    if NotificationType != MibAddInstance {
        return;
    }
    if (*Row).SitePrefixLength != 0 {
        return;
    }

    let interface: Interface = Interface {
        index: (*Row).InterfaceIndex,
        ..Default::default()
    };

    #[allow(clippy::unwrap_used)]
    let _ = (CallerContext as *mut Sender<Interface>)
        .as_ref()
        .unwrap()
        .blocking_send(interface);
}

#[allow(non_snake_case)]
unsafe extern "system" fn global_iface_callback(
    CallerContext: PVOID,
    Row: *mut MIB_IPINTERFACE_ROW,
    NotificationType: MIB_NOTIFICATION_TYPE,
) {
    if NotificationType != MibAddInstance {
        return;
    }
    if (*Row).SitePrefixLength != 0 {
        return;
    }

    let interface: Interface = Interface {
        index: (*Row).InterfaceIndex,
        ..Default::default()
    };

    #[allow(clippy::unwrap_used)]
    let _ = (CallerContext as *mut Sender<Interface>)
        .as_ref()
        .unwrap()
        .blocking_send(interface);
}

impl ChangeNotification {
    fn new(tx: Sender<Interface>) -> Result<Self> {
        let mut route_cb_handle = core::ptr::null_mut();
        let mut iface_cb_handle = core::ptr::null_mut();
        let mut tx = Box::new(tx);

        if unsafe {
            NotifyRouteChange2(
                AF_INET as _,
                Some(global_route_callback),
                tx.as_mut() as *mut Sender<Interface> as _,
                0,
                &mut route_cb_handle,
            )
        } != NO_ERROR
            && unsafe {
                NotifyIpInterfaceChange(
                    AF_INET as _,
                    Some(global_iface_callback),
                    tx.as_mut() as *mut Sender<Interface> as _,
                    0,
                    &mut iface_cb_handle,
                )
            } != NO_ERROR
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self {
                _tx: tx,
                route_cb_handle,
                iface_cb_handle,
            })
        }
    }
}

impl Drop for ChangeNotification {
    fn drop(&mut self) {
        unsafe {
            CancelMibChangeNotify2(self.route_cb_handle);
            CancelMibChangeNotify2(self.iface_cb_handle);
        }
    }
}

unsafe impl Send for ChangeNotification {}

fn get_default_interface(tunnel_interface: u64) -> Result<Interface> {
    let mut table: PMIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET as u16, &mut table) } != NO_ERROR {
        return Err(std::io::Error::last_os_error());
    }

    let mut lowest_metric = u32::MAX;
    let mut index: u32 = 0;

    let table = match unsafe { table.as_ref() } {
        Some(table) => table,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Table entry doesnt exist!",
            ))
        }
    };

    let mut interface_found = false;

    for i in 0..table.NumEntries {
        let row = unsafe { *(table.Table.as_ptr().add(i as usize)) };
        if row.InterfaceIndex == 0u32 {
            continue;
        }
        if row.DestinationPrefix.PrefixLength != 0u8 {
            continue;
        }

        let mut ifrow: MIB_IF_ROW2 = MIB_IF_ROW2 {
            InterfaceLuid: row.InterfaceLuid,
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut ifrow as PMIB_IF_ROW2) } != NO_ERROR {
            return Err(std::io::Error::last_os_error());
        }
        if ifrow.OperStatus != IfOperStatusUp {
            log::debug!(
                "Interface {} is not up (Status: {}) -> skip",
                ifrow.InterfaceIndex,
                ifrow.OperStatus
            );
            continue;
        }

        if row.InterfaceLuid.Value == tunnel_interface {
            continue;
        }

        let mut iface: MIB_IPINTERFACE_ROW = MIB_IPINTERFACE_ROW {
            InterfaceLuid: row.InterfaceLuid,
            Family: AF_INET as u16,
            ..Default::default()
        };

        let err = unsafe { GetIpInterfaceEntry(&mut iface as PMIB_IPINTERFACE_ROW) };
        if err != NO_ERROR {
            return Err(std::io::Error::last_os_error());
        }

        if row.Metric + iface.Metric < lowest_metric {
            log::debug!(
                "Metric: row {}, interface {}, lowest {}",
                row.Metric,
                iface.Metric,
                lowest_metric
            );
            lowest_metric = row.Metric + iface.Metric;
            index = row.InterfaceIndex;
            interface_found = true;
        }
    }

    if !interface_found {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Couldn't find default interface!",
        ));
    }

    log::debug!("Default interface index {}", index);

    let mut out_buf_len = std::mem::size_of::<IP_ADAPTER_INFO>() as u32;
    let mut raw_adapter_mem: Vec<u8> = Vec::with_capacity(out_buf_len as usize);

    let mut res = unsafe {
        GetAdaptersInfo(
            raw_adapter_mem.as_mut_ptr() as *mut IP_ADAPTER_INFO,
            &mut out_buf_len,
        )
    };

    if res == ERROR_BUFFER_OVERFLOW {
        raw_adapter_mem = Vec::with_capacity(out_buf_len as usize);
        unsafe {
            res = GetAdaptersInfo(
                raw_adapter_mem.as_mut_ptr() as *mut IP_ADAPTER_INFO,
                &mut out_buf_len,
            );
        }
    }

    if res != NO_ERROR {
        return Err(std::io::Error::last_os_error());
    }

    let mut p_adapter: *mut IP_ADAPTER_INFO = raw_adapter_mem.as_mut_ptr() as *mut IP_ADAPTER_INFO;

    let mut default_interface = Interface {
        index,
        ip: Ipv4Addr::new(0, 0, 0, 0),
    };

    interface_found = false;
    while p_adapter as u64 != 0 {
        let address = unsafe { (*p_adapter).IpAddressList };
        let adapter_index = unsafe { (*p_adapter).Index };

        if index == adapter_index {
            default_interface.ip = std::str::from_utf8(unsafe {
                &*((&address.IpAddress.String) as *const [i8] as *const [u8])
            })
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "Couldn't parse the address")
            })?
            .trim_matches(char::from(0))
            .parse::<Ipv4Addr>()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "Couldn't parse the address")
            })?;

            interface_found = true;
            break;
        }

        unsafe {
            p_adapter = (*p_adapter).Next;
        }
    }

    if !interface_found {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Couldn't find default interface ip address!",
        ));
    }

    log::debug!("Default interface addr {:?}", default_interface.ip);

    Ok(default_interface)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
    use std::os::windows::io::AsRawSocket;

    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[case(IpAddr::V6(Ipv6Addr::LOCALHOST))]
    #[tokio::test]
    async fn make_external(#[case] ip_addr: IpAddr) {
        let protector = NativeProtector::new().unwrap();

        let socket = UdpSocket::bind((ip_addr, 0)).unwrap();
        unsafe { protector.make_external(socket.as_raw_socket()).unwrap() }

        let socket = TcpListener::bind((ip_addr, 0)).unwrap();
        unsafe { protector.make_external(socket.as_raw_socket()).unwrap() }
    }

    #[test]
    #[ignore]
    fn watcher() {
        use std::{thread, time};
        use tokio::sync::mpsc::channel;

        println!("Starting watcher...");
        let (tx, mut rx) = channel(100);
        let _watcher = IfWatcher::new(tx);
        loop {
            println!("Loop started...");
            let interface = rx.blocking_recv().unwrap();
            println!(
                "interface index {:?}, ip {:?}",
                interface.index, interface.ip
            );
            let ten_millis = time::Duration::from_millis(10);
            thread::sleep(ten_millis);
        }
    }
}
