#![cfg(windows)]
//
// Port supporting code for wireguard-nt from wireguard-windows v0.5.3 to Rust
// This file implements functionality similar to: wireguard-windows/tunnel/mtumonitor.go
// and its dependencies in wireguard-windows/tunnel/winipcfg/route_change_handler.go
//

use super::winipcfg::luid::InterfaceLuid;
use std::ptr;
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};
use winapi::shared::{
    ifdef::IfOperStatusUp,
    netioapi::*,
    ntdef::{HANDLE, NULL, PVOID},
    winerror::*,
    ws2def::*,
};

pub struct MtuMonitor {
    own_luid: u64,
    family: ADDRESS_FAMILY,
    min_mtu: u32,

    last_mtu: u32,

    // OS change-notification handles; see the `unsafe impl Send` below.
    route_cb_handle: HANDLE,
    iface_cb_handle: HANDLE,
}

// SAFETY: `route_cb_handle` and `iface_cb_handle` are opaque OS
// change-notification handles. They are never dereferenced, only handed back
// to CancelMibChangeNotify2, which may be called from any thread. The monitor
// is therefore safe to move between threads.
unsafe impl Send for MtuMonitor {}

impl MtuMonitor {
    pub fn new(own_luid: u64, family: ADDRESS_FAMILY) -> Self {
        #[allow(non_snake_case)]
        let min_mtu = match family as i32 {
            AF_INET => 576,
            AF_INET6 => 1280,
            _ => 0,
        };
        Self {
            own_luid,
            family,
            min_mtu,
            last_mtu: 0,

            route_cb_handle: NULL,
            iface_cb_handle: NULL,
        }
    }

    pub fn start_monitoring(&mut self) -> Result<(), NETIO_STATUS> {
        self.do_it()?;

        let mut cb_handle: HANDLE = NULL;
        let result = unsafe {
            winapi::shared::netioapi::NotifyRouteChange2(
                self.family,
                Some(Self::route_change_callback),
                self as *mut Self as _,
                false as _,
                &mut cb_handle,
            )
        };
        if NO_ERROR != result {
            return Err(result);
        }
        self.route_cb_handle = cb_handle;

        let mut cb_handle: HANDLE = NULL;
        let result = unsafe {
            winapi::shared::netioapi::NotifyIpInterfaceChange(
                self.family,
                Some(Self::interface_change_callback),
                self as *mut Self as _,
                false as _,
                &mut cb_handle,
            )
        };
        if NO_ERROR != result {
            return Err(result);
        }
        self.iface_cb_handle = cb_handle;

        Ok(())
    }

    pub fn stop(&mut self) {
        telio_log_trace!("+++ MtuMonitor::stop");

        unsafe {
            if !self.route_cb_handle.is_null() {
                CancelMibChangeNotify2(self.route_cb_handle);
                self.route_cb_handle = NULL;
            }

            if !self.iface_cb_handle.is_null() {
                CancelMibChangeNotify2(self.iface_cb_handle);
                self.iface_cb_handle = NULL;
            }
        }

        telio_log_trace!("--- MtuMonitor::stop");
    }

    #[allow(non_snake_case)]
    extern "system" fn route_change_callback(
        CallerContext: PVOID,
        Row: *mut MIB_IPFORWARD_ROW2,
        NotificationType: MIB_NOTIFICATION_TYPE,
    ) {
        assert!(!Row.is_null());
        telio_log_trace!(
            "+++ MtuMonitor::route_change_callback: CallerContext {:p}, Row {:p}, NotificationType {}",
            CallerContext,
            Row,
            NotificationType
        );

        let self_ptr = CallerContext as *mut MtuMonitor;
        assert!(!self_ptr.is_null());
        if 0 == unsafe { (*Row).DestinationPrefix.PrefixLength } {
            // Result can be ignored
            match unsafe { (*self_ptr).do_it() } {
                Ok(_) => {}
                Err(err) => {
                    telio_log_trace!("MtuMonitor::do_it returned error {}", err);
                }
            }
        }

        telio_log_trace!(
            "--- MtuMonitor::route_change_callback: CallerContext {:p}, Row {:p}, NotificationType {}",
            CallerContext,
            Row,
            NotificationType
        );
    }

    #[allow(non_snake_case)]
    extern "system" fn interface_change_callback(
        CallerContext: PVOID,
        Row: *mut MIB_IPINTERFACE_ROW,
        NotificationType: MIB_NOTIFICATION_TYPE,
    ) {
        telio_log_trace!(
            "+++ MtuMonitor::interface_change_callback: CallerContext {:p}, Row {:p}, NotificationType {}",
            CallerContext,
            Row,
            NotificationType
        );

        let self_ptr = CallerContext as *mut MtuMonitor;
        assert!(!self_ptr.is_null());
        if NotificationType == MibParameterNotification {
            // Result can be ignored
            match unsafe { (*self_ptr).do_it() } {
                Ok(_) => {}
                Err(err) => {
                    telio_log_trace!("MtuMonitor::do_it returned error {}", err);
                }
            }
        }

        telio_log_trace!(
            "--- MtuMonitor::interface_change_callback: CallerContext {:p}, Row {:p}, NotificationType {}",
            CallerContext,
            Row,
            NotificationType
        );
    }

    fn do_it(&mut self) -> Result<(), NETIO_STATUS> {
        telio_log_trace!("+++ MtuMonitor::do_it");

        telio_log_trace!("+++ MtuMonitor::do_it: find_default_luid");
        let default_luid = self.find_default_luid()?;
        telio_log_trace!("--- MtuMonitor::do_it: find_default_luid");

        let mut mtu: u32 = 0;

        if 0 != default_luid {
            let default_luid = InterfaceLuid::new(default_luid);
            telio_log_trace!("+++ MtuMonitor::do_it: get_interface");
            let default_iface = default_luid.get_interface()?;
            if default_iface.Mtu > 0 {
                mtu = default_iface.Mtu;
            }
        }

        if mtu > 0 && self.last_mtu != mtu {
            let own_luid = InterfaceLuid::new(self.own_luid);
            telio_log_trace!("+++ MtuMonitor::do_it: get_ip_interface");
            let mut own_iface = own_luid.get_ip_interface(self.family)?;
            own_iface.NlMtu = mtu.saturating_sub(80);
            if own_iface.NlMtu < self.min_mtu {
                own_iface.NlMtu = self.min_mtu;
            }

            telio_log_trace!("+++ MtuMonitor::do_it: SetIpInterfaceEntry");
            let result = unsafe { SetIpInterfaceEntry(&mut own_iface) };
            if NO_ERROR != result {
                return Err(result);
            }
            self.last_mtu = mtu;
        }

        telio_log_trace!("--- MtuMonitor::do_it");

        Ok(())
    }

    fn find_default_luid(&self) -> Result<u64, NETIO_STATUS> {
        let mut p_table: PMIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let result = unsafe { GetIpForwardTable2(self.family, &mut p_table) };
        if NO_ERROR != result {
            telio_log_trace!(
                "find_default_luid failed GetIpForwardTable2 with {}",
                result
            );
            return Err(result);
        }
        let mut lowest_metric: u32 = u32::MAX;
        let mut luid: u64 = 0;

        assert!(!p_table.is_null());
        let num_entries = unsafe { (*p_table).NumEntries };
        let x_table = unsafe { (*p_table).Table.as_ptr() };
        for i in 0..num_entries {
            let current_entry = unsafe { x_table.add(i as _) };

            if 0 != unsafe { (*current_entry).DestinationPrefix.PrefixLength } {
                continue;
            }
            if unsafe { (*current_entry).InterfaceLuid.Value } == self.own_luid {
                continue;
            }

            let current_interface =
                InterfaceLuid::new(unsafe { (*current_entry).InterfaceLuid.Value });
            match current_interface.get_interface() {
                Ok(ifrow) => {
                    if IfOperStatusUp != ifrow.OperStatus {
                        continue;
                    }
                }
                Err(_) => {
                    continue;
                }
            }
            match current_interface.get_ip_interface(self.family) {
                Ok(iface) => {
                    let current_metric = unsafe { (*current_entry).Metric + iface.Metric };
                    if current_metric < lowest_metric {
                        lowest_metric = current_metric;
                        luid = unsafe { (*current_entry).InterfaceLuid.Value };
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }

        unsafe { FreeMibTable(p_table as _) };

        Ok(luid)
    }
}

#[cfg(windows)]
impl Drop for MtuMonitor {
    fn drop(&mut self) {
        telio_log_trace!("+++ MtuMonitor::drop");
        self.stop();
        telio_log_trace!("--- MtuMonitor::drop");
    }
}
