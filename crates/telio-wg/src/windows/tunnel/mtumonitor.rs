#![cfg(windows)]
//
// Port supporting code for wireguard-nt from wireguard-windows v0.5.3 to Rust
// This file implements functionality similar to: wireguard-windows/tunnel/mtumonitor.go
// and its dependencies in wireguard-windows/tunnel/winipcfg/route_change_handler.go
//

use super::winipcfg::luid::InterfaceLuid;
use std::sync::{Arc, Mutex};
use std::{mem, ptr};
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

    last_luid: u64,
    last_index: i32,
    last_mtu: u32,

    // Quickhack: Adapter is Sync+Send, so it cannot hold any substructures with raw ptr / HANDLE
    route_cb_handle: Arc<Mutex<usize>>, // route_cb_handle: HANDLE,
    iface_cb_handle: Arc<Mutex<usize>>, // iface_cb_handle: HANDLE,
}

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
            last_luid: 0,
            last_index: -1,
            last_mtu: 0,

            route_cb_handle: Arc::new(Mutex::new(0)),
            iface_cb_handle: Arc::new(Mutex::new(0)),
        }
    }

    pub unsafe fn start_monitoring(&mut self) -> Result<(), NETIO_STATUS> {
        self.do_it()?;

        if let Ok(mut route_cb_handle) = self.route_cb_handle.clone().lock() {
            let mut cb_handle: HANDLE = NULL;
            let result = winapi::shared::netioapi::NotifyRouteChange2(
                self.family,
                Some(Self::route_change_callback),
                self as *mut Self as _,
                false as _,
                &mut cb_handle,
            );
            if NO_ERROR != result {
                return Err(result);
            }
            *route_cb_handle = cb_handle as _;
        }

        if let Ok(mut iface_cb_handle) = self.iface_cb_handle.clone().lock() {
            let mut cb_handle: HANDLE = NULL;
            let result = winapi::shared::netioapi::NotifyIpInterfaceChange(
                self.family,
                Some(Self::interface_change_callback),
                self as *mut Self as _,
                false as _,
                &mut cb_handle,
            );
            if NO_ERROR != result {
                return Err(result);
            }
            *iface_cb_handle = cb_handle as _;
        } else {
            telio_log_error!("error obtaining lock");
            return Err(ERROR_INVALID_PARAMETER);
        }

        Ok(())
    }

    pub fn stop(&self) {
        telio_log_trace!("+++ MtuMonitor::stop");

        if let Ok(mut route_cb_handle) = self.route_cb_handle.clone().lock() {
            unsafe {
                if 0 != *route_cb_handle {
                    CancelMibChangeNotify2(*route_cb_handle as HANDLE);
                    *route_cb_handle = 0;
                }
            }
        } else {
            telio_log_error!("error obtaining lock");
        }

        if let Ok(mut iface_cb_handle) = self.iface_cb_handle.clone().lock() {
            unsafe {
                if 0 != *iface_cb_handle {
                    CancelMibChangeNotify2(*iface_cb_handle as HANDLE);
                    *iface_cb_handle = 0;
                }
            }
        } else {
            telio_log_error!("error obtaining lock");
        }

        telio_log_trace!("--- MtuMonitor::stop");
    }

    #[allow(non_snake_case)]
    unsafe extern "system" fn route_change_callback(
        CallerContext: PVOID,
        Row: *mut MIB_IPFORWARD_ROW2,
        NotificationType: MIB_NOTIFICATION_TYPE,
    ) {
        telio_log_trace!(
            "+++ MtuMonitor::route_change_callback: CallerContext {:p}, Row {:p}, NotificationType {}",
            CallerContext,
            Row,
            NotificationType
        );

        let self_ptr = CallerContext as *mut MtuMonitor;
        if 0 == (*Row).DestinationPrefix.PrefixLength {
            // Result can be ignored
            match (*self_ptr).do_it() {
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
    unsafe extern "system" fn interface_change_callback(
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
        if NotificationType == MibParameterNotification {
            // Result can be ignored
            match (*self_ptr).do_it() {
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

    unsafe fn do_it(&mut self) -> Result<(), NETIO_STATUS> {
        telio_log_trace!("+++ MtuMonitor::do_it");

        telio_log_trace!("+++ MtuMonitor::do_it: find_default_luid");
        self.find_default_luid()?;
        telio_log_trace!("--- MtuMonitor::do_it: find_default_luid");

        let mut mtu: u32 = 0;

        if 0 != self.last_luid {
            let last_luid = InterfaceLuid::new(self.last_luid);
            telio_log_trace!("+++ MtuMonitor::do_it: get_interface");
            let last_iface = last_luid.get_interface()?;
            if last_iface.Mtu > 0 {
                mtu = last_iface.Mtu;
            }
        }

        if mtu > 0 && self.last_mtu != mtu {
            let own_luid = InterfaceLuid::new(self.own_luid);
            telio_log_trace!("+++ MtuMonitor::do_it: get_ip_interface");
            let mut own_iface = own_luid.get_ip_interface(self.family)?;
            own_iface.NlMtu = mtu - 80;
            if own_iface.NlMtu < self.min_mtu {
                own_iface.NlMtu = self.min_mtu;
            }

            telio_log_trace!("+++ MtuMonitor::do_it: SetIpInterfaceEntry");
            let result = SetIpInterfaceEntry(&mut own_iface);
            if NO_ERROR != result {
                return Err(result);
            }
            self.last_mtu = mtu;
        }

        telio_log_trace!("--- MtuMonitor::do_it");

        Ok(())
    }

    unsafe fn find_default_luid(&mut self) -> Result<(), NETIO_STATUS> {
        let mut p_table: PMIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let result = GetIpForwardTable2(self.family, &mut p_table);
        if NO_ERROR != result {
            telio_log_trace!(
                "find_default_luid failed GetIpForwardTable2 with {}",
                result
            );
            return Err(result);
        }

        let mut lowest_metric: u32 = u32::MAX;
        let mut index: u32 = 0;
        let mut luid: u64 = 0;

        let num_entries = (*p_table).NumEntries;
        let x_table = (*p_table).Table.as_ptr();
        for i in 0..num_entries {
            let current_entry = x_table.add(i as _);

            if 0 != (*current_entry).DestinationPrefix.PrefixLength {
                continue;
            }
            if (*current_entry).InterfaceLuid.Value == self.own_luid {
                continue;
            }

            let current_interface = InterfaceLuid::new((*current_entry).InterfaceLuid.Value);
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
                    let current_metric = (*current_entry).Metric + iface.Metric;
                    if current_metric < lowest_metric {
                        lowest_metric = current_metric;
                        index = (*current_entry).InterfaceIndex;
                        luid = (*current_entry).InterfaceLuid.Value;
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }

        FreeMibTable(p_table as _);

        self.last_luid = luid;
        self.last_index = index as i32;

        Ok(())
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
