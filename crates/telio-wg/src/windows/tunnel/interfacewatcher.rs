#![cfg(windows)]
#![allow(dead_code)]

//
// Port supporting code for wireguard-nt from wireguard-windows v0.5.3 to Rust
// This file implements functionality similar to: wireguard-windows/tunnel/interfacewatcher.go
//
// There are some configuration options specific to WireGuard for Windows which we don't
// set from within the Adapter class, because we only have the SetInterface and Peers structures.
// The relevant Go code has been kept as a reference in comments
// with an OPTWGWINCONF tag (= "optional WireGuard for Windows configuration").
//

use super::addressconfig;
use super::mtumonitor::MtuMonitor;
use crate::windows::cleanup::*;
use std::sync::{Arc, Mutex, MutexGuard};
use std::{mem, option, ptr};
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn, Hidden,
};
use winapi::shared::{
    ifdef::IfOperStatusUp,
    netioapi::*,
    ntdef::{HANDLE, NULL, PVOID},
    winerror::*,
    ws2def::*,
};

pub struct InterfaceWatcher {
    // Quickhack: Adapter is Sync+Send, so it cannot hold any substructures with raw ptr / HANDLE
    iface_cb_handle: Arc<Mutex<usize>>, // iface_cb_handle: HANDLE,

    watched_adapter: Arc<Mutex<AdapterConfiguration>>,
    enable_dynamic_wg_nt_control: bool,
}

struct AdapterConfiguration {
    luid: u64,
    adapter: Option<Arc<wireguard_nt::Adapter>>,
    stored_events: Vec<InterfaceWatcherEvent>,

    last_known_config: Option<Arc<WireGuardUapiSetDevice>>,

    mtu_monitor: Vec<Arc<Mutex<MtuMonitor>>>,
}

struct InterfaceWatcherEvent {
    pub luid: u64,
    pub family: ADDRESS_FAMILY,
}

#[derive(Debug, Default, PartialEq)]
struct WireGuardUapiSetDevice {
    // Create a local copy of the configuration
    // Workaround: wireguard_uapi::xplatform::set::Device does not implement Clone
    config: wireguard_uapi::xplatform::set::Device,
}

impl WireGuardUapiSetDevice {
    pub fn new(config: &wireguard_uapi::xplatform::set::Device) -> Self {
        // Create a local copy of the configuration
        WireGuardUapiSetDevice {
            config: wireguard_uapi::xplatform::set::Device {
                private_key: config.private_key.clone(),
                listen_port: config.listen_port,
                fwmark: config.fwmark,
                replace_peers: config.replace_peers,
                peers: config.peers.clone(),
            },
        }
    }
}

impl AdapterConfiguration {
    pub fn new() -> Self {
        Self {
            luid: 0,
            adapter: None,
            stored_events: Vec::new(),
            last_known_config: None,
            mtu_monitor: Vec::new(),
        }
    }
}

impl InterfaceWatcher {
    pub fn new(enable_dynamic_wg_nt_control: bool) -> Self {
        telio_log_trace!("InterfaceWatcher::new");
        Self {
            iface_cb_handle: Arc::new(Mutex::new(0)), // iface_cb_handle: NULL,

            watched_adapter: Arc::new(Mutex::new(AdapterConfiguration::new())),
            enable_dynamic_wg_nt_control,
        }
    }

    pub fn start_monitoring(&mut self) -> Result<(), NETIO_STATUS> {
        /*
        TODO: implement a watchdog which will wait up to 1 min for our adapter to come up. Does not seem necessary.
        //
        iw.watchdog = time.AfterFunc(time.Duration(1<<63-1), func() {
            iw.errors <- interfaceWatcherError{services.ErrorCreateNetworkAdapter, errors.New("TCP/IP interface for adapter did not appear after one minute")}
        })
        iw.watchdog.Stop()
        */

        telio_log_trace!("+++ InterfaceWatcher::start_monitoring");

        if let Ok(mut iface_cb_handle) = self.iface_cb_handle.clone().lock() {
            let mut cb_handle: HANDLE = NULL;
            let result = unsafe {
                winapi::shared::netioapi::NotifyIpInterfaceChange(
                    AF_UNSPEC as _,
                    Some(Self::interface_change_callback),
                    self as *mut Self as _,
                    false as _,
                    &mut cb_handle,
                )
            };
            telio_log_trace!("--- InterfaceWatcher::start_monitoring {}", result);
            if NO_ERROR != result {
                Err(result)
            } else {
                *iface_cb_handle = cb_handle as _;
                Ok(())
            }
        } else {
            telio_log_error!("error obtaining lock");
            Err(ERROR_INVALID_PARAMETER)
        }
    }

    pub fn stop(&self) {
        telio_log_trace!("+++ InterfaceWatcher::stop");

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

        if let Ok(watched_adapter) = self.watched_adapter.clone().lock() {
            for mtu_monitor in watched_adapter.mtu_monitor.as_slice() {
                if let Ok(mtumon) = mtu_monitor.clone().lock() {
                    mtumon.stop();
                }
            }
        } else {
            telio_log_error!("error obtaining lock");
        }

        telio_log_trace!("--- InterfaceWatcher::stop");
    }

    pub fn configure(&mut self, adapter: Arc<wireguard_nt::Adapter>, luid: u64) {
        telio_log_trace!("+++ InterfaceWatcher::configure");

        if let Ok(mut watched_adapter) = self.watched_adapter.clone().lock() {
            // TODO: restart watchdog
            // iw.watchdog.Reset(time.Minute)

            watched_adapter.luid = luid;
            watched_adapter.adapter = Some(adapter);

            watched_adapter.last_known_config = None;

            let mut setup_ipv4 = false;
            let mut setup_ipv6 = false;
            for event in watched_adapter.stored_events.as_slice() {
                if event.luid == luid {
                    match event.family as i32 {
                        AF_INET => {
                            setup_ipv4 = true;
                        }
                        AF_INET6 => {
                            setup_ipv6 = true;
                        }
                        _ => {}
                    }
                }
            }
            watched_adapter.stored_events.clear();

            if setup_ipv4 {
                Self::setup(&mut watched_adapter, AF_INET as _);
            }
            if setup_ipv6 {
                Self::setup(&mut watched_adapter, AF_INET6 as _);
            }
        } else {
            telio_log_error!("error obtaining lock");
        }

        telio_log_trace!("--- InterfaceWatcher::configure");
    }

    pub fn set_last_known_configuration(
        &mut self,
        config: &wireguard_uapi::xplatform::set::Device,
    ) {
        telio_log_trace!("+++ InterfaceWatcher::set_last_known_configuration");

        if let Ok(mut watched_adapter) = self.watched_adapter.clone().lock() {
            watched_adapter.last_known_config = Some(Arc::new(WireGuardUapiSetDevice::new(config)));
        } else {
            telio_log_error!("error obtaining lock");
        }

        telio_log_trace!("--- InterfaceWatcher::set_last_known_configuration");
    }

    pub fn clear_last_known_configuration(&mut self) {
        telio_log_trace!("+++ InterfaceWatcher::clear_last_known_configuration");

        if let Ok(mut watched_adapter) = self.watched_adapter.clone().lock() {
            watched_adapter.last_known_config = None;
        } else {
            telio_log_error!("error obtaining lock");
        }

        telio_log_trace!("--- InterfaceWatcher::clear_last_known_configuration");
    }

    fn setup(watched_adapter: &mut AdapterConfiguration, family: ADDRESS_FAMILY) {
        telio_log_trace!("+++ InterfaceWatcher::setup");

        let family_str: String = match family as i32 {
            AF_INET => "IPv4".to_string(),
            AF_INET6 => "IPv6".to_string(),
            _ => format!("unk {family}"),
        };

        // TODO: we have successfully started the adapter, now stop watchdog
        // iw.watchdog.Stop()

        // OPTWGWINCONF: use MtuMonitor to dynamically adjust the MTU size, if it wasn't forced by config.
        // if iw.conf.Interface.MTU == 0
        {
            telio_log_info!("Monitoring MTU of default routes for {}", family_str);
            let arc_mtu_monitor =
                Arc::new(Mutex::new(MtuMonitor::new(watched_adapter.luid, family)));
            if let Ok(mut mtu_monitor) = arc_mtu_monitor.lock() {
                match mtu_monitor.start_monitoring() {
                    Ok(_) => {
                        watched_adapter.mtu_monitor.push(arc_mtu_monitor.clone());
                    }
                    Err(_err) => {
                        // TODO: collect and broadcast errors?
                        // iw.errors <- interfaceWatcherError{services.ErrorMonitorMTUChanges, err}
                    }
                }
            };
        }

        if let Some(last_known_config) = &watched_adapter.last_known_config {
            telio_log_info!("Setting device addresses for {}", family_str);
            match addressconfig::configure_interface(
                family,
                &last_known_config.config,
                watched_adapter.luid,
            ) {
                Ok(_) => {}
                Err(_err) => {
                    // TODO: collect and broadcast errors?
                    // iw.errors <- interfaceWatcherError{services.ErrorSetNetConfig, err}
                }
            }
        } else {
            telio_log_info!("Adapter config not set");
        }

        // TODO: It would be nice to check for some specific rare cases such as buggy virtio drivers
        // evaluateDynamicPitfalls(family, iw.conf, iw.luid)

        // TODO: collect and broadcast success?
        // iw.started <- family

        telio_log_trace!("--- InterfaceWatcher::setup");
    }

    fn mib_add_instance(&mut self, iface: *const MIB_IPINTERFACE_ROW) {
        telio_log_trace!("+++ InterfaceWatcher::mib_add_instance");

        if let Ok(mut watched_adapter) = self.watched_adapter.clone().lock() {
            if 0 == watched_adapter.luid {
                watched_adapter.stored_events.push(InterfaceWatcherEvent {
                    luid: unsafe { (*iface).InterfaceLuid.Value },
                    family: unsafe { (*iface).Family },
                });
                telio_log_trace!("--- InterfaceWatcher::mib_add_instance 1");
                return;
            }
            if unsafe { (*iface).InterfaceLuid.Value } != watched_adapter.luid {
                telio_log_trace!("--- InterfaceWatcher::mib_add_instance 2");
                return;
            }
            Self::setup(&mut watched_adapter, unsafe { (*iface).Family });

            #[allow(clippy::unwrap_used)]
            let adapter = watched_adapter.adapter.as_ref().unwrap();
            if let Ok(state) = adapter.get_adapter_state() {
                if wireguard_nt::WIREGUARD_STATE_DOWN == state {
                    if let Some(last_known_config) = &watched_adapter.last_known_config {
                        telio_log_info!("Reinitializing adapter configuration");
                        if let Err(err) = adapter.set_config_uapi(&last_known_config.config) {
                            telio_log_error!("Failed to set last known config: {}", err);
                        }
                    } else {
                        telio_log_info!("Adapter config not set");
                    }

                    // Bring interface up if needed
                    let has_peers = &watched_adapter
                        .last_known_config
                        .as_ref()
                        .is_some_and(|c| !c.config.peers.is_empty());
                    if self.enable_dynamic_wg_nt_control && !has_peers {
                        telio_log_info!("Skipping adatper.up() due to empty peer list");
                    } else if adapter.up().is_err() {
                        telio_log_error!("Adapter could not be set to online state");
                    }
                }
            } else {
                // No error code available from the Rust wrapper
                telio_log_error!("Querying adapter state failed");
            }
        } else {
            telio_log_error!("error obtaining lock");
        }

        telio_log_trace!("--- InterfaceWatcher::mib_add_instance LAST");
    }

    #[allow(non_snake_case, non_upper_case_globals)]
    unsafe extern "system" fn interface_change_callback(
        CallerContext: PVOID,
        Row: *mut MIB_IPINTERFACE_ROW,
        NotificationType: MIB_NOTIFICATION_TYPE,
    ) {
        telio_log_trace!(
            "+++ InterfaceWatcher::interface_change_callback: CallerContext {:p}, Row {:p}, NotificationType {}",
            CallerContext,
            Row,
            NotificationType
        );

        if Row.is_null() {
            return;
        }

        let self_ptr = CallerContext as *mut InterfaceWatcher;
        if NotificationType == MibAddInstance {
            (*self_ptr).mib_add_instance(Row);
        };

        telio_log_trace!(
            "--- InterfaceWatcher::interface_change_callback: CallerContext {:p}, Row {:p}, NotificationType {}",
            CallerContext,
            Row,
            NotificationType
        );
    }
}

impl Drop for InterfaceWatcher {
    fn drop(&mut self) {
        telio_log_trace!("+++ InterfaceWatcher::drop");

        self.stop();

        // TODO: disable those firewall rules we (could have) created for us to reach the peers (servers).
        // This whole firewall thing - is it necessary at all?
        // firewall.DisableFirewall()

        if let Ok(watched_adapter) = self.watched_adapter.clone().lock() {
            if 0 != watched_adapter.luid {
                cleanup_network_config(watched_adapter.luid);
            }
        } else {
            telio_log_error!("error obtaining lock");
        }

        telio_log_trace!("--- InterfaceWatcher::drop");
    }
}
