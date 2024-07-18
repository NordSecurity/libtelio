#![cfg(windows)]
#![allow(dead_code)]

//
// Port supporting code for wireguard-nt from wireguard-windows v0.5.3 to Rust
// This file implements functionality similar to: wireguard-windows/tunnel/addressconfig.go
//
// There are some configuration options specific to WireGuard for Windows which we don't
// set from within the Adapter class, because we only have the SetInterface and Peers structures.
// The relevant Go code has been kept as a reference in comments
// with an OPTWGWINCONF tag (= "optional WireGuard for Windows configuration").
//

use super::winipcfg::{luid::*, types::*};
use ipnet::{Ipv4Net, Ipv6Net};
use std::{
    alloc::{alloc, dealloc, Layout},
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};
use winapi::shared::{
    ifdef::IfOperStatusUp,
    netioapi::*,
    nldef::RouterDiscoveryDisabled,
    ntdef::{HANDLE, NULL, PVOID},
    winerror::*,
    ws2def::*,
    ws2ipdef::*,
};
use winapi::um::{iphlpapi::*, iptypes::*};

unsafe fn cleanup_addresses_on_disconnected_interfaces2(
    ptr_adapters: PIP_ADAPTER_ADDRESSES,
    _addresses: &[IP_ADDRESS_PREFIX],
) {
    let mut iface: PIP_ADAPTER_ADDRESSES = ptr_adapters;
    while !iface.is_null() {
        let iface_friendly_name = u16_ptr_to_string((*iface).FriendlyName);

        if (*iface).OperStatus != IfOperStatusUp {
            let luid = InterfaceLuid::new((*iface).Luid.Value);
            // TODO: collect addresses, deduplicate as in the original code

            let mut address = (*iface).FirstUnicastAddress;
            while !address.is_null() {
                let sockaddr_raw = (*address).Address.lpSockaddr;
                match (*sockaddr_raw).sa_family as i32 {
                    AF_INET => {
                        let sockaddr_ipv4: *mut SOCKADDR_IN = sockaddr_raw as _;
                        let ipv4_addr = convert_sockaddr_to_ipv4addr(&(*sockaddr_ipv4));
                        telio_log_info!(
                            "Cleaning up stale IPv4 address {} from itf {}",
                            ipv4_addr,
                            iface_friendly_name
                        );
                        match luid
                            .delete_ipv4_address2(sockaddr_ipv4, (*address).OnLinkPrefixLength)
                        {
                            Ok(_) => {}
                            Err(_err) => {}
                        };
                    }
                    AF_INET6 => {
                        let sockaddr_ipv6: *mut SOCKADDR_IN6 = sockaddr_raw as _;
                        telio_log_info!(
                            "Cleaning up stale IPv6 address {:?} from itf {}",
                            (*sockaddr_ipv6).sin6_addr.u.Byte(),
                            iface_friendly_name
                        );
                        match luid
                            .delete_ipv6_address2(sockaddr_ipv6, (*address).OnLinkPrefixLength)
                        {
                            Ok(_) => {}
                            Err(_err) => {}
                        };
                    }
                    _ => {}
                }

                address = (*address).Next;
            }
        }

        iface = (*iface).Next;
    }
}

unsafe fn cleanup_addresses_on_disconnected_interfaces(
    family: ADDRESS_FAMILY,
    addresses: &[IP_ADDRESS_PREFIX],
) -> Result<(), u32> {
    if addresses.is_empty() {
        return Ok(());
    }

    // Using a pre-allocated buffer of 64KB, we should avoid calling GetAdaptersAddresses() multiple times (slow!)
    let mut size_adapters: u32 = 65536;
    for _ in 0..5 {
        let layout_adapters = match Layout::from_size_align(size_adapters as _, 16) {
            Ok(layout) => layout,
            Err(_) => {
                return Err(ERROR_NOT_ENOUGH_MEMORY);
            }
        };
        let ptr_adapters: PIP_ADAPTER_ADDRESSES = alloc(layout_adapters) as PIP_ADAPTER_ADDRESSES;
        if ptr_adapters.is_null() {
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
        // ATTENTION, CLEANUP: Don't remove, this is for auto-deallocating ptr_adapters in this scope
        let _box_adapters = Box::from_raw(ptr_adapters);

        let result = GetAdaptersAddresses(family as _, 0, NULL, ptr_adapters, &mut size_adapters);
        match result {
            NO_ERROR => {
                cleanup_addresses_on_disconnected_interfaces2(ptr_adapters, addresses);
                return Ok(());
            }
            ERROR_BUFFER_OVERFLOW => {
                // Let the loop repeat, size_adapters was returned with a new buffer size to be allocated
            }
            _ => {
                return Err(result);
            }
        };
    }

    // This should not happen! We were trying to allocate memory for the NIC list 5x times using
    // a growing buffer, each time sized at least the size reported by OS.
    // This could be a pathological case like adding 10 NICs at once.
    Err(ERROR_BUFFER_OVERFLOW)
}

pub fn configure_interface(
    family: ADDRESS_FAMILY,
    config: &wireguard_uapi::xplatform::set::Device,
    luid: u64,
) -> Result<(), u32> {
    /*
        TODO: the code below is an extract from wireguard-windows in Go. It retries this function a couple of times
        if the machine just booted and could not configure the network stack promptly.
        It is unclear whether we need it, since we start the VPN when the service and the UI are up and running.

        retryOnFailure := services.StartedAtBoot()
        tryTimes := 0
    startOver:
        var err error
        if tryTimes > 0 {
            log.Printf("Retrying interface configuration after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
            time.Sleep(time.Second)
            retryOnFailure = retryOnFailure && tryTimes < 15
        }
        tryTimes++
        */

    telio_log_trace!("+++ AddressConfig::configure_interface");

    let iface = InterfaceLuid::new(luid);

    // Deduplicate routes as in the original code
    let mut routes_ipv4: HashSet<RouteDataIpv4> = HashSet::new();
    let mut routes_ipv6: HashSet<RouteDataIpv6> = HashSet::new();

    let mut found_default_ipv4 = false;
    let mut found_default_ipv6 = false;
    for peer in config.peers.as_slice() {
        for allowedip in peer.allowed_ips.as_slice() {
            match allowedip.ipaddr {
                IpAddr::V4(ipaddr) => {
                    let route = RouteDataIpv4 {
                        destination: Ipv4Net::new(ipaddr, allowedip.cidr_mask)
                            .map_err(|_| winapi::shared::winerror::ERROR_INVALID_PARAMETER)?,
                        next_hop: Ipv4Addr::UNSPECIFIED,
                        metric: 0,
                    };
                    routes_ipv4.insert(route);

                    if 0 == allowedip.cidr_mask {
                        found_default_ipv4 = true;
                    }
                }
                IpAddr::V6(ipaddr) => {
                    let route = RouteDataIpv6 {
                        destination: Ipv6Net::new(ipaddr, allowedip.cidr_mask)
                            .map_err(|_| winapi::shared::winerror::ERROR_INVALID_PARAMETER)?,
                        next_hop: Ipv6Addr::UNSPECIFIED,
                        metric: 0,
                    };
                    routes_ipv6.insert(route);

                    if 0 == allowedip.cidr_mask {
                        found_default_ipv6 = true;
                    }
                }
            }
        }
    }

    // OPTWGWINCONF: option for not setting routes
    // if !conf.interface.TableOff {
    match unsafe { iface.set_routes_ipv4(routes_ipv4) } {
        Ok(_) => {}
        Err(err) => {
            /*
            TODO: retry a couple of times if the machine just booted and could not configure the network stack promptly
            //
            if err == windows.ERROR_NOT_FOUND && retryOnFailure {
                goto startOver
            } else if err != nil {
                return fmt.Errorf("unable to set routes: %w", err)
            }
            */
            telio_log_error!("Unable to set IPv4 routes: {}", err);
            return Err(err);
        }
    }
    match unsafe { iface.set_routes_ipv6(routes_ipv6) } {
        Ok(_) => {}
        Err(err) => {
            /*
            TODO: retry a couple of times if the machine just booted and could not configure the network stack promptly
            //
            if err == windows.ERROR_NOT_FOUND && retryOnFailure {
                goto startOver
            } else if err != nil {
                return fmt.Errorf("unable to set routes: %w", err)
            }
            */
            telio_log_error!("Unable to set IPv6 routes: {}", err);
            return Err(err);
        }
    }
    // }    // if !conf.interface.TableOff

    /*
    OPTWGWINCONF: set the adapter's IP address. We do it - but somewhere else.
    //
    err = luid.SetIPAddressesForFamily(family, conf.Interface.Addresses)
    if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
        cleanupAddressesOnDisconnectedInterfaces(family, conf.Interface.Addresses)
        err = luid.SetIPAddressesForFamily(family, conf.Interface.Addresses)
    }
    if err == windows.ERROR_NOT_FOUND && retryOnFailure {
        goto startOver
    } else if err != nil {
        return fmt.Errorf("unable to set ips: %w", err)
    }
    */

    let mut ipif = unsafe { iface.get_ip_interface(family) }?;
    ipif.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    ipif.DadTransmits = 0;
    ipif.ManagedAddressConfigurationSupported = false as _;
    ipif.OtherStatefulConfigurationSupported = false as _;
    /*
    OPTWGWINCONF: force MTU size - we adjust our MTU size dynamically instead via MtuMonitor
    //
    if conf.Interface.MTU > 0 {
        ipif.NLMTU = uint32(conf.Interface.MTU)
    }
    */
    if (AF_INET as ADDRESS_FAMILY == family && found_default_ipv4)
        || (AF_INET6 as ADDRESS_FAMILY == family && found_default_ipv6)
    {
        ipif.UseAutomaticMetric = false as _;
        ipif.Metric = 0;
    }

    match unsafe { iface.set_ip_interface(&mut ipif) } {
        Ok(_) => {}
        Err(err) => {
            /*
            TODO: retry a couple of times if the machine just booted and could not configure the network stack promptly
            //
            if err == windows.ERROR_NOT_FOUND && retryOnFailure {
                goto startOver
            } else if err != nil {
                return fmt.Errorf("unable to set metric and MTU: %w", err)
            }
            */
            telio_log_error!("Unable to set adapter metric: {}", err);
            return Err(err);
        }
    }

    /*
    OPTWGWINCONF: set DNS servers via config file. We set DNS servers later from another routine.
    //
    err = luid.SetDNS(family, conf.Interface.DNS, conf.Interface.DNSSearch)
    if err == windows.ERROR_NOT_FOUND && retryOnFailure {
        goto startOver
    } else if err != nil {
        return fmt.Errorf("unable to set DNS: %w", err)
    }
    return nil
    */

    telio_log_trace!("--- AddressConfig::configure_interface OK");

    Ok(())
}

pub fn enable_firewall(_conf: u64, _luid: u64) -> Result<(), u32> {
    Ok(())
    /*
    TODO: set Windows firewall to allow connections to the peers (servers). Doesn't seem necessary.
    //
    func enableFirewall(conf *conf.Config, luid winipcfg.LUID) error {
    doNotRestrict := true
    if len(conf.Peers) == 1 && !conf.Interface.TableOff {
        for _, allowedip := range conf.Peers[0].AllowedIPs {
            if allowedip.Bits() == 0 && allowedip == allowedip.Masked() {
                doNotRestrict = false
                break
            }
        }
    }
    log.Println("Enabling firewall rules")
    return firewall.EnableFirewall(uint64(luid), doNotRestrict, conf.Interface.DNS)
    */
}
