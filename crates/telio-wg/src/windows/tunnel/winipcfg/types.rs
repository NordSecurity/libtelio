#![cfg(windows)]
#![allow(dead_code)]

//
// Port supporting code for wireguard-nt from wireguard-windows v0.5.3 to Rust
// This file replicates parts of wireguard-windows/tunnel/winipcfg/types.go
//

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::prelude::*;
use winapi::shared::ws2def::*;
use winapi::shared::ws2ipdef::*;

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct RouteDataIpv4 {
    pub destination: Ipv4Net,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct RouteDataIpv6 {
    pub destination: Ipv6Net,
    pub next_hop: Ipv6Addr,
    pub metric: u32,
}

/// This function converts std::net::Ipv4Addr to winapi::shared::inaddr::in_addr
#[inline]
pub unsafe fn convert_ipv4addr_to_inaddr(ip: &Ipv4Addr) -> winapi::shared::inaddr::in_addr {
    let mut winaddr = winapi::shared::inaddr::in_addr::default();

    winaddr.S_un.S_un_b_mut().s_b1 = ip.octets()[0];
    winaddr.S_un.S_un_b_mut().s_b2 = ip.octets()[1];
    winaddr.S_un.S_un_b_mut().s_b3 = ip.octets()[2];
    winaddr.S_un.S_un_b_mut().s_b4 = ip.octets()[3];

    winaddr
}

/// This function converts std::net::Ipv6Addr to winapi::shared::in6addr::in6_addr
#[inline]
pub unsafe fn convert_ipv6addr_to_inaddr(ip: &Ipv6Addr) -> winapi::shared::in6addr::in6_addr {
    let mut winaddr = winapi::shared::in6addr::in6_addr::default();

    for i in 0..7 {
        winaddr.u.Word_mut()[i] = ip.segments()[i];
    }

    winaddr
}

/// This function converts std::net::Ipv4Addr to winapi::shared::ws2def::SOCKADDR_IN
pub unsafe fn convert_ipv4addr_to_sockaddr(ip: &Ipv4Addr) -> SOCKADDR_IN {
    SOCKADDR_IN {
        sin_family: AF_INET as ADDRESS_FAMILY,
        sin_addr: convert_ipv4addr_to_inaddr(ip),
        ..Default::default()
    }
}

/// This function converts ipnet::Ipv6Addr to winapi::shared::ws2ipdef::SOCKADDR_IN6
pub unsafe fn convert_ipv6addr_to_sockaddr(ip: &Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6 as ADDRESS_FAMILY,
        sin6_addr: convert_ipv6addr_to_inaddr(ip),
        ..Default::default()
    }
}

/// This function converts winapi::shared::ws2def::SOCKADDR_IN to std::net::Ipv4Addr
pub unsafe fn convert_sockaddr_to_ipv4addr(sockaddr: &SOCKADDR_IN) -> Ipv4Addr {
    Ipv4Addr::new(
        sockaddr.sin_addr.S_un.S_un_b().s_b1,
        sockaddr.sin_addr.S_un.S_un_b().s_b2,
        sockaddr.sin_addr.S_un.S_un_b().s_b3,
        sockaddr.sin_addr.S_un.S_un_b().s_b4,
    )
}

/// This function converts a null-terminated Windows Unicode PWCHAR/LPWSTR to an OsString
pub unsafe fn u16_ptr_to_osstring(ptr: *const u16) -> OsString {
    let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ptr, len);

    OsString::from_wide(slice)
}

/// This function converts a null-terminated Windows PWCHAR/LPWSTR to a String
pub unsafe fn u16_ptr_to_string(ptr: *const u16) -> String {
    let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ptr, len);

    String::from_utf16_lossy(slice)
}
