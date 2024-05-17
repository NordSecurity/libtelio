//! Telio constants definition

use std::net::{Ipv4Addr, Ipv6Addr};
use telio_utils::const_ipnet::{ConstIpv4Net, ConstIpv6Net};

/// VPN IPv4 Meshnet Address
pub const VPN_INTERNAL_IPV4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
/// VPN IPv6 Meshnet Address
pub const VPN_INTERNAL_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 1);
/// VPN IPv4 Non-Meshnet Address
pub const VPN_EXTERNAL_IPV4: Ipv4Addr = Ipv4Addr::new(10, 5, 0, 1);
/// Ipv4 multicast range
pub const IPV4_MULTICAST_NETWORK: ConstIpv4Net = ConstIpv4Net::new(Ipv4Addr::new(224, 0, 0, 0), 4);
/// Ipv6 multicast range
pub const IPV6_MULTICAST_NETWORK: ConstIpv6Net =
    ConstIpv6Net::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 128);
/// Ipv4 starcast's virtual peer address
pub const IPV4_STARCAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
/// Ipv6 starcast's virtual peer address
pub const IPV6_STARCAST_ADDRESS: Ipv6Addr = Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 0x5);
/// Ipv4 starcast's virtual peer network
pub const IPV4_STARCAST_NETWORK: ConstIpv4Net = ConstIpv4Net::new(IPV4_STARCAST_ADDRESS, 32);
/// Ipv6 starcast's virtual peer network
pub const IPV6_STARCAST_NETWORK: ConstIpv6Net = ConstIpv6Net::new(IPV6_STARCAST_ADDRESS, 128);
