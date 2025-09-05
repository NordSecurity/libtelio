//! This module can be removed once IpNet crate
//! fixes this issue: https://github.com/krisprice/ipnet/issues/55

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Struct used to create const items of Ipv4Net type
pub struct ConstIpv4Net {
    ip: Ipv4Addr,
    prefix_len: u8,
}

impl ConstIpv4Net {
    /// Creates a new IPv4 network address from an `Ipv4Addr` and prefix
    /// length. If called from a const context it will verify prefix length
    /// at compile time. Otherwise it will panic at runtime if prefix length
    /// is not less than or equal to 32.
    pub const fn new(ip: Ipv4Addr, prefix_len: u8) -> Self {
        assert!(
            prefix_len <= 32,
            "PREFIX_LEN must be less than or equal to 32 for ConstIpv4Net"
        );
        Self { ip, prefix_len }
    }
}

impl From<ConstIpv4Net> for Ipv4Net {
    fn from(value: ConstIpv4Net) -> Self {
        // Allow unwrap since ConstIpv4Net is guaranteed to have the correct prefix_len
        #[allow(clippy::unwrap_used)]
        Ipv4Net::new(value.ip, value.prefix_len).unwrap()
    }
}

impl From<ConstIpv4Net> for IpNet {
    fn from(value: ConstIpv4Net) -> Self {
        // Allow unwrap since ConstIpv4Net is guaranteed to have the correct prefix_len
        #[allow(clippy::unwrap_used)]
        IpNet::V4(Ipv4Net::new(value.ip, value.prefix_len).unwrap())
    }
}

/// Struct used to create const items of Ipv4Net type
pub struct ConstIpv6Net {
    ip: Ipv6Addr,
    prefix_len: u8,
}

impl ConstIpv6Net {
    /// Creates a new IPv6 network address from an `Ipv6Addr` and prefix
    /// length. If called from a const context it will verify prefix length
    /// at compile time. Otherwise it will panic at runtime if prefix length
    /// is not less than or equal to 128.
    pub const fn new(ip: Ipv6Addr, prefix_len: u8) -> Self {
        assert!(
            prefix_len <= 128,
            "PREFIX_LEN must be less than or equal to 128 for ConstIpv6Net"
        );
        Self { ip, prefix_len }
    }
}

impl From<ConstIpv6Net> for Ipv6Net {
    fn from(value: ConstIpv6Net) -> Self {
        // Allow unwrap since ConstIpv4Net is guaranteed to have the correct prefix_len
        #[allow(clippy::unwrap_used)]
        Ipv6Net::new(value.ip, value.prefix_len).unwrap()
    }
}

impl From<ConstIpv6Net> for IpNet {
    fn from(value: ConstIpv6Net) -> Self {
        // Allow unwrap since ConstIpv4Net is guaranteed to have the correct prefix_len
        #[allow(clippy::unwrap_used)]
        IpNet::V6(Ipv6Net::new(value.ip, value.prefix_len).unwrap())
    }
}
