use std::net::IpAddr;

/// Possible errors from node
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No IPs are assigned to node
    #[error("Node does not have IP addresses assigned")]
    NoIPsFound,
}

/// Stack in-use by node
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub enum IpStack {
    /// Node can be reached only through IPv4 address
    #[default]
    IPv4,
    /// Node can be reached only through IPv6 address
    IPv6,
    /// Node can be reached through IPv4 or IPv6 addresses
    IPv4v6,
}

/// Returns IP stack used in node
pub fn get_ip_stack(ip_addresses: &[IpAddr]) -> Result<IpStack, Error> {
    let (mut v4, mut v6) = (false, false);

    for addr in ip_addresses.iter() {
        if addr.is_ipv4() {
            v4 = true;
        } else {
            v6 = true;
        }
    }

    match (v4, v6) {
        (false, false) => Err(Error::NoIPsFound),
        (true, false) => Ok(IpStack::IPv4),
        (false, true) => Ok(IpStack::IPv6),
        (true, true) => Ok(IpStack::IPv4v6),
    }
}
