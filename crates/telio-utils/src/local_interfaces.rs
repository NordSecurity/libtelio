#[cfg(feature = "test-util")]
use if_addrs::{IfAddr, Ifv4Addr, Interface};

use ipnet::{Ipv4Net, Ipv6Net, PrefixLenError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error as TError;

#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
/// Trait to get IF Address
pub trait GetIfAddrs: Send + Sync + Default + 'static {
    /// Signature of method that returns IF addresses
    fn get(&self) -> std::io::Result<Vec<if_addrs::Interface>>;
}

#[derive(Debug, TError)]
/// Error types of getting local interfaces
pub enum Error {
    /// IP address prefix length error
    #[error(transparent)]
    PrefixLenError(#[from] PrefixLenError),
    /// IO Error
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

#[derive(Default)]
/// Defination of struct to get system interfaces
pub struct SystemGetIfAddrs;
impl GetIfAddrs for SystemGetIfAddrs {
    fn get(&self) -> std::io::Result<Vec<if_addrs::Interface>> {
        #[cfg(not(feature = "test-util"))]
        return if_addrs::get_if_addrs();
        #[cfg(feature = "test-util")]
        Ok(vec![Interface {
            name: "eth0".to_string(),
            addr: IfAddr::V4(Ifv4Addr {
                ip: Ipv4Addr::new(192, 168, 1, 10),
                netmask: Ipv4Addr::new(192, 168, 1, 0),
                broadcast: None,
            }),
            index: Some(12),
            #[cfg(windows)]
            adapter_name: "adapter".to_string(),
        }])
    }
}

/// Method that returns vector of IPs on the system
/// Filtering out meshnet and loopback IP
pub fn gather_local_interfaces<G: GetIfAddrs>(
    get_if_addr: &G,
) -> Result<Vec<if_addrs::Interface>, Error> {
    let shared_range: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)?;
    let ipv6_shared_range: Ipv6Net =
        Ipv6Net::new(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 0), 64)?;
    Ok(get_if_addr
        .get()?
        .into_iter()
        .filter(|x| !x.addr.is_loopback())
        .filter(|x| match x.addr.ip() {
            // Filter 100.64/10 libtelio's meshnet network.
            IpAddr::V4(v4) => !shared_range.contains(&v4),
            // Filter IPv6
            IpAddr::V6(v6) => !ipv6_shared_range.contains(&v6),
        })
        .collect())
}
