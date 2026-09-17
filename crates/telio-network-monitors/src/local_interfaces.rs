use ipnet::Ipv4Net;
use mockall::automock;
use std::net::{IpAddr, Ipv4Addr};

/// A trait that provides an interface for retrieving network interface addresses.
#[automock]
pub trait GetIfAddrs: Send + Sync + Default + 'static {
    /// Fetches the list of network interfaces available on the system.
    /// Returns a `Result` which is contains a `Vec` of `if_addrs::Interface`
    /// representing the available network interfaces.
    fn get(&self) -> std::io::Result<Vec<if_addrs::Interface>>;
}

/// A concrete implementation of the `GetIfAddrs` trait that retrieves network interface
/// addresses from the operating system using the `if_addrs` crate.
#[derive(Default)]
pub struct SystemGetIfAddrs;
impl GetIfAddrs for SystemGetIfAddrs {
    fn get(&self) -> std::io::Result<Vec<if_addrs::Interface>> {
        if_addrs::get_if_addrs()
    }
}

/// Method that returns vector of Interfaces on the system
/// Filtering out meshnet and loopback IP
pub fn gather_local_interfaces<G: GetIfAddrs>(
    get_if_addr: &G,
) -> std::io::Result<Vec<if_addrs::Interface>> {
    let shared_range: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10).unwrap_or_default();
    Ok((*get_if_addr)
        .get()?
        .into_iter()
        .filter(|x| {
            !x.addr.is_loopback() && {
                match x.addr.ip() {
                    // Filter 100.64/10 libtelio's meshnet network.
                    IpAddr::V4(v4) => !shared_range.contains(&v4),
                    // Filter IPv6
                    _ => false,
                }
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use if_addrs::IfOperStatus;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn gather_local_interfaces_filtering() {
        let mut get_if_addrs_mock = MockGetIfAddrs::new();
        get_if_addrs_mock.expect_get().return_once(|| {
            Ok(vec![
                if_addrs::Interface {
                    name: "localhost".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(127, 0, 0, 1),
                        netmask: Ipv4Addr::new(255, 0, 0, 0),
                        prefixlen: 8,
                        broadcast: None,
                    }),
                    index: None,
                    oper_status: IfOperStatus::Testing,
                    is_p2p: false,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
                if_addrs::Interface {
                    name: "correct".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(10, 0, 0, 1),
                        netmask: Ipv4Addr::new(255, 255, 255, 0),
                        prefixlen: 24,
                        broadcast: None,
                    }),
                    index: None,
                    oper_status: IfOperStatus::Testing,
                    is_p2p: false,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
                if_addrs::Interface {
                    name: "internal".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(100, 64, 0, 1),
                        netmask: Ipv4Addr::new(255, 192, 0, 0),
                        prefixlen: 10,
                        broadcast: None,
                    }),
                    index: None,
                    oper_status: IfOperStatus::Testing,
                    is_p2p: false,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
                if_addrs::Interface {
                    name: "ipv6".to_owned(),
                    addr: if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                        ip: Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0x12, 0x34, 0x56, 0),
                        netmask: Ipv6Addr::new(255, 255, 255, 255, 0, 0, 0, 0),
                        prefixlen: 32,
                        broadcast: None,
                    }),
                    index: None,
                    oper_status: IfOperStatus::Testing,
                    is_p2p: false,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
            ])
        });

        let interfaces = gather_local_interfaces(&get_if_addrs_mock).unwrap();
        assert!(interfaces.len() == 1);
        assert!(interfaces[0].name == "correct");
    }
}
