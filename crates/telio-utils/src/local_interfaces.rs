use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Function type of a function returning interface addresses from the system
pub type GetIfAddrs = fn() -> std::io::Result<Vec<if_addrs::Interface>>;

/// Function returning interface addresses from the system
pub fn system_get_if_addr() -> std::io::Result<Vec<if_addrs::Interface>> {
    return if_addrs::get_if_addrs();
}

/// Method that returns vector of IPs on the system
/// Filtering out meshnet and loopback IP
pub fn gather_local_interfaces(
    get_if_addr: GetIfAddrs,
) -> std::io::Result<Vec<if_addrs::Interface>> {
    let shared_range = Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10).unwrap();
    let ipv6_shared_range =
        Ipv6Net::new(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 0), 64).unwrap();
    Ok(get_if_addr()?
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn gather_local_interfaces_filtering() {
        let mut mock_get_if_addrs = || {
            Ok(vec![
                if_addrs::Interface {
                    name: "localhost".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(127, 0, 0, 1),
                        netmask: Ipv4Addr::new(255, 0, 0, 0),
                        broadcast: None,
                    }),
                    index: None,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
                if_addrs::Interface {
                    name: "correct".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(10, 0, 0, 1),
                        netmask: Ipv4Addr::new(255, 255, 255, 0),
                        broadcast: None,
                    }),
                    index: None,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
                if_addrs::Interface {
                    name: "internal".to_owned(),
                    addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                        ip: Ipv4Addr::new(100, 64, 0, 1),
                        netmask: Ipv4Addr::new(255, 192, 0, 0),
                        broadcast: None,
                    }),
                    index: None,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
                if_addrs::Interface {
                    name: "ipv6".to_owned(),
                    addr: if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                        ip: Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0x12, 0x34, 0x56, 0),
                        netmask: Ipv6Addr::new(255, 255, 255, 255, 0, 0, 0, 0),
                        broadcast: None,
                    }),
                    index: None,
                    #[cfg(windows)]
                    adapter_name: "{78f73923-a518-4936-ba87-2a30427b1f63}".to_string(),
                },
            ])
        };

        let interfaces = gather_local_interfaces(mock_get_if_addrs).unwrap();
        assert!(interfaces.len() == 1);
        assert!(interfaces[0].name == "correct");
    }
}
