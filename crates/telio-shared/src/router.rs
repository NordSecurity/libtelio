#![cfg(any(target_os = "linux", target_os = "macos", doc))]
#![cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "macos"))))]

use std::{net::IpAddr, process::Command};

use interfaces::{Interface, InterfacesError};

use crate::executable_command::{ExecutableCommand, ExecuteError};

#[derive(Debug, thiserror::Error)]
pub enum CleanupInterfaceError {
    #[error("ip link del: {0}")]
    IpLinkDel(ExecuteError),

    #[error("Interface::get_by_name(): {0}")]
    GetInterfaces(InterfacesError),
}

#[derive(Debug, thiserror::Error)]
pub enum SetupInterfaceError {
    #[error("address is not ipv4")]
    AddressNotIpv4,

    #[error("ip addr add: {0}")]
    IpAddrAdd(ExecuteError),

    #[error("ip link set up: {0}")]
    IpLinkSetUp(ExecuteError),
}

#[derive(Debug, thiserror::Error)]
pub enum SetupRoutesError {
    #[error("ip route add: {0}")]
    IpRouteAdd(ExecuteError),
}

pub fn cleanup_interface(interface_name: &str) -> Result<(), CleanupInterfaceError> {
    if Interface::get_by_name(interface_name)
        .map_err(CleanupInterfaceError::GetInterfaces)?
        .is_some()
    {
        Command::new("ip")
            .args(&["link", "del", "dev", interface_name, "type", "wireguard"])
            .execute()
            .map_err(CleanupInterfaceError::IpLinkDel)?;
    }

    Ok(())
}

pub fn setup_interface(
    interface_name: &str,
    interface_address: &IpAddr,
) -> Result<(), SetupInterfaceError> {
    let address = address_to_string(interface_address)?;

    Command::new("ip")
        .args(&["addr", "add", "dev", interface_name, &address])
        .execute()
        .map_err(SetupInterfaceError::IpAddrAdd)?;

    Command::new("ip")
        .args(&["link", "set", "up", "dev", interface_name])
        .execute()
        .map_err(SetupInterfaceError::IpLinkSetUp)?;

    Ok(())
}

pub fn setup_routes(interface_name: &str, destination: &str) -> Result<(), SetupRoutesError> {
    Command::new("ip")
        .args(&["route", "add", destination, "dev", interface_name])
        .execute()
        .map_err(SetupRoutesError::IpRouteAdd)?;

    Ok(())
}

fn address_to_string(address: &IpAddr) -> Result<String, SetupInterfaceError> {
    if let IpAddr::V4(address) = address {
        Ok(format!("{}", address))
    } else {
        Err(SetupInterfaceError::AddressNotIpv4)
    }
}
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::device::{tun::TunSocket, Tun};
    use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket, Packet};
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
        time::{Duration, Instant},
    };

    #[test]
    fn test_address_to_string() {
        let address = address_to_string(&IpAddr::V4(Ipv4Addr::new(255, 127, 63, 31)));
        assert_eq!(address.unwrap(), "255.127.63.31");

        let address = address_to_string(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));
        assert!(std::matches!(
            address.unwrap_err(),
            SetupInterfaceError::AddressNotIpv4
        ));
    }

    #[test]
    fn test_cleanup_interface() {
        const INTERFACE_NAME: &str = "routerTest1";

        // Using TunSocket to create tun instead of 'ip link', because the latter
        // fails on CI due to Docker container privilege limitations. Why TunSocket
        // works on CI is a mystery.
        let _tun = if Interface::get_by_name(INTERFACE_NAME).unwrap().is_none() {
            Some(TunSocket::new(INTERFACE_NAME).unwrap())
        } else {
            None
        };

        assert!(Interface::get_by_name(INTERFACE_NAME).unwrap().is_some());

        cleanup_interface(INTERFACE_NAME).unwrap();

        assert!(Interface::get_by_name(INTERFACE_NAME).unwrap().is_none());

        // Should succeed when interface is not available
        cleanup_interface(INTERFACE_NAME).unwrap();
    }

    #[test]
    fn test_router() {
        const INTERFACE_NAME: &str = "routerTest2";
        const INTERFACE_ADDRESS: Ipv4Addr = Ipv4Addr::new(90, 100, 110, 120);

        cleanup_interface(INTERFACE_NAME).unwrap();

        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let tun = TunSocket::new(INTERFACE_NAME).unwrap();

        setup_interface(INTERFACE_NAME, &IpAddr::V4(INTERFACE_ADDRESS)).unwrap();

        setup_routes(INTERFACE_NAME, "100.64.255.255/32").unwrap();

        const PAYLOAD: &[u8; 10] = b"aaaaaaaaaa";
        socket.send_to(PAYLOAD, "100.64.255.255:1111").unwrap();

        let start_time = Instant::now();

        loop {
            let mut buffer = [0; 65536];
            let response_buffer = tun.read(&mut buffer).unwrap();

            let ip_header = Ipv4Packet::new(response_buffer).unwrap();

            // Some weird non-udp packet is received periodically
            if ip_header.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                let udp_header = UdpPacket::new(ip_header.payload()).unwrap();
                assert_eq!(udp_header.payload(), PAYLOAD);
                assert_eq!(ip_header.get_source(), INTERFACE_ADDRESS);
                assert_eq!(
                    ip_header.get_destination(),
                    Ipv4Addr::new(100, 64, 255, 255)
                );
                assert_eq!(udp_header.get_destination(), 1111);
                break;
            }

            assert!(start_time.elapsed() < Duration::from_secs(1));
        }
    }
}
