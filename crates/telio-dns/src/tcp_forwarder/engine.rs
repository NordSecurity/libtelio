//! TCP forwarder engine implemented with smoltcp.

use smoltcp::iface::{Config, Interface};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::time::Duration;
use telio_model::constants::{
    DNS_PORT, DNS_VIRTUAL_PEER_IPV4, DNS_VIRTUAL_PEER_ON_EXIT_IPV4, VPN_INTERNAL_IPV4,
};
use telio_utils::{telio_log_warn, Instant};

const DEVICE_MTU: usize = 1280;
const DNS_IPV4_ADDRS: [Ipv4Addr; 2] = [DNS_VIRTUAL_PEER_IPV4, DNS_VIRTUAL_PEER_ON_EXIT_IPV4];
const SUBNET_MASK: u8 = 32;

const TCP_SOCKET_BUF: usize = 16 * 1024;

const CLIENT_SOCKET_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Suspend aware clock for smoltcp's timers.
#[derive(Clone, Copy)]
struct SmolClock {
    start: Instant,
}

impl SmolClock {
    fn new() -> Self {
        SmolClock {
            start: Instant::now(),
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(
            i64::try_from(self.start.elapsed().as_micros()).unwrap_or(i64::MAX),
        )
    }
}

/// Packet queues bridging the smoltcp interface and the
/// forwarder's ingress/egress channels.
struct VirtualDevice {
    /// Packets received from the tunnel.
    rx: VecDeque<Vec<u8>>,
    /// Packets to be transmitted back to the tunnel.
    tx: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    fn new() -> Self {
        VirtualDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
}

/// Receive token handing one queued ingress packet to smoltcp.
struct VirtualRxToken(Vec<u8>);

/// Transmit token appending one egress packet to the device TX queue.
struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl smoltcp::phy::TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.0.push_back(buffer);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((VirtualRxToken(packet), VirtualTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

/// Build the smoltcp interface serving the virtual DNS addresses.
fn build_interface(device: &mut VirtualDevice, now: SmolInstant) -> Interface {
    use rand::RngExt;
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::rng().random();
    let mut iface = Interface::new(config, device, now);

    iface.update_ip_addrs(|addrs| {
        for ip in DNS_IPV4_ADDRS {
            if addrs
                .push(IpCidr::new(IpAddress::Ipv4(ip), SUBNET_MASK))
                .is_err()
            {
                telio_log_warn!(
                    "TCP forwarder interface address table full, dropping {}",
                    ip,
                );
            }
        }
    });
    // Interface requires a valid route lookup, the gateway address itself is never used.
    if iface
        .routes_mut()
        .add_default_ipv4_route(VPN_INTERNAL_IPV4)
        .is_err()
    {
        telio_log_warn!("Failed to add default route to TCP forwarder");
    }
    iface
}

/// Create smoltcp socket in listening state.
fn new_listen_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUF]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
        CLIENT_SOCKET_CONNECTION_TIMEOUT.as_secs(),
    )));
    if socket.listen(DNS_PORT).is_err() {
        telio_log_warn!("Failed to open TCP DNS listen socket");
    }
    socket
}
