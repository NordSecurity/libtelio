//! Telio firewall component used to track open connections
//! with other devices§

use log::error;
use lru_time_cache::LruCache;
use pnet_packet::{
    icmp::{IcmpPacket, IcmpTypes},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpPacket},
    udp::UdpPacket,
    Packet,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Formatter},
    net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr},
    sync::{Mutex, RwLock},
    time::Duration,
};

use telio_crypto::PublicKey;
use telio_utils::{telio_log_debug, telio_log_trace, telio_log_warn};

const LRU_CAPACITY: usize = 4096; // Max entries to keep (sepatately for TCP, UDP, and others)
const LRU_TIMEOUT: u64 = 120_000; // 2min (https://datatracker.ietf.org/doc/html/rfc4787#section-4.3)

const TCP_FIRST_PKT_MASK: u16 = TcpFlags::SYN | TcpFlags::ACK;
const ICMP_BLOCK_TYPES_MASK: u32 = 1 << IcmpTypes::EchoRequest.0
    | 1 << IcmpTypes::Timestamp.0
    | 1 << IcmpTypes::InformationRequest.0
    | 1 << IcmpTypes::AddressMaskRequest.0;

/// File sending port
pub const FILE_SEND_PORT: u16 = 49111;

trait IpPacket<'a>: Sized + Debug + Packet {
    type Addr: Into<IpAddr>;
    fn check_valid(&self) -> bool;
    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
    fn get_destination(&self) -> Self::Addr;
    fn get_source(&self) -> Self::Addr;
    fn try_from(buffer: &'a [u8]) -> Option<Self>;
}

impl<'a> IpPacket<'a> for Ipv4Packet<'a> {
    type Addr = StdIpv4Addr;

    fn check_valid(&self) -> bool {
        if self.get_version() != 4 {
            return false; // non IPv4 => DROP
        }
        if self.get_header_length() < 5 {
            return false; // IPv4->IHL < 5 => DROP
        }
        true
    }

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_level_protocol()
    }

    fn get_destination(&self) -> Self::Addr {
        self.get_destination()
    }

    fn get_source(&self) -> Self::Addr {
        self.get_source()
    }

    fn try_from(buffer: &'a [u8]) -> Option<Self> {
        Self::new(buffer)
    }
}

impl<'a> IpPacket<'a> for Ipv6Packet<'a> {
    type Addr = StdIpv6Addr;

    fn check_valid(&self) -> bool {
        if self.get_version() != 6 {
            return false; // non IPv6 => DROP
        }
        if self.get_payload_length() as usize != self.payload().len() {
            return false;
        }
        true
    }

    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.get_next_header()
    }

    fn get_destination(&self) -> Self::Addr {
        self.get_destination()
    }

    fn get_source(&self) -> Self::Addr {
        self.get_source()
    }

    fn try_from(buffer: &'a [u8]) -> Option<Self> {
        Self::new(buffer)
    }
}
/// Firewall trait.
#[cfg_attr(any(test, feature = "mockall"), mockall::automock)]
pub trait Firewall {
    /// Clears the port whitelist
    fn clear_port_whitelist(&self);

    /// Add port on peer to whitelist
    fn add_to_port_whitelist(&self, peer: PublicKey, port: u16);

    /// Remove peer from port whitelist
    fn remove_from_port_whitelist(&self, peer: PublicKey);

    /// Returns a whitelist of ports
    #[cfg(test)]
    fn get_port_whitelist(&self) -> HashMap<PublicKey, u16>;

    /// Clears the peer whitelist
    fn clear_peer_whitelist(&self);

    /// Add peer to whitelist
    fn add_to_peer_whitelist(&self, peer: PublicKey);

    /// Remove peer from whitelist
    fn remove_from_peer_whitelist(&self, peer: PublicKey);

    /// Returns a whitelist of peers
    #[cfg(test)]
    fn get_peer_whitelist(&self) -> HashSet<PublicKey>;

    /// For new connections it opens a pinhole for incoming connection
    /// If connection is already cached, it resets its timer and extends its lifetime
    /// Only returns false for invalid or not ipv4 packets
    fn process_outbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool;

    /// Checks if incoming packet should be accepted.
    /// Does not extend pinhole lifetime on success
    /// Adds new connection to cache only if ip is whitelisted
    /// Allows all icmp packets except for request types
    fn process_inbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool;
}

#[derive(Default)]
struct Whitelist {
    /// List of whitelisted source peer and destination port pairs
    port_whitelist: HashMap<PublicKey, u16>,

    /// List of whitelisted peers identified by public key from which any packet will be accepted
    peer_whitelist: HashSet<PublicKey>,
}

impl Whitelist {
    fn is_whitelisted(&self, peer: &PublicKey, port: u16) -> bool {
        self.peer_whitelist.contains(peer)
            || self
                .port_whitelist
                .get(peer)
                .map(|p| *p == port)
                .unwrap_or_default()
    }
}

/// Statefull packet-filter firewall.
pub struct StatefullFirewall {
    /// Recent udp connections
    udp: Mutex<LruCache<IpConnWithPort, UdpConnectionInfo>>,
    /// Recent tcp connections
    tcp: Mutex<LruCache<IpConnWithPort, TcpConnectionInfo>>,
    /// Whitelist of networks/peers allowed to connect
    whitelist: RwLock<Whitelist>,
}

#[derive(Debug)]
struct UdpConnectionInfo {
    is_remote_initiated: bool,
}

#[derive(PartialEq, Debug)]
struct TcpConnectionInfo {
    tx_alive: bool,
    rx_alive: bool,
    conn_remote_initiated: bool,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug)]
enum IpAddr {
    Ipv4(u32),
    Ipv6(u128),
}

impl From<StdIpv4Addr> for IpAddr {
    fn from(ipv4_addr: StdIpv4Addr) -> IpAddr {
        IpAddr::Ipv4(ipv4_addr.into())
    }
}

impl From<StdIpv6Addr> for IpAddr {
    fn from(ipv6_addr: StdIpv6Addr) -> IpAddr {
        IpAddr::Ipv6(ipv6_addr.into())
    }
}

impl From<IpAddr> for StdIpAddr {
    fn from(ip_addr: IpAddr) -> Self {
        match ip_addr {
            IpAddr::Ipv4(ipv4) => StdIpAddr::V4(ipv4.into()),
            IpAddr::Ipv6(ipv6) => StdIpAddr::V6(ipv6.into()),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
struct IpConnWithPort {
    remote_addr: IpAddr,
    remote_port: u16,
    local_addr: IpAddr,
    local_port: u16,
}

impl Debug for IpConnWithPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpConnWithPort")
            .field("remote_addr", &StdIpAddr::from(self.remote_addr))
            .field("remote_port", &self.remote_port)
            .field("local_addr", &StdIpAddr::from(self.local_addr))
            .field("remote_addr", &self.local_port)
            .finish()
    }
}

macro_rules! unwrap_option_or_return {
    ( $option:expr, $retval:expr ) => {
        match $option {
            Some(x) => x,
            None => return $retval,
        }
    };
    ( $option:expr ) => {
        unwrap_option_or_return!($option, ())
    };
}

macro_rules! unwrap_lock_or_return {
    ( $guard:expr, $retval:expr ) => {
        match $guard {
            Ok(x) => x,
            Err(_poisoned) => {
                error!("Poisoned lock");
                return $retval;
            }
        }
    };
    ( $guard:expr ) => {
        unwrap_lock_or_return!($guard, ())
    };
}

impl StatefullFirewall {
    /// Constructs firewall with default timeout (2 mins) and capacity (4096 entries).
    pub fn new() -> Self {
        StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT)
    }

    #[cfg(feature = "test_utils")]
    /// Return the size of conntrack entries for tcp and udp (for testing only).
    pub fn get_state(&self) -> (usize, usize) {
        let tcp = unwrap_lock_or_return!(self.tcp.lock(), (0, 0)).len();
        let udp = unwrap_lock_or_return!(self.udp.lock(), (0, 0)).len();
        (tcp, udp)
    }

    /// Constructs firewall with custom capacity and timeout in ms (for testing only).
    pub fn new_custom(capacity: usize, ttl: u64) -> Self {
        let ttl = Duration::from_millis(ttl);
        Self {
            tcp: Mutex::new(LruCache::with_expiry_duration_and_capacity(ttl, capacity)),
            udp: Mutex::new(LruCache::with_expiry_duration_and_capacity(ttl, capacity)),
            whitelist: RwLock::new(Whitelist::default()),
        }
    }

    fn process_outbound_ip_packet<'a, P: IpPacket<'a>>(
        &self,
        public_key: &[u8; 32],
        buffer: &'a [u8],
    ) -> bool {
        let ip = unwrap_option_or_return!(P::try_from(buffer), false);
        let peer: PublicKey = public_key.into();
        {
            // whitelist read-lock scope
            let whitelist = unwrap_lock_or_return!(self.whitelist.read(), false);

            // Fasttrack, if peer is whitelisted - skip any conntrack and allow immediately
            if whitelist.peer_whitelist.contains(&peer) {
                telio_log_trace!(
                    "Outbound IP packet is for whitelisted peer, forwarding: {:?}",
                    ip
                );
                return true;
            }
        }

        if !ip.check_valid() {
            telio_log_trace!("Outbound IP packet is not valid, dropping: {:?}", ip);
            return false;
        }

        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                self.handle_outbound_udp(&ip);
            }
            IpNextHeaderProtocols::Tcp => {
                self.handle_outbound_tcp(&ip);
            }
            _ => (),
        };

        telio_log_trace!("Accepting packet {:?} {:?}", ip, peer);
        true
    }

    fn process_inbound_ip_packet<'a, P: IpPacket<'a>>(
        &self,
        public_key: &[u8; 32],
        buffer: &'a [u8],
    ) -> bool {
        let ip = unwrap_option_or_return!(P::try_from(buffer), false);
        let peer: PublicKey = public_key.into();
        let whitelist = unwrap_lock_or_return!(self.whitelist.read(), false);

        // Fasttrack, if peer is whitelisted - skip any conntrack and allow immediately
        if whitelist.peer_whitelist.contains(&peer) {
            telio_log_trace!(
                "Inbound IP packet is for whitelisted peer, forwarding: {:?}",
                ip
            );
            return true;
        }

        if !ip.check_valid() {
            telio_log_trace!("Inbound IP packet is not valid, dropping: {:?}", ip);
            return false;
        }

        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => self.handle_inbound_udp(&whitelist, &peer, &ip),
            IpNextHeaderProtocols::Tcp => self.handle_inbound_tcp(&whitelist, &peer, &ip),
            IpNextHeaderProtocols::Icmp => self.handle_inbound_icmp(&whitelist, &peer, &ip),
            _ => false,
        }
    }

    fn handle_outbound_udp<'a>(&self, ip: &impl IpPacket<'a>) {
        let udp_packet = unwrap_option_or_return!(UdpPacket::new(ip.payload()));
        let key = IpConnWithPort {
            remote_addr: ip.get_destination().into(),
            remote_port: udp_packet.get_destination(),
            local_addr: ip.get_source().into(),
            local_port: udp_packet.get_source(),
        };
        let mut udp_cache = unwrap_lock_or_return!(self.udp.lock());
        // If key already exists, dont change the value, just update timer with get()
        if udp_cache.get(&key).is_none() {
            let conninfo = UdpConnectionInfo {
                is_remote_initiated: false,
            };
            telio_log_trace!("Inserting new UDP conntrack entry {:?}", key);
            udp_cache.insert(key, conninfo);
        }
    }

    fn handle_outbound_tcp<'a>(&self, ip: &impl IpPacket<'a>) {
        let tcp_packet = unwrap_option_or_return!(TcpPacket::new(ip.payload()));
        let key = IpConnWithPort {
            remote_addr: ip.get_destination().into(),
            remote_port: tcp_packet.get_destination(),
            local_addr: ip.get_source().into(),
            local_port: tcp_packet.get_source(),
        };
        let mut tcp_cache = unwrap_lock_or_return!(self.tcp.lock());

        let flags = tcp_packet.get_flags();

        if flags & TCP_FIRST_PKT_MASK == TcpFlags::SYN {
            telio_log_trace!("Inserting TCP conntrack entry {:?}", key);
            tcp_cache.insert(
                key,
                TcpConnectionInfo {
                    tx_alive: true,
                    rx_alive: true,
                    conn_remote_initiated: false,
                },
            );
        } else if flags & TcpFlags::RST == TcpFlags::RST {
            telio_log_trace!("Removing TCP conntrack entry {:?}", key);
            tcp_cache.remove(&key);
        } else if flags & TcpFlags::FIN == TcpFlags::FIN {
            telio_log_trace!("Connection {:?} closing", key);
            if let Some(connection) = tcp_cache.get_mut(&key) {
                connection.tx_alive = false;
                if !connection.rx_alive {
                    telio_log_trace!("Removing TCP conntrack entry {:?}", key);
                    tcp_cache.remove(&key);
                }
            }
        }
    }

    fn handle_inbound_udp<'a>(
        &self,
        whitelist: &Whitelist,
        peer: &PublicKey,
        ip: &impl IpPacket<'a>,
    ) -> bool {
        let udp_packet = unwrap_option_or_return!(UdpPacket::new(ip.payload()), false);
        let key = IpConnWithPort {
            remote_addr: ip.get_source().into(),
            remote_port: udp_packet.get_source(),
            local_addr: ip.get_destination().into(),
            local_port: udp_packet.get_destination(),
        };
        let mut udp_cache = unwrap_lock_or_return!(self.udp.lock(), false);

        if let Some(connection_info) = udp_cache.get(&key) {
            telio_log_trace!(
                "Matched UDP conntrack entry {:?} {:?}",
                key,
                connection_info
            );
            if connection_info.is_remote_initiated
                && !whitelist.is_whitelisted(peer, key.local_port)
            {
                telio_log_trace!("Removing UDP conntrack entry {:?}", key);
                udp_cache.remove(&key);
                return false;
            }

            telio_log_trace!("Accepting UDP packet {:?} {:?}", ip, peer);
            return true;
        }

        // no value in cache, insert and allow only if ip is whitelisted
        if !whitelist.is_whitelisted(peer, key.local_port) {
            telio_log_trace!("Dropping UDP packet {:?} {:?}", key, peer);
            return false;
        }

        let conninfo = UdpConnectionInfo {
            is_remote_initiated: true,
        };

        telio_log_trace!(
            "Updating UDP conntrack entry {:?} {:?} {:?}",
            key,
            peer,
            conninfo
        );
        udp_cache.insert(key, conninfo);

        telio_log_trace!("Accepting UDP packet {:?} {:?}", ip, peer);
        true
    }

    fn handle_inbound_tcp<'a>(
        &self,
        whitelist: &Whitelist,
        peer: &PublicKey,
        ip: &impl IpPacket<'a>,
    ) -> bool {
        let tcp_packet = unwrap_option_or_return!(TcpPacket::new(ip.payload()), false);
        let key = IpConnWithPort {
            remote_addr: ip.get_source().into(),
            remote_port: tcp_packet.get_source(),
            local_addr: ip.get_destination().into(),
            local_port: tcp_packet.get_destination(),
        };

        let flags = tcp_packet.get_flags();
        let mut tcp_cache = unwrap_lock_or_return!(self.tcp.lock(), false);

        if let Some(connection_info) = tcp_cache.get(&key) {
            telio_log_trace!(
                "Matched TCP conntrack entry {:?} {:?}",
                key,
                connection_info
            );
            if connection_info.conn_remote_initiated
                && !whitelist.is_whitelisted(peer, key.local_port)
            {
                telio_log_trace!("Removing TCP conntrack entry {:?}", key);
                tcp_cache.remove(&key);
                return false;
            }

            if flags & TcpFlags::RST == TcpFlags::RST {
                telio_log_trace!("Removing TCP conntrack entry {:?}", key);
                tcp_cache.remove(&key);
            } else if flags & TcpFlags::FIN == TcpFlags::FIN {
                telio_log_trace!("Connection {:?} closing", key);
                if let Some(connection) = tcp_cache.get_mut(&key) {
                    connection.rx_alive = false;
                    if !connection.tx_alive {
                        telio_log_trace!("Removing TCP conntrack entry {:?}", key);
                        tcp_cache.remove(&key);
                    }
                }
            }

            telio_log_trace!("Accepting TCP packet {:?} {:?}", ip, peer);
            return true;
        }

        if !whitelist.is_whitelisted(peer, key.local_port) {
            telio_log_trace!("Dropping TCP packet {:?} {:?}", key, peer);
            return false;
        }

        // not in cache but connection is allowed
        if flags & TCP_FIRST_PKT_MASK == TcpFlags::SYN {
            let conninfo = TcpConnectionInfo {
                tx_alive: true,
                rx_alive: true,
                conn_remote_initiated: true,
            };

            telio_log_trace!(
                "Updating TCP conntrack entry {:?} {:?} {:?}",
                key,
                peer,
                conninfo
            );
            tcp_cache.insert(key, conninfo);
        }

        telio_log_trace!("Accepting TCP packet {:?} {:?}", ip, peer);
        true
    }

    fn handle_inbound_icmp<'a>(
        &self,
        _whitelist: &Whitelist,
        peer: &PublicKey,
        ip: &impl IpPacket<'a>,
    ) -> bool {
        let icmp_packet = unwrap_option_or_return!(IcmpPacket::new(ip.payload()), false);

        if (1 << icmp_packet.get_icmp_type().0) & ICMP_BLOCK_TYPES_MASK != 0 {
            telio_log_trace!("Dropping ICMP packet {:?} {:?}", ip, peer);
            return false;
        }

        telio_log_trace!("Accepting ICMP packet {:?} {:?}", ip, peer);
        true
    }
}

impl Firewall for StatefullFirewall {
    fn clear_port_whitelist(&self) {
        telio_log_debug!("Clearing firewall port whitelist");
        let mut whitelist = unwrap_lock_or_return!(self.whitelist.write());
        whitelist.port_whitelist.clear();
    }

    fn add_to_port_whitelist(&self, peer: PublicKey, port: u16) {
        telio_log_debug!("Adding {peer:?}:{port} network to firewall port whitelist");
        let mut whitelist = unwrap_lock_or_return!(self.whitelist.write());
        whitelist.port_whitelist.insert(peer, port);
    }

    fn remove_from_port_whitelist(&self, peer: PublicKey) {
        telio_log_debug!("Removing {peer:?} network from firewall port whitelist");
        let mut whitelist = unwrap_lock_or_return!(self.whitelist.write());
        whitelist.port_whitelist.remove(&peer);
    }

    #[cfg(test)]
    fn get_port_whitelist(&self) -> HashMap<PublicKey, u16> {
        unwrap_lock_or_return!(self.whitelist.write(), Default::default())
            .port_whitelist
            .clone()
    }

    fn clear_peer_whitelist(&self) {
        telio_log_debug!("Clearing firewall peer whitelist");
        unwrap_lock_or_return!(self.whitelist.write())
            .peer_whitelist
            .clear();
    }

    fn add_to_peer_whitelist(&self, peer: PublicKey) {
        telio_log_debug!("Adding {:?} peer to firewall whitelist", peer);
        unwrap_lock_or_return!(self.whitelist.write())
            .peer_whitelist
            .insert(peer);
    }

    fn remove_from_peer_whitelist(&self, peer: PublicKey) {
        telio_log_debug!("Removing {:?} peer from firewall whitelist", peer);
        unwrap_lock_or_return!(self.whitelist.write())
            .peer_whitelist
            .remove(&peer);
    }

    #[cfg(test)]
    fn get_peer_whitelist(&self) -> HashSet<PublicKey> {
        unwrap_lock_or_return!(self.whitelist.write(), Default::default())
            .peer_whitelist
            .clone()
    }

    fn process_outbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool {
        match unwrap_option_or_return!(buffer.first(), false) >> 4 {
            4 => self.process_outbound_ip_packet::<Ipv4Packet>(public_key, buffer),
            6 => self.process_outbound_ip_packet::<Ipv6Packet>(public_key, buffer),
            version => {
                telio_log_warn!("Unexpected IP version {version} for outbound packet");
                false
            }
        }
    }

    /// Checks if incoming packet should be accepted.
    /// Does not extend pinhole lifetime on success
    /// Adds new connection to cache only if ip is whitelisted
    /// Allows all icmp packets except for request types
    fn process_inbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool {
        match unwrap_option_or_return!(buffer.first(), false) >> 4 {
            4 => self.process_inbound_ip_packet::<Ipv4Packet>(public_key, buffer),
            6 => self.process_inbound_ip_packet::<Ipv6Packet>(public_key, buffer),
            version => {
                telio_log_warn!("Unexpected IP version {version} for inbound packet");
                false
            }
        }
    }
}

/// The default initialization of Firewall object
impl Default for StatefullFirewall {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test_utils"))]
#[allow(missing_docs, unused)]
pub mod tests {
    use super::*;
    use pnet_packet::{
        icmp::{IcmpType, MutableIcmpPacket},
        ip::IpNextHeaderProtocol,
        ipv4::MutableIpv4Packet,
        ipv6::MutableIpv6Packet,
        tcp::MutableTcpPacket,
        udp::MutableUdpPacket,
        MutablePacket,
    };
    use std::{
        convert::TryInto,
        net::{Ipv4Addr, SocketAddr as StdSocketAddr, SocketAddrV6},
        net::{Ipv6Addr, SocketAddrV4},
        thread::sleep,
        time::Duration,
    };
    use telio_crypto::SecretKey;

    type MakeUdp = &'static dyn Fn(&str, &str) -> Vec<u8>;
    type MakeTcp = &'static dyn Fn(&str, &str, u16) -> Vec<u8>;
    type MakeIcmp = &'static dyn Fn(&str, &str, &IcmpType) -> Vec<u8>;

    impl From<StdIpAddr> for IpAddr {
        fn from(addr: std::net::IpAddr) -> Self {
            match addr {
                StdIpAddr::V4(addr) => addr.into(),
                StdIpAddr::V6(addr) => addr.into(),
            }
        }
    }

    const IPV4_HEADER_MIN: usize = 20; // IPv4 header minimal length in bytes
    const IPV6_HEADER_MIN: usize = 40; // IPv6 header minimal length in bytes
    const TCP_HEADER_MIN: usize = 20; // TCP header minimal length in bytes
    const UDP_HEADER: usize = 8; // UDP header length in bytes
    const ICMP_HEADER: usize = 8; // ICMP header length in bytes

    fn set_ipv4(
        ip: &mut MutableIpv4Packet,
        protocol: IpNextHeaderProtocol,
        header_length: usize,
        total_length: usize,
    ) {
        ip.set_next_level_protocol(protocol);
        ip.set_version(4);
        ip.set_header_length((header_length / 4) as u8);
        ip.set_total_length(total_length.try_into().unwrap());
        ip.set_flags(2);
        ip.set_ttl(64);
        ip.set_source(Ipv4Addr::LOCALHOST);
        ip.set_destination(Ipv4Addr::new(8, 8, 8, 8));
    }

    fn set_ipv6(
        ip: &mut MutableIpv6Packet,
        protocol: IpNextHeaderProtocol,
        header_length: usize,
        total_length: usize,
    ) {
        ip.set_next_header(protocol);
        ip.set_version(6);
        ip.set_traffic_class(0);
        ip.set_flow_label(0);
        ip.set_payload_length((total_length - header_length).try_into().unwrap());
        ip.set_hop_limit(64);
        ip.set_source(Ipv6Addr::LOCALHOST);
        ip.set_destination(Ipv6Addr::new(2001, 4860, 4860, 0, 0, 0, 0, 8888));
    }

    fn make_random_peer() -> PublicKey {
        SecretKey::gen().public()
    }

    fn make_peer() -> [u8; 32] {
        [1; 32]
    }

    pub fn make_udp(src: &str, dst: &str) -> Vec<u8> {
        let msg: &str = "Some message";
        let msg_len = msg.as_bytes().len();
        let ip_len = IPV4_HEADER_MIN + UDP_HEADER + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("UDP: Bad IP buffer");
        set_ipv4(&mut ip, IpNextHeaderProtocols::Udp, IPV4_HEADER_MIN, ip_len);
        let source: SocketAddrV4 = src.parse().expect("UDPv4: Bad src address");
        let destination: SocketAddrV4 = dst.parse().expect("UDPv4: Bad dst address");
        ip.set_source(*source.ip());
        ip.set_destination(*destination.ip());

        let mut udp =
            MutableUdpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("UDP: Bad UDP buffer");
        udp.set_source(source.port());
        udp.set_destination(destination.port());
        udp.set_length((UDP_HEADER + msg_len) as u16);
        udp.set_checksum(0);
        udp.payload_mut().copy_from_slice(msg.as_bytes());

        raw
    }

    pub fn make_udp6(src: &str, dst: &str) -> Vec<u8> {
        let msg: &str = "Some message";

        let msg_len = msg.as_bytes().len();
        let ip_len = IPV6_HEADER_MIN + UDP_HEADER + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv6Packet::new(&mut raw).expect("UDP: Bad IP buffer");
        set_ipv6(&mut ip, IpNextHeaderProtocols::Udp, IPV6_HEADER_MIN, ip_len);
        let source: SocketAddrV6 = src.parse().expect("UDPv6: Bad src address");
        let destination: SocketAddrV6 = dst.parse().expect("UDPv6: Bad dst address");
        ip.set_source(*source.ip());
        ip.set_destination(*destination.ip());

        let mut udp =
            MutableUdpPacket::new(&mut raw[IPV6_HEADER_MIN..]).expect("UDP: Bad UDP buffer");
        udp.set_source(source.port());
        udp.set_destination(destination.port());
        udp.set_length((UDP_HEADER + msg_len) as u16);
        udp.set_checksum(0);
        udp.payload_mut().copy_from_slice(msg.as_bytes());

        raw
    }

    pub fn make_tcp(src: &str, dst: &str, flags: u16) -> Vec<u8> {
        let msg: &str = "Some message";
        let msg_len = msg.as_bytes().len();
        let ip_len = IPV4_HEADER_MIN + TCP_HEADER_MIN + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("TCP: Bad IP buffer");
        set_ipv4(&mut ip, IpNextHeaderProtocols::Tcp, IPV4_HEADER_MIN, ip_len);
        let source: SocketAddrV4 = src.parse().expect("UDPv4: Bad src address");
        let destination: SocketAddrV4 = dst.parse().expect("UDPv4: Bad dst address");
        ip.set_source(*source.ip());
        ip.set_destination(*destination.ip());

        let mut tcp =
            MutableTcpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("TCP: Bad TCP buffer");
        tcp.set_source(source.port());
        tcp.set_destination(destination.port());
        tcp.set_checksum(0);
        tcp.payload_mut().copy_from_slice(msg.as_bytes());
        tcp.set_flags(flags);

        raw
    }

    pub fn make_tcp6(src: &str, dst: &str, flags: u16) -> Vec<u8> {
        let msg: &str = "Some message";
        let msg_len = msg.as_bytes().len();
        let ip_len = IPV6_HEADER_MIN + TCP_HEADER_MIN + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv6Packet::new(&mut raw).expect("TCP: Bad IP buffer");
        set_ipv6(&mut ip, IpNextHeaderProtocols::Tcp, IPV6_HEADER_MIN, ip_len);
        let source: SocketAddrV6 = src.parse().expect("UDPv6: Bad src address");
        let destination: SocketAddrV6 = dst.parse().expect("UDPv6: Bad dst address");
        ip.set_source(*source.ip());
        ip.set_destination(*destination.ip());

        let mut tcp =
            MutableTcpPacket::new(&mut raw[IPV6_HEADER_MIN..]).expect("TCP: Bad TCP buffer");
        tcp.set_source(source.port());
        tcp.set_destination(destination.port());
        tcp.set_checksum(0);
        tcp.payload_mut().copy_from_slice(msg.as_bytes());
        tcp.set_flags(flags);

        raw
    }

    fn make_icmp(src: &str, dst: &str, icmp_type: &IcmpType) -> Vec<u8> {
        let ip_len = IPV4_HEADER_MIN + ICMP_HEADER + 10;
        let mut raw = vec![0u8; ip_len];

        let mut packet =
            MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(icmp_type.clone());

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Icmp,
            IPV4_HEADER_MIN,
            ip_len,
        );
        ip.set_source(src.parse().expect("ICMP: Bad src IP"));
        ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));

        raw
    }

    fn make_icmp6(src: &str, dst: &str, icmp_type: &IcmpType) -> Vec<u8> {
        let ip_len = IPV6_HEADER_MIN + ICMP_HEADER + 10;
        let mut raw = vec![0u8; ip_len];

        let mut packet =
            MutableIcmpPacket::new(&mut raw[IPV6_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(icmp_type.clone());

        let mut ip = MutableIpv6Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv6(
            &mut ip,
            IpNextHeaderProtocols::Icmp,
            IPV6_HEADER_MIN,
            ip_len,
        );
        ip.set_source(src.parse().expect("ICMP: Bad src IP"));
        ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));

        raw
    }

    #[test]
    fn firewall_ipv4_packet_validation() {
        let mut raw = make_icmp("127.0.0.1", "8.8.8.8", &IcmpTypes::EchoRequest);
        let mut ip = MutableIpv4Packet::new(&mut raw).expect("PRE: Bad IP buffer");
        assert_eq!(ip.to_immutable().check_valid(), true);

        ip.set_version(4);
        assert_eq!(ip.to_immutable().check_valid(), true);

        ip.set_version(0); // Invalid IP version
        assert_eq!(ip.to_immutable().check_valid(), false);

        ip.set_version(6); // Only Ipv4 supported
        assert_eq!(ip.to_immutable().check_valid(), false);

        ip.set_version(4);
        ip.set_header_length(4); // Ipv4->IHL must be [5..15]
        assert_eq!(ip.to_immutable().check_valid(), false);

        let icmp =
            MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("PRE: Bad ICMP buffer");
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoRequest);
    }

    #[test]
    fn firewall_ipv6_packet_validation() {
        let mut raw = make_icmp6("::1", "2001:4860:4860::8888", &IcmpTypes::EchoRequest);
        let mut ip = MutableIpv6Packet::new(&mut raw).expect("PRE: Bad IP buffer");
        assert_eq!(ip.to_immutable().check_valid(), true);

        ip.set_version(6);
        assert_eq!(ip.to_immutable().check_valid(), true);

        ip.set_version(0); // Invalid IP version
        assert_eq!(ip.to_immutable().check_valid(), false);

        ip.set_version(4); // Only Ipv6 supported
        assert_eq!(ip.to_immutable().check_valid(), false);

        let icmp =
            MutableIcmpPacket::new(&mut raw[IPV6_HEADER_MIN..]).expect("PRE: Bad ICMP buffer");
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoRequest);
    }

    #[test]
    fn firewall_ipv6_packet_validation_of_payload_length() {
        let mut raw = make_icmp6("::1", "2001:4860:4860::8888", &IcmpTypes::EchoRequest);
        {
            let mut ip = MutableIpv6Packet::new(&mut raw).expect("PRE: Bad IP buffer");
            ip.set_payload_length(ip.get_payload_length() + 1);
        }
        let ip = Ipv6Packet::new(&mut raw).expect("PRE: Bad IP buffer");
        assert!(!ip.check_valid());
    }

    #[test]
    fn firewall_packet_validation_ipv4_ihl() {
        const IPV4_IHL: usize = 15; //Ipv4->IHL is 4 bits, can be [5..15]
        const PACKET_LENGTH: usize = 4 * IPV4_IHL;

        let mut raw = [0u8; PACKET_LENGTH];
        let mut ip = MutableIpv4Packet::new(&mut raw).expect("PRE: Bad IP buffer");

        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Udp,
            PACKET_LENGTH,
            PACKET_LENGTH,
        );
        assert_eq!(ip.to_immutable().check_valid(), true); // IPv4->IHL=15 => continue
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_udp() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            src3: &'static str,
            src4: &'static str,
            src5: &'static str,
            dst1: &'static str,
            dst2: &'static str,
            make_udp: MakeUdp,
        }

        let test_inputs = vec![
            TestInput{
                src1: "127.0.0.1:1111", src2: "127.0.0.1:2222",
                src3: "127.0.0.1:3333", src4: "127.0.0.1:4444",
                src5: "127.0.0.1:5555",
                dst1: "8.8.8.8:8888", dst2: "8.8.8.8:7777",
                make_udp: &make_udp,
            },
            TestInput{
                src1: "[::1]:1111", src2: "[::1]:2222",
                src3: "[::1]:3333", src4: "[::1]:4444",
                src5: "[::1]:5555",
                dst1: "[2001:4860:4860::8888]:8888",
                dst2: "[2001:4860:4860::8888]:7777",
                make_udp: &make_udp6,
            },
        ];
        for TestInput { src1, src2, src3, src4, src5, dst1, dst2, make_udp } in test_inputs {
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

            // Should FAIL (no matching outgoing connections yet)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src1)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src2)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src3)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src4)), false);
            assert_eq!(fw.udp.lock().unwrap().len(), 0);
    
            // Should PASS (adds 1111..4444 and drops 2222)
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src2, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.udp.lock().unwrap().len(), 2);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src3, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.udp.lock().unwrap().len(), 3);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src4, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.udp.lock().unwrap().len(), 3);

            // Should PASS (matching outgoing connections exist in LRUCache)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src3)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src4)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src1)), true);

            // Should FAIL (was added but dropped from LRUCache)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src2)), false);

            // Should FAIL (has no matching outgoing connection)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src5)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst2, src1)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst1)), false);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_tcp() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            src3: &'static str,
            src4: &'static str,
            src5: &'static str,
            dst1: &'static str,
            dst2: &'static str,
            make_tcp: MakeTcp,
        }

        let test_inputs = vec![
            TestInput{
                src1: "127.0.0.1:1111", src2: "127.0.0.1:2222",
                src3: "127.0.0.1:3333", src4: "127.0.0.1:4444",
                src5: "127.0.0.1:5555",
                dst1: "8.8.8.8:8888", dst2: "8.8.8.8:7777",
                make_tcp: &make_tcp,
            },
            TestInput{
                src1: "[::1]:1111", src2: "[::1]:2222",
                src3: "[::1]:3333", src4: "[::1]:4444",
                src5: "[::1]:5555",
                dst1: "[2001:4860:4860::8888]:8888",
                dst2: "[2001:4860:4860::8888]:7777",
                make_tcp: &make_tcp6,
            },
        ];
        for TestInput { src1, src2, src3, src4, src5, dst1, dst2, make_tcp } in test_inputs {
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

            // Should FAIL (no matching outgoing connections yet)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src1, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src2, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src3, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src4, TcpFlags::SYN)), false);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);

            // Should PASS (adds 1111..4444 and drops 2222)
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src2, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 2);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src3, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 3);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src4, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 3);

            // Should PASS (matching outgoing connections exist in LRUCache)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src4, TcpFlags::SYN)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src3, TcpFlags::SYN)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src1, TcpFlags::SYN)), true);

            // Should FAIL (was added but dropped from LRUCache)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src2, TcpFlags::SYN)), false);

            // Should FAIL (has no matching outgoing connection)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src5, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst2, src1, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), false);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_tcp_states() {
        struct TestInput {
            us: &'static str,
            them: &'static str,
            make_tcp: MakeTcp,
        }

        impl TestInput {
            fn us_port(&self) -> u16 { self.us.parse::<StdSocketAddr>().unwrap().port() }
            fn them_port(&self) -> u16 { self.them.parse::<StdSocketAddr>().unwrap().port() }
            fn us_ip(&self) -> IpAddr { self.us.parse::<StdSocketAddr>().unwrap().ip().into() }
            fn them_ip(&self) -> IpAddr { self.them.parse::<StdSocketAddr>().unwrap().ip().into() }
        }

        let test_inputs = vec![
            TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                 make_tcp: &make_tcp },
            TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888",  make_tcp: &make_tcp6 },
        ];
        for test_input @ TestInput { us, them, make_tcp } in test_inputs {
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN)), false);

            let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN)), true);

            let conn_key = IpConnWithPort {
                remote_addr: test_input.them_ip(),
                remote_port: test_input.them_port(),
                local_addr: test_input.us_ip(),
                local_port: test_input.us_port(),
            };
            assert_eq!(fw.tcp.lock().unwrap().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: true, conn_remote_initiated: false
            }));

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::RST)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN)), false);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::FIN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::FIN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_icmp() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            dst: &'static str,
            make_icmp: MakeIcmp,
        }

        let test_inputs = vec![
            TestInput { src1: "8.8.8.8",             src2: "8.8.4.4",              dst: "127.0.0.1", make_icmp: &make_icmp },
            TestInput { src1: "2001:4860:4860::8888",src2: "2001:4860:4860::8844", dst: "::1",       make_icmp: &make_icmp6 },
        ];
        for TestInput { src1, src2, dst, make_icmp } in test_inputs {
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

            // Should FAIL (should always block request type icmp, unless whitelisted)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::EchoRequest)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::Timestamp)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::InformationRequest)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::AddressMaskRequest)), false);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src2, dst, &IcmpTypes::EchoRequest)), false);

            // Should PASS
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp(dst, src1, &IcmpTypes::EchoRequest)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp(dst, src2, &IcmpTypes::EchoRequest)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp(dst, src1, &IcmpTypes::EchoRequest)), true);

            // Should PASS
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::EchoReply)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src2, dst, &IcmpTypes::EchoReply)), true);

            // Should PASS
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::TimestampReply)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::AddressMaskReply)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::DestinationUnreachable)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::InformationReply)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::ParameterProblem)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::RouterSolicitation)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::Traceroute)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::TimeExceeded)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, &IcmpTypes::RedirectMessage)), true);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_pinhole_timeout() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_udp: MakeUdp,
        }

        let test_inputs = vec![
            TestInput{ src: "127.0.0.1:1111",  dst: "8.8.8.8:8888",                 make_udp: &make_udp, },
            TestInput{ src: "[::1]:1111",      dst: "[2001:4860:4860::8888]:8888",  make_udp: &make_udp6, },
        ];

        for TestInput { src, dst, make_udp } in test_inputs {
            let fw = StatefullFirewall::new_custom(3, 100);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src, dst)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), true);
            sleep(Duration::from_millis(200));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), false);
        }
    }

    #[rustfmt::skip]
    #[test]
    #[ignore]
    fn firewall_pinhole_timeout_extending() {
        let capacity = 3;
        let ttl = 20;
        
        struct TestInput { src: &'static str, dst: &'static str, make_udp: MakeUdp, }
        let test_inputs = vec![
            TestInput{ src: "[::1]:1111",     dst: "[2001:4860:4860::8888]:8888",  make_udp: &make_udp6, },
            TestInput{ src: "127.0.0.1:1111", dst: "8.8.8.8:8888",                 make_udp: &make_udp, },
        ];

        for TestInput { src, dst, make_udp } in test_inputs {
            let fw = StatefullFirewall::new_custom(capacity, ttl);

            // Should PASS (adds 1111)
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src, dst)), true);

            //Should PASS
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), true);
            sleep(Duration::from_millis(15));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), true);

            //Should PASS (because TTL was extended)
            sleep(Duration::from_millis(15));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), true);

            //Should FAIL (because TTL=100 < sleep(200))
            sleep(Duration::from_millis(30));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), false);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_crud() {
        let fw = StatefullFirewall::new();
        assert!(fw.get_peer_whitelist().is_empty());

        let peer = make_random_peer();
        fw.add_to_peer_whitelist(peer);
        fw.add_to_peer_whitelist(make_random_peer());
        assert_eq!(fw.get_peer_whitelist().len(), 2);

        fw.remove_from_peer_whitelist(peer);
        assert_eq!(fw.get_peer_whitelist().len(), 1);

        fw.clear_peer_whitelist();
        assert!(fw.get_peer_whitelist().is_empty());
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            src3: &'static str,
            src4: &'static str,
            src5: &'static str,
            dst1: &'static str,
            dst2: &'static str,
            make_udp: MakeUdp,
            make_tcp: MakeTcp,
            make_icmp: MakeIcmp,
        }
        let test_inputs = vec![
            TestInput {
                src1: "100.100.100.100:1234", 
                src2: "100.100.100.100:1000",

                src3: "100.100.100.101:1234",
                src4: "100.100.100.101:2222",
                src5: "100.100.100.101:1111",

                dst1: "127.0.0.1:1111",
                dst2: "127.0.0.1:1000",
                make_udp: &make_udp,
                make_tcp: &make_tcp,
                make_icmp: &make_icmp,
            },
            TestInput {
                src1: "[2001:4860:4860::8888]:1234",
                src2: "[2001:4860:4860::8888]:1000",

                src3: "[2001:4860:4860::8844]:1234",
                src4: "[2001:4860:4860::8844]:2222",
                src5: "[2001:4860:4860::8844]:1111",

                dst1: "[::1]:1111",
                dst2: "[::1]:1000",
                make_udp: &make_udp6,
                make_tcp: &make_tcp6,
                make_icmp: &make_icmp6,
            }
        ];
        for TestInput { src1, src2, src3, src4, src5, dst1, dst2, make_udp, make_tcp, make_icmp } in test_inputs {
            let fw = StatefullFirewall::new();
            let peer1 = make_random_peer();
            let peer2 = make_random_peer();

            assert!(fw.get_peer_whitelist().is_empty());

            assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp(src1, dst1,)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp(src2, dst1,)), false);

            fw.add_to_port_whitelist(peer2, 1111);
            assert_eq!(fw.get_port_whitelist().len(), 1);

            assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp(src1, dst1,)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp(src2, dst1,)), true);
            assert_eq!(fw.udp.lock().unwrap().len(), 1);

        
            assert_eq!(fw.process_inbound_packet(&peer1.0, &make_tcp(src3, dst2, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp(src4, dst1, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);
            // only this one should be added to cache
            assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp(src5, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            fw.add_to_peer_whitelist(peer2);
            let src = src1.parse::<StdSocketAddr>().unwrap().ip().to_string();
            let dst = dst1.parse::<StdSocketAddr>().unwrap().ip().to_string();
            assert_eq!(fw.process_inbound_packet(&peer1.0, &make_icmp(&src, &dst, &IcmpTypes::EchoRequest)), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &make_icmp(&src, &dst, &IcmpTypes::EchoRequest)), true);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_icmp() {
        struct TestInput {
            us: &'static str,
            them: &'static str,
            make_icmp: MakeIcmp,
        }

        let test_inputs = vec![
            TestInput{ us: "127.0.0.1", them: "8.8.8.8",              make_icmp: &make_icmp, },
            TestInput{ us: "::1",       them: "2001:4860:4860::8888", make_icmp: &make_icmp6, },
        ];
        for TestInput { us, them, make_icmp } in test_inputs {
            let fw = StatefullFirewall::new();

            let peer = make_random_peer();
            assert_eq!(fw.process_outbound_packet(&peer.0, &make_icmp(us, them, &IcmpTypes::EchoRequest)), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::EchoReply)), true);

            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::EchoRequest)), false);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::Timestamp)), false);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::InformationRequest)), false);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::AddressMaskRequest)), false);

            fw.add_to_peer_whitelist(peer);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::EchoRequest)), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::Timestamp)), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::InformationRequest)), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, &IcmpTypes::AddressMaskRequest)), true);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_udp_allow() {
        struct TestInput { us: &'static str, them: &'static str, make_udp: MakeUdp, }
        let test_inputs = vec![
            TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                make_udp: &make_udp, },
            TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888", make_udp: &make_udp6, },
        ];

        for TestInput { us, them, make_udp } in test_inputs {
            let fw = StatefullFirewall::new();

            let them_peer = make_random_peer();

            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), false);
            fw.add_to_port_whitelist(them_peer, 8888); // NOTE: this doesn't change anything about this test
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_udp(us, them)), true);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            assert_eq!(fw.udp.lock().unwrap().len(), 1);
        
            // Should PASS because we started the session
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            fw.remove_from_port_whitelist(them_peer); // NOTE: also has no impact on this test
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            assert_eq!(fw.udp.lock().unwrap().len(), 1);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_udp_block() {
        struct TestInput { us: &'static str, them: &'static str, make_udp: MakeUdp, }
        let test_inputs = vec![
            TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                 make_udp: &make_udp, },
            TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888",  make_udp: &make_udp6, },
        ];

        for TestInput { us, them, make_udp } in test_inputs {
            let fw = StatefullFirewall::new();

            let them_peer = make_random_peer();

            fw.add_to_port_whitelist(them_peer,1111);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_udp(us, them)), true);
            assert_eq!(fw.udp.lock().unwrap().len(), 1);

            // Should BLOCK because they started the session
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            fw.remove_from_port_whitelist(them_peer);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), false);
            assert_eq!(fw.udp.lock().unwrap().len(), 0);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_tcp_allow() {
        struct TestInput { us: &'static str, them: &'static str, make_tcp: MakeTcp, }
        let test_inputs = vec![
            TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                 make_tcp: &make_tcp, },
            TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888",  make_tcp: &make_tcp6, },
        ];
        for TestInput { us, them, make_tcp } in test_inputs {
            let fw = StatefullFirewall::new();

            let them_peer = make_random_peer();

            fw.add_to_port_whitelist(them_peer, 8888); // NOTE: this doesn't change anything about the test
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), false);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_tcp(us, them, TcpFlags::SYN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);

        
            // Should PASS because we started the session
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), true);
            fw.remove_from_port_whitelist(them_peer);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
        }
        
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_tcp_block() {
        struct TestInput { us: &'static str, them: &'static str, make_tcp: MakeTcp, }
        let test_inputs = vec![
            TestInput{ us: "127.0.0.1:1111", them: "8.8.8.8:8888",                 make_tcp: &make_tcp, },
            TestInput{ us: "[::1]:1111",     them: "[2001:4860:4860::8888]:8888",  make_tcp: &make_tcp6, },
        ];
        for TestInput { us, them, make_tcp } in test_inputs {
            let fw = StatefullFirewall::new();

            let them_peer = make_random_peer();

            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN)), false);
            fw.add_to_port_whitelist(them_peer, 1111);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_tcp(us, them, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

        
            // Should BLOCK because they started the session
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), true);
            fw.remove_from_port_whitelist(them_peer);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), false);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);
        }
        
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_peer() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            dst: &'static str,
            make_udp: MakeUdp,
            make_tcp: MakeTcp,
            make_icmp: MakeIcmp,
        }
        let test_inputs = vec![
            TestInput {
                src1: "100.100.100.100:1234",
                src2: "100.100.100.101:1234",
                dst: "127.0.0.1:1111",
                make_udp: &make_udp,
                make_tcp: &make_tcp,
                make_icmp: &make_icmp,
            },
            TestInput {
                src1: "[2001:4860:4860::8888]:1234",
                src2: "[2001:4860:4860::8844]:1234",
                dst: "[::1]:1111",
                make_udp: &make_udp6,
                make_tcp: &make_tcp6,
                make_icmp: &make_icmp6,
            }
        ];
        for TestInput { src1, src2, dst, make_udp, make_tcp, make_icmp } in test_inputs {
            let fw = StatefullFirewall::new();
            assert!(fw.get_peer_whitelist().is_empty());

            let src2_ip = src2.parse::<StdSocketAddr>().unwrap().ip().to_string();
            let dst_ip = dst.parse::<StdSocketAddr>().unwrap().ip().to_string();

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip,&IcmpTypes::EchoRequest)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), false);

            fw.add_to_peer_whitelist((&make_peer()).into());
            assert_eq!(fw.get_peer_whitelist().len(), 1);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip,&IcmpTypes::EchoRequest)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), true);

            fw.remove_from_peer_whitelist((&make_peer()).into());
            assert_eq!(fw.get_peer_whitelist().len(), 0);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip,&IcmpTypes::EchoRequest)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), false);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_port() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_udp: MakeUdp,
            make_tcp: MakeTcp,
            make_icmp: MakeIcmp,
        }
        impl TestInput {
            fn src_socket(&self, port: u16) -> String { 
                StdSocketAddr::new(self.src.parse().unwrap(), port).to_string()
            }
            fn dst_socket(&self, port: u16) -> String { 
                StdSocketAddr::new(self.dst.parse().unwrap(), port).to_string()
            }
        }
        let test_inputs = vec![
            TestInput {
                src: "100.100.100.100", dst: "127.0.0.1",
                make_udp: &make_udp, make_tcp: &make_tcp, make_icmp: &make_icmp,
            },
            TestInput {
                src: "2001:4860:4860::8888", dst: "::1",
                make_udp: &make_udp6, make_tcp: &make_tcp6, make_icmp: &make_icmp6,
            }
        ];
        for test_input @ TestInput { src, dst, make_udp, make_tcp, make_icmp } in test_inputs {
            let fw = StatefullFirewall::new();
            assert!(fw.get_peer_whitelist().is_empty());
            assert!(fw.get_port_whitelist().is_empty());

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&test_input.src, &test_input.dst,&IcmpTypes::EchoRequest)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), false);

            fw.add_to_port_whitelist(PublicKey(make_peer()), FILE_SEND_PORT);
            assert_eq!(fw.get_port_whitelist().len(), 1);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&test_input.src, &test_input.dst,&IcmpTypes::EchoRequest)), false);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), true);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(&test_input.src_socket(11111), &test_input.dst_socket(12345))), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(12345), TcpFlags::PSH)), false);

            fw.remove_from_port_whitelist(PublicKey(make_peer()));
            assert_eq!(fw.get_port_whitelist().len(), 0);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&test_input.src, &test_input.dst,&IcmpTypes::EchoRequest)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), false);
        }
    }
}
