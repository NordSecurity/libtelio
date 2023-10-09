//! Telio firewall component used to track open connections
//! with other devices§

use log::error;
use pnet_packet::{
    icmp::{IcmpPacket, IcmpType, IcmpTypes},
    icmpv6::{Icmpv6Packet, Icmpv6Type, Icmpv6Types},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpPacket},
    udp::UdpPacket,
    Packet,
};
use std::{
    convert::TryInto,
    fmt::{Debug, Formatter},
    net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr},
    sync::{Mutex, RwLock},
    time::Duration,
};
use telio_utils::lru_cache::{Entry, LruCache};

use telio_crypto::PublicKey;
use telio_utils::{telio_log_debug, telio_log_trace, telio_log_warn};

/// HashSet type used internally by firewall and returned by get_peer_whitelist
pub type HashSet<V> = rustc_hash::FxHashSet<V>;
/// HashMap type used internally by firewall and returned by get_port_whitelist
pub type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;

const LRU_CAPACITY: usize = 4096; // Max entries to keep (sepatately for TCP, UDP, and others)
const LRU_TIMEOUT: u64 = 120_000; // 2min (https://datatracker.ietf.org/doc/html/rfc4787#section-4.3)

const TCP_FIRST_PKT_MASK: u16 = TcpFlags::SYN | TcpFlags::ACK;

const ICMP_BLOCKED_TYPES: [u8; 4] = [
    IcmpTypes::EchoRequest.0,
    IcmpTypes::Timestamp.0,
    IcmpTypes::InformationRequest.0,
    IcmpTypes::AddressMaskRequest.0,
];

const ICMPV6_BLOCKED_TYPES: [u8; 4] = [
    Icmpv6Types::EchoRequest.0,
    Icmpv6Types::RouterAdvert.0,
    Icmpv6Types::NeighborSolicit.0,
    Icmpv6Types::NeighborAdvert.0,
];

/// File sending port
pub const FILE_SEND_PORT: u16 = 49111;

trait Icmp: Sized {
    const BLOCKED_TYPES: [u8; 4];
    fn new(payload: &[u8]) -> Option<Self>;
    fn get_type(&self) -> u8;
}

impl Icmp for IcmpType {
    fn new(payload: &[u8]) -> Option<Self> {
        // We only need the type
        IcmpPacket::new(payload).map(|p| p.get_icmp_type())
    }

    fn get_type(&self) -> u8 {
        self.0
    }

    const BLOCKED_TYPES: [u8; 4] = ICMP_BLOCKED_TYPES;
}

impl Icmp for Icmpv6Type {
    fn new(payload: &[u8]) -> Option<Self> {
        // We only need the type
        Icmpv6Packet::new(payload).map(|p| p.get_icmpv6_type())
    }

    fn get_type(&self) -> u8 {
        self.0
    }

    const BLOCKED_TYPES: [u8; 4] = ICMPV6_BLOCKED_TYPES;
}

trait IpPacket<'a>: Sized + Debug + Packet {
    type Addr: Into<IpAddr>;
    type Icmp: Icmp;

    fn check_valid(&self) -> bool;
    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol;
    fn get_destination(&self) -> Self::Addr;
    fn get_source(&self) -> Self::Addr;
    fn try_from(buffer: &'a [u8]) -> Option<Self>;
}

impl<'a> IpPacket<'a> for Ipv4Packet<'a> {
    type Addr = StdIpv4Addr;
    type Icmp = IcmpType;

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
    type Icmp = Icmpv6Type;

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
    fn get_port_whitelist(&self) -> HashMap<PublicKey, u16>;

    /// Clears the peer whitelist
    fn clear_peer_whitelist(&self);

    /// Add peer to whitelist
    fn add_to_peer_whitelist(&self, peer: PublicKey);

    /// Remove peer from whitelist
    fn remove_from_peer_whitelist(&self, peer: PublicKey);

    /// Returns a whitelist of peers
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
    fn is_port_whitelisted(&self, peer: &PublicKey, port: u16) -> bool {
        debug_assert!(!self.peer_whitelist.contains(peer));
        self.port_whitelist
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
    /// Recent icmp connections
    icmp: Mutex<LruCache<IcmpConn, ()>>,
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

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
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
            .field("local_port", &self.local_port)
            .finish()
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct IcmpConn {
    remote_addr: IpAddr,
    local_addr: IpAddr,
    response_type: u8,
    identifier_sequence: u32,
}

type IcmpKey = Result<IcmpConn, IcmpErrorKey>;

#[derive(Clone, Debug)]
enum IcmpErrorKey {
    Udp(Option<IpConnWithPort>),
    Tcp(Option<IpConnWithPort>),
    Icmp(Option<IcmpConn>),
    None,
}

impl Debug for IcmpConn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpConn")
            .field("remote_addr", &StdIpAddr::from(self.remote_addr))
            .field("local_addr", &StdIpAddr::from(self.local_addr))
            .field("response_type", &self.response_type)
            .field("identifier_sequence", &self.identifier_sequence)
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
    fn new_custom(capacity: usize, ttl: u64) -> Self {
        let ttl = Duration::from_millis(ttl);
        Self {
            tcp: Mutex::new(LruCache::new(ttl, capacity)),
            udp: Mutex::new(LruCache::new(ttl, capacity)),
            icmp: Mutex::new(LruCache::new(ttl, capacity)),
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
            IpNextHeaderProtocols::Icmp => {
                self.handle_outbound_icmp(&ip);
            }
            IpNextHeaderProtocols::Icmpv6 => {
                self.handle_outbound_icmp(&ip);
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
            IpNextHeaderProtocols::Icmp => self.handle_inbound_icmp(&peer, &ip),
            IpNextHeaderProtocols::Icmpv6 => self.handle_inbound_icmp(&peer, &ip),
            _ => false,
        }
    }

    fn handle_outbound_udp<'a>(&self, ip: &impl IpPacket<'a>) {
        let key = unwrap_option_or_return!(Self::build_udp_key(ip, false));
        let mut udp_cache = unwrap_lock_or_return!(self.udp.lock());
        // If key already exists, dont change the value, just update timer with entry
        if let Entry::Vacant(e) = udp_cache.entry(key) {
            let conninfo = UdpConnectionInfo {
                is_remote_initiated: false,
            };
            telio_log_trace!("Inserting new UDP conntrack entry {:?}", e.key());
            e.insert(conninfo);
        }
    }

    fn handle_outbound_tcp<'a>(&self, ip: &impl IpPacket<'a>) {
        let (key, flags) = unwrap_option_or_return!(Self::build_tcp_key(ip, false));
        let mut tcp_cache = unwrap_lock_or_return!(self.tcp.lock());

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
            if let Entry::Occupied(mut e) = tcp_cache.entry(key) {
                let TcpConnectionInfo { tx_alive, .. } = e.get_mut();
                *tx_alive = false;
            }
        }
    }

    fn handle_outbound_icmp<'a>(&self, ip: &impl IpPacket<'a>) {
        let mut icmp_cache = unwrap_lock_or_return!(self.icmp.lock());
        if let Ok(key) = Self::build_icmp_key(ip, false) {
            // If key already exists, dont change the value, just update timer with entry
            if let Entry::Vacant(e) = icmp_cache.entry(key) {
                telio_log_trace!("Inserting new ICMP conntrack entry {:?}", e.key());
                e.insert(());
            }
        }
    }

    fn handle_inbound_udp<'a>(
        &self,
        whitelist: &Whitelist,
        peer: &PublicKey,
        ip: &impl IpPacket<'a>,
    ) -> bool {
        let key = unwrap_option_or_return!(Self::build_udp_key(ip, true), false);
        let mut udp_cache = unwrap_lock_or_return!(self.udp.lock(), false);

        if let Some(connection_info) = udp_cache.get(&key) {
            telio_log_trace!(
                "Matched UDP conntrack entry {:?} {:?}",
                key,
                connection_info
            );
            if connection_info.is_remote_initiated
                && !whitelist.is_port_whitelisted(peer, key.local_port)
            {
                telio_log_trace!("Removing UDP conntrack entry {:?}", key);
                udp_cache.remove(&key);
                return false;
            }

            telio_log_trace!("Accepting UDP packet {:?} {:?}", ip, peer);
            return true;
        }

        // no value in cache, insert and allow only if ip is whitelisted
        if !whitelist.is_port_whitelisted(peer, key.local_port) {
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
        let (key, flags) = unwrap_option_or_return!(Self::build_tcp_key(ip, true), false);
        let mut tcp_cache = unwrap_lock_or_return!(self.tcp.lock(), false);

        if let Some(connection_info) = tcp_cache.peek(&key) {
            telio_log_trace!(
                "Matched TCP conntrack entry {:?} {:?}",
                key,
                connection_info
            );
            if connection_info.conn_remote_initiated
                && !whitelist.is_port_whitelisted(peer, key.local_port)
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
                }
            } else if !connection_info.tx_alive
                && !connection_info.rx_alive
                && !connection_info.conn_remote_initiated
            {
                if flags & TcpFlags::ACK == TcpFlags::ACK {
                    telio_log_trace!("Removing TCP conntrack entry {:?}", key);
                    tcp_cache.remove(&key);
                    return true;
                }
                return false;
            }
            // restarts cache entry timeout
            tcp_cache.get(&key);
            telio_log_trace!("Accepting TCP packet {:?} {:?}", ip, peer);
            return true;
        }

        if !whitelist.is_port_whitelisted(peer, key.local_port) {
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

    fn handle_inbound_icmp<'a, P: IpPacket<'a>>(&self, peer: &PublicKey, ip: &P) -> bool {
        let icmp_packet = unwrap_option_or_return!(IcmpPacket::new(ip.payload()), false);

        if P::Icmp::BLOCKED_TYPES.contains(&icmp_packet.get_icmp_type().0) {
            telio_log_trace!("Dropping ICMP packet {:?} {:?}", ip, peer);
            return false;
        }

        match Self::build_icmp_key(ip, true) {
            Ok(key) => {
                let mut icmp_cache = unwrap_lock_or_return!(self.icmp.lock(), false);
                let is_in_cache = icmp_cache.get(&key).is_some();
                if is_in_cache {
                    telio_log_trace!("Matched ICMP conntrack entry {:?}", key,);
                    telio_log_trace!("Removing ICMP conntrack entry {:?}", key);
                    icmp_cache.remove(&key);
                    telio_log_trace!("Accepting ICMP packet {:?} {:?}", ip, peer);
                }
                is_in_cache
            }
            Err(icmp_error_key) => {
                telio_log_trace!("Encountered ICMP error packet, checking nested packet");
                let should_accept = self.handle_icmp_error(icmp_error_key);
                if should_accept {
                    telio_log_trace!("Accepting ICMP packet {:?} {:?}", ip, peer);
                }
                should_accept
            }
        }
    }

    fn build_udp_key<'a, P: IpPacket<'a>>(ip: &P, inbound: bool) -> Option<IpConnWithPort> {
        let udp_packet = match UdpPacket::new(ip.payload()) {
            Some(packet) => packet,
            _ => {
                telio_log_trace!("Could not create UDP packet from IP packet {:?}", ip);
                return None;
            }
        };
        let key = if inbound {
            IpConnWithPort {
                remote_addr: ip.get_source().into(),
                remote_port: udp_packet.get_source(),
                local_addr: ip.get_destination().into(),
                local_port: udp_packet.get_destination(),
            }
        } else {
            IpConnWithPort {
                remote_addr: ip.get_destination().into(),
                remote_port: udp_packet.get_destination(),
                local_addr: ip.get_source().into(),
                local_port: udp_packet.get_source(),
            }
        };
        Some(key)
    }

    fn build_tcp_key<'a, P: IpPacket<'a>>(ip: &P, inbound: bool) -> Option<(IpConnWithPort, u16)> {
        let tcp_packet = match TcpPacket::new(ip.payload()) {
            Some(packet) => packet,
            _ => {
                telio_log_trace!("Could not create TCP packet from IP packet {:?}", ip);
                return None;
            }
        };
        let key = if inbound {
            IpConnWithPort {
                remote_addr: ip.get_source().into(),
                remote_port: tcp_packet.get_source(),
                local_addr: ip.get_destination().into(),
                local_port: tcp_packet.get_destination(),
            }
        } else {
            IpConnWithPort {
                remote_addr: ip.get_destination().into(),
                remote_port: tcp_packet.get_destination(),
                local_addr: ip.get_source().into(),
                local_port: tcp_packet.get_source(),
            }
        };
        let flags = tcp_packet.get_flags();
        Some((key, flags))
    }

    fn build_icmp_key<'a, P: IpPacket<'a>>(ip: &P, inbound: bool) -> IcmpKey {
        let icmp_packet = match IcmpPacket::new(ip.payload()) {
            Some(packet) => packet,
            _ => {
                telio_log_trace!("Could not create ICMP packet from IP packet {:?}", ip);
                return Err(IcmpErrorKey::None);
            }
        };
        let response_type = {
            use IcmpTypes as v4;
            use Icmpv6Types as v6;
            let it = icmp_packet.get_icmp_type().0;
            // Request messages get the icmp type of the corresponding reply message
            // Reply messages get their own icmp type, to match that of its corresponding request
            // We only create keys for outbound requests and inbound replies
            if inbound {
                if it == v4::EchoReply.0
                    || it == v4::TimestampReply.0
                    || it == v4::InformationReply.0
                    || it == v4::AddressMaskReply.0
                    || it == v6::EchoReply.0
                {
                    it
                } else if (it == v4::DestinationUnreachable.0
                    || it == v4::TimeExceeded.0
                    || it == v4::ParameterProblem.0)
                    && ip.get_next_level_protocol() == IpNextHeaderProtocols::Icmp
                {
                    return Self::build_icmp_error_key(icmp_packet, true);
                } else if (it == v6::DestinationUnreachable.0
                    || it == v6::PacketTooBig.0
                    || it == v6::ParameterProblem.0
                    || it == v6::TimeExceeded.0)
                    && ip.get_next_level_protocol() == IpNextHeaderProtocols::Icmpv6
                {
                    return Self::build_icmp_error_key(icmp_packet, false);
                } else {
                    return Err(IcmpErrorKey::None);
                }
            } else if it == v4::EchoRequest.0 {
                v4::EchoReply.0
            } else if it == v4::Timestamp.0 {
                v4::TimestampReply.0
            } else if it == v4::InformationRequest.0 {
                v4::InformationReply.0
            } else if it == v4::AddressMaskRequest.0 {
                v4::AddressMaskReply.0
            } else if it == v6::EchoRequest.0 {
                v6::EchoReply.0
            } else {
                return Err(IcmpErrorKey::None);
            }
        };

        let identifier_sequence = {
            let bytes = icmp_packet
                .payload()
                .get(0..4)
                .and_then(|b| b.try_into().ok());
            let bytes = unwrap_option_or_return!(bytes, Err(IcmpErrorKey::None));
            u32::from_ne_bytes(bytes)
        };
        let (remote_addr, local_addr) = if inbound {
            (ip.get_source().into(), ip.get_destination().into())
        } else {
            (ip.get_destination().into(), ip.get_source().into())
        };
        let key = IcmpConn {
            remote_addr,
            local_addr,
            response_type,
            identifier_sequence,
        };
        Ok(key)
    }

    fn build_icmp_error_key(icmp_packet: IcmpPacket, is_v4: bool) -> IcmpKey {
        let inner_packet = match icmp_packet.payload().get(4..) {
            Some(bytes) => bytes,
            None => {
                telio_log_trace!("ICMP error body does not contain a nested packet");
                return Err(IcmpErrorKey::None);
            }
        };
        let icmp_error_key = if is_v4 {
            let packet = match Ipv4Packet::try_from(inner_packet) {
                Some(packet) => packet,
                _ => {
                    telio_log_trace!("ICMP error contains invalid IPv4 packet");
                    return Err(IcmpErrorKey::None);
                }
            };
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    IcmpErrorKey::Udp(Self::build_udp_key(&packet, false))
                }
                IpNextHeaderProtocols::Tcp => {
                    IcmpErrorKey::Tcp(Self::build_tcp_key(&packet, false).map(|(key, _)| key))
                }
                IpNextHeaderProtocols::Icmp => {
                    IcmpErrorKey::Icmp(Self::build_icmp_key(&packet, false).ok())
                }
                _ => IcmpErrorKey::None,
            }
        } else {
            let packet = match Ipv6Packet::try_from(inner_packet) {
                Some(packet) => packet,
                _ => {
                    telio_log_trace!("ICMP error contains invalid IPv6 packet");
                    return Err(IcmpErrorKey::None);
                }
            };
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    IcmpErrorKey::Udp(Self::build_udp_key(&packet, false))
                }
                IpNextHeaderProtocols::Tcp => {
                    IcmpErrorKey::Tcp(Self::build_tcp_key(&packet, false).map(|(key, _)| key))
                }
                IpNextHeaderProtocols::Icmpv6 => {
                    IcmpErrorKey::Icmp(Self::build_icmp_key(&packet, false).ok())
                }
                _ => IcmpErrorKey::None,
            }
        };
        Err(icmp_error_key)
    }

    fn handle_icmp_error(&self, error_key: IcmpErrorKey) -> bool {
        match error_key {
            IcmpErrorKey::Icmp(Some(icmp_key)) => {
                let mut icmp_cache = unwrap_lock_or_return!(self.icmp.lock(), false);
                let is_in_cache = icmp_cache.get(&icmp_key).is_some();
                if is_in_cache {
                    telio_log_trace!(
                        "Nested packet in ICMP error packet matched ICMP conntrack entry {:?}",
                        icmp_key,
                    );
                    telio_log_trace!("Removing ICMP conntrack entry {:?}", icmp_key);
                    icmp_cache.remove(&icmp_key);
                }
                is_in_cache
            }
            IcmpErrorKey::Tcp(Some(tcp_key)) => {
                let mut tcp_cache = unwrap_lock_or_return!(self.tcp.lock(), false);
                let is_in_cache = tcp_cache.get(&tcp_key).is_some();
                if is_in_cache {
                    telio_log_trace!(
                        "Nested packet in ICMP error packet matched TCP conntrack entry {:?}",
                        tcp_key,
                    );
                    telio_log_trace!("Removing TCP conntrack entry {:?}", tcp_key);
                    tcp_cache.remove(&tcp_key);
                }
                is_in_cache
            }
            IcmpErrorKey::Udp(Some(udp_key)) => {
                let mut udp_cache = unwrap_lock_or_return!(self.udp.lock(), false);
                let is_in_cache = udp_cache.get(&udp_key).is_some();
                if is_in_cache {
                    telio_log_trace!(
                        "Nested packet in ICMP error packet matched UDP conntrack entry {:?}",
                        udp_key,
                    );
                    telio_log_trace!("Removing UDP conntrack entry {:?}", udp_key);
                    udp_cache.remove(&udp_key);
                }
                is_in_cache
            }
            _ => false,
        }
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
        icmpv6::{Icmpv6Type, MutableIcmpv6Packet},
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
        time::Duration,
    };
    use telio_crypto::SecretKey;

    type MakeUdp = &'static dyn Fn(&str, &str) -> Vec<u8>;
    type MakeTcp = &'static dyn Fn(&str, &str, u16) -> Vec<u8>;
    type MakeIcmp = &'static dyn Fn(&str, &str, GenericIcmpType) -> Vec<u8>;
    type MakeIcmpWithBody = &'static dyn Fn(&str, &str, GenericIcmpType, &[u8]) -> Vec<u8>;

    fn advance_time(time: Duration) {
        #[cfg(not(feature = "test_utils"))]
        sn_fake_clock::FakeClock::advance_time(time.as_millis() as u64);
        #[cfg(feature = "test_utils")]
        panic!("don't use advance time when lru cache is not built with support for it")
    }

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
        let source: SocketAddrV4 = src
            .parse()
            .expect(&format!("UDPv4: Bad src address: {src}"));
        let destination: SocketAddrV4 = dst
            .parse()
            .expect(&format!("UDPv4: Bad dst address: {dst}"));
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
        let source: SocketAddrV6 = src
            .parse()
            .expect(&format!("UDPv6: Bad src address: {src}"));
        let destination: SocketAddrV6 = dst
            .parse()
            .expect(&format!("UDPv6: Bad dst address: {dst}"));
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
        let source: SocketAddrV4 = src
            .parse()
            .expect(&format!("TCPv4: Bad src address: {src}"));
        let destination: SocketAddrV4 = dst
            .parse()
            .expect(&format!("TCPv4: Bad dst address: {dst}"));
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
        let source: SocketAddrV6 = src
            .parse()
            .expect(&format!("TCPv6: Bad src address: {src}"));
        let destination: SocketAddrV6 = dst
            .parse()
            .expect(&format!("TCPv6: Bad dst address: {dst}"));
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum GenericIcmpType {
        V4(IcmpType),
        V6(Icmpv6Type),
    }

    impl From<IcmpType> for GenericIcmpType {
        fn from(t: IcmpType) -> Self {
            GenericIcmpType::V4(t)
        }
    }

    impl From<Icmpv6Type> for GenericIcmpType {
        fn from(t: Icmpv6Type) -> Self {
            GenericIcmpType::V6(t)
        }
    }

    impl GenericIcmpType {
        fn v4(&self) -> IcmpType {
            match self {
                GenericIcmpType::V4(t) => *t,
                GenericIcmpType::V6(t) => panic!("{:?} is not v4", t),
            }
        }

        fn v6(&self) -> Icmpv6Type {
            match self {
                GenericIcmpType::V4(t) => {
                    if *t == IcmpTypes::EchoReply {
                        return Icmpv6Types::EchoReply;
                    }
                    if *t == IcmpTypes::EchoRequest {
                        return Icmpv6Types::EchoRequest;
                    }
                    if *t == IcmpTypes::DestinationUnreachable {
                        return Icmpv6Types::DestinationUnreachable;
                    }
                    if *t == IcmpTypes::ParameterProblem {
                        return Icmpv6Types::ParameterProblem;
                    }
                    if *t == IcmpTypes::RouterSolicitation {
                        return Icmpv6Types::RouterSolicit;
                    }
                    if *t == IcmpTypes::TimeExceeded {
                        return Icmpv6Types::TimeExceeded;
                    }
                    if *t == IcmpTypes::RedirectMessage {
                        return Icmpv6Types::Redirect;
                    }
                    unimplemented!("{:?}", t)
                }
                GenericIcmpType::V6(t) => *t,
            }
        }
    }

    fn make_icmp4_with_body(
        src: &str,
        dst: &str,
        icmp_type: GenericIcmpType,
        body: &[u8],
    ) -> Vec<u8> {
        let additional_body_len = body.len().saturating_sub(14);
        let ip_len = IPV4_HEADER_MIN + ICMP_HEADER + 10 + additional_body_len;
        let mut raw = vec![0u8; ip_len];

        let icmp_type: GenericIcmpType = (icmp_type).into();
        let mut packet =
            MutableIcmpPacket::new(&mut raw[IPV4_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(icmp_type.v4());

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Icmp,
            IPV4_HEADER_MIN,
            ip_len,
        );
        ip.set_source(src.parse().expect("ICMP: Bad src IP"));
        ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));

        let body_start = 14.max(body.len());
        for (i, b) in body.iter().enumerate() {
            raw[ip_len - (body_start - i)] = *b;
        }

        raw
    }

    fn make_icmp4(src: &str, dst: &str, icmp_type: GenericIcmpType) -> Vec<u8> {
        make_icmp4_with_body(src, dst, icmp_type, &[])
    }

    fn make_icmp6_with_body(
        src: &str,
        dst: &str,
        icmp_type: GenericIcmpType,
        body: &[u8],
    ) -> Vec<u8> {
        let additional_body_len = body.len().saturating_sub(14);
        let ip_len = IPV6_HEADER_MIN + ICMP_HEADER + 10 + additional_body_len;
        let mut raw = vec![0u8; ip_len];

        let icmp_type: GenericIcmpType = (icmp_type).into();
        let mut packet =
            MutableIcmpv6Packet::new(&mut raw[IPV6_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmpv6_type(icmp_type.v6());

        let mut ip = MutableIpv6Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv6(
            &mut ip,
            IpNextHeaderProtocols::Icmpv6,
            IPV6_HEADER_MIN,
            ip_len,
        );
        ip.set_source(src.parse().expect("ICMP: Bad src IP"));
        ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));

        let body_start = 14.max(body.len());
        for (i, b) in body.iter().enumerate() {
            raw[ip_len - (body_start - i)] = *b;
        }

        raw
    }

    fn make_icmp6(src: &str, dst: &str, icmp_type: GenericIcmpType) -> Vec<u8> {
        make_icmp6_with_body(src, dst, icmp_type, &[])
    }

    #[test]
    fn firewall_ipv4_packet_validation() {
        let mut raw = make_icmp4("127.0.0.1", "8.8.8.8", IcmpTypes::EchoRequest.into());
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
        let mut raw = make_icmp6("::1", "2001:4860:4860::8888", IcmpTypes::EchoRequest.into());
        let mut ip = MutableIpv6Packet::new(&mut raw).expect("PRE: Bad IP buffer");
        assert_eq!(ip.to_immutable().check_valid(), true);

        ip.set_version(6);
        assert_eq!(ip.to_immutable().check_valid(), true);

        ip.set_version(0); // Invalid IP version
        assert_eq!(ip.to_immutable().check_valid(), false);

        ip.set_version(4); // Only Ipv6 supported
        assert_eq!(ip.to_immutable().check_valid(), false);

        let icmp =
            MutableIcmpv6Packet::new(&mut raw[IPV6_HEADER_MIN..]).expect("PRE: Bad ICMP buffer");
        assert_eq!(icmp.get_icmpv6_type(), Icmpv6Types::EchoRequest);
    }

    #[test]
    fn firewall_ipv6_packet_validation_of_payload_length() {
        let mut raw = make_icmp6("::1", "2001:4860:4860::8888", IcmpTypes::EchoRequest.into());
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
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::ACK)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::PSH)), false);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::ACK)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_tcp_connection_is_removed_when_outbound_fin_is_after_inbound_one() {
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

            let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
            let conn_key = IpConnWithPort {
                remote_addr: test_input.them_ip(),
                remote_port: test_input.them_port(),
                local_addr: test_input.us_ip(),
                local_port: test_input.us_port(),
            };

            assert_eq!(fw.tcp.lock().unwrap().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: true, conn_remote_initiated: false
            }));

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::FIN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            assert_eq!(fw.tcp.lock().unwrap().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: false, conn_remote_initiated: false
            }));

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::FIN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            assert_eq!(fw.tcp.lock().unwrap().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: false, rx_alive: false, conn_remote_initiated: false
            }));

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::ACK)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_tcp_connection_timeout_is_not_updated_after_fin() {
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
            let ttl = 20;
            let fw = StatefullFirewall::new_custom(3, ttl);

            let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);
            let conn_key = IpConnWithPort {
                remote_addr: test_input.them_ip(),
                remote_port: test_input.them_port(),
                local_addr: test_input.us_ip(),
                local_port: test_input.us_port(),
            };

            assert_eq!(fw.tcp.lock().unwrap().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: true, conn_remote_initiated: false
            }));

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::FIN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            assert_eq!(fw.tcp.lock().unwrap().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: false, conn_remote_initiated: false
            }));

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::FIN)), true);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            // update tcp cache entry timeout
            assert_eq!(fw.tcp.lock().unwrap().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: false, rx_alive: false, conn_remote_initiated: false
            }));

            // process inbound packet (should not update ttl, because not ACK, but entry should still exist)
            advance_time(Duration::from_millis(ttl / 2));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::PSH)), false);
            assert_eq!(fw.tcp.lock().unwrap().len(), 1);

            // process inbound packet (should not update ttl, because not ACK, and entry should be removed after timeout)
            advance_time(Duration::from_millis(ttl / 2 + 1));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::PSH)), false);
            assert_eq!(fw.tcp.lock().unwrap().len(), 0);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_icmp_cache_general() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            src3: &'static str,
            dst: &'static str,
            make_icmp: MakeIcmpWithBody,
        }

        let test_inputs = vec![
            TestInput { src1: "8.8.8.8",              src2: "8.8.4.4",              src3: "4.4.4.4",              dst: "127.0.0.1", make_icmp: &make_icmp4_with_body },
            TestInput { src1: "2001:4860:4860::8888", src2: "2001:4860:4860::8844", src3: "2001:4860:4860::4444", dst: "::1",       make_icmp: &make_icmp6_with_body },
        ];
        for TestInput{ src1, src2, src3, dst, make_icmp } in test_inputs {
            let fw = StatefullFirewall::new_custom(2, LRU_TIMEOUT);

            let request1 = make_icmp(dst, src1, IcmpTypes::EchoRequest.into(), &[1, 0, 1, 0]);
            let request2 = make_icmp(dst, src2, IcmpTypes::EchoRequest.into(), &[1, 0, 1, 0]);
            let request3 = make_icmp(dst, src3, IcmpTypes::EchoRequest.into(), &[1, 0, 1, 0]);
            let reply1 = make_icmp(src1, dst, IcmpTypes::EchoReply.into(), &[1, 0, 1, 0]);
            let reply2 = make_icmp(src2, dst, IcmpTypes::EchoReply.into(), &[1, 0, 1, 0]);
            let reply3 = make_icmp(src3, dst, IcmpTypes::EchoReply.into(), &[1, 0, 1, 0]);

            // Add src1, src2 and src3 to the cache, and dropping src1
            assert_eq!(fw.process_outbound_packet(&make_peer(), &request1), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &request2), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &request3), true);

            // src2 and src3 are in the cache so they pass, but src1 fails as it is not in the cache
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply1), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply2), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply3), true);

            // None of the entries are in the cache since they were removed when processing their previous inbound requests
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply1), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply2), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply3), false);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_icmp_cache_identifier_and_sequence() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_icmp: MakeIcmpWithBody,
        }

        let test_inputs = vec![
            TestInput { src: "8.8.8.8",              dst: "127.0.0.1", make_icmp: &make_icmp4_with_body },
            TestInput { src: "2001:4860:4860::8888", dst: "::1",       make_icmp: &make_icmp6_with_body },
        ];
        for TestInput{ src, dst, make_icmp } in test_inputs {
            let fw = StatefullFirewall::new();
            
            let request = make_icmp(dst, src, IcmpTypes::EchoRequest.into(), &[1, 0, 1, 0]);
            let reply1 = make_icmp(src, dst, IcmpTypes::EchoReply.into(), &[1, 0, 1, 0]);
            let reply2 = make_icmp(src, dst, IcmpTypes::EchoReply.into(), &[1, 0, 2, 0]);
            let reply3 = make_icmp(src, dst, IcmpTypes::EchoReply.into(), &[2, 0, 1, 0]);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &request), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply2), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply3), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &reply1), true);
        }
    }

    #[test]
    fn firewall_icmp_cache_key_by_type() {
        struct TestInput(
            GenericIcmpType,
            Option<GenericIcmpType>,
            &'static str,
            &'static str,
            MakeIcmpWithBody,
        );

        const V4_SRC_IP: &str = "8.8.8.8";
        const V4_DST_IP: &str = "127.0.0.1";

        const V6_SRC_IP: &str = "2001:4860:4860::8888";
        const V6_DST_IP: &str = "::1";

        let test_input_v4 = vec![
            (IcmpTypes::EchoRequest, Some(IcmpTypes::EchoReply)),
            (IcmpTypes::EchoReply, None),
            (IcmpTypes::Timestamp, Some(IcmpTypes::TimestampReply)),
            (IcmpTypes::TimestampReply, None),
            (
                IcmpTypes::InformationRequest,
                Some(IcmpTypes::InformationReply),
            ),
            (IcmpTypes::InformationReply, None),
            (
                IcmpTypes::AddressMaskRequest,
                Some(IcmpTypes::AddressMaskReply),
            ),
            (IcmpTypes::AddressMaskReply, None),
        ]
        .into_iter()
        .map(|(req, rep)| {
            TestInput(
                req.into(),
                rep.map(|r| r.into()),
                V4_SRC_IP,
                V4_DST_IP,
                &make_icmp4_with_body,
            )
        })
        .collect::<Vec<_>>();

        let test_input_v6 = vec![
            (Icmpv6Types::EchoRequest, Some(Icmpv6Types::EchoReply)),
            (Icmpv6Types::EchoReply, None),
        ]
        .into_iter()
        .map(|(req, rep)| {
            TestInput(
                req.into(),
                rep.map(|r| r.into()),
                V6_SRC_IP,
                V6_DST_IP,
                &make_icmp6_with_body,
            )
        })
        .collect::<Vec<_>>();

        for test_input in [test_input_v4, test_input_v6] {
            for TestInput(request_type, matching_reply, src_ip, _, make_request_packet) in
                &test_input
            {
                for TestInput(reply_type, _, _, dst_ip, make_reply_packet) in &test_input {
                    if request_type == reply_type {
                        continue;
                    }
                    let fw = StatefullFirewall::new();
                    let outbound =
                        make_request_packet(src_ip, dst_ip, *request_type, &[1, 0, 1, 0]);
                    let inbound = make_reply_packet(dst_ip, src_ip, *reply_type, &[1, 0, 1, 0]);
                    assert_eq!(fw.process_outbound_packet(&make_peer(), &outbound), true);
                    assert_eq!(
                        fw.process_inbound_packet(&make_peer(), &inbound),
                        matches!(matching_reply, Some(rt) if rt == reply_type)
                    );
                }
            }
        }
    }

    #[test]
    fn firewall_icmp_cache_error_response_icmp() {
        struct TestInput(
            &'static str,
            &'static str,
            GenericIcmpType,
            GenericIcmpType,
            MakeIcmpWithBody,
        );
        for TestInput(src, dst, request_type, error_type, make_icmp) in [
            TestInput(
                "8.8.8.8",
                "127.0.0.1",
                IcmpTypes::EchoRequest.into(),
                IcmpTypes::DestinationUnreachable.into(),
                &make_icmp4_with_body,
            ),
            TestInput(
                "2001:4860:4860::8888",
                "::1",
                Icmpv6Types::EchoRequest.into(),
                Icmpv6Types::DestinationUnreachable.into(),
                &make_icmp6_with_body,
            ),
        ] {
            let fw = StatefullFirewall::new();

            let actual_request = make_icmp(src, dst, request_type, &[1, 0, 1, 0]);
            let other_request = make_icmp(src, dst, request_type, &[2, 0, 3, 0]);

            let mut actual_response_body = vec![0; 4];
            actual_response_body.extend_from_slice(&actual_request);
            let actual_response = make_icmp(dst, src, error_type, &actual_response_body);

            let mut other_response_body = vec![0; 4];
            other_response_body.extend_from_slice(&other_request);
            let other_response = make_icmp(dst, src, error_type, &other_response_body);

            assert_eq!(
                fw.process_outbound_packet(&make_peer(), &actual_request),
                true
            );
            assert_eq!(
                fw.process_inbound_packet(&make_peer(), &other_response),
                false
            );
            assert_eq!(
                fw.process_inbound_packet(&make_peer(), &actual_response),
                true
            );
        }
    }

    #[test]
    fn firewall_icmp_cache_error_response_tcp() {
        struct TestInput(
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            GenericIcmpType,
            MakeTcp,
            MakeIcmpWithBody,
        );
        for TestInput(
            src1,
            src1_with_port,
            src2,
            src2_with_port,
            dst,
            dst_with_port,
            error_type,
            make_tcp,
            make_icmp,
        ) in [
            TestInput(
                "8.8.8.8",
                "8.8.8.8:8888",
                "8.8.4.4",
                "8.8.4.4:4444",
                "127.0.0.1",
                "127.0.0.1:1111",
                IcmpTypes::DestinationUnreachable.into(),
                &make_tcp,
                &make_icmp4_with_body,
            ),
            TestInput(
                "2001:4860:4860::8888",
                "[2001:4860:4860::8888]:8888",
                "2001:4860:4860::4444",
                "[2001:4860:4860::4444]:4444",
                "::1",
                "[::1]:1111",
                Icmpv6Types::DestinationUnreachable.into(),
                &make_tcp6,
                &make_icmp6_with_body,
            ),
        ] {
            let fw = StatefullFirewall::new();

            let actual_request = make_tcp(src1_with_port, dst_with_port, TcpFlags::SYN);
            let other_request = make_tcp(src2_with_port, dst_with_port, TcpFlags::SYN);

            let mut actual_response_body = vec![0; 4];
            actual_response_body.extend_from_slice(&actual_request);
            let actual_response = make_icmp(dst, src1, error_type, &actual_response_body);

            let mut other_response_body = vec![0; 4];
            other_response_body.extend_from_slice(&other_request);
            let other_response = make_icmp(dst, src2, error_type, &other_response_body);

            assert_eq!(
                fw.process_outbound_packet(&make_peer(), &actual_request),
                true
            );
            assert_eq!(
                fw.process_inbound_packet(&make_peer(), &other_response),
                false
            );
            assert_eq!(
                fw.process_inbound_packet(&make_peer(), &actual_response),
                true
            );
        }
    }

    #[test]
    fn firewall_icmp_cache_error_response_udp() {
        struct TestInput(
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            GenericIcmpType,
            MakeUdp,
            MakeIcmpWithBody,
        );
        for TestInput(
            src1,
            src1_with_port,
            src2,
            src2_with_port,
            dst,
            dst_with_port,
            error_type,
            make_udp,
            make_icmp,
        ) in [
            TestInput(
                "8.8.8.8",
                "8.8.8.8:8888",
                "8.8.4.4",
                "8.8.4.4:4444",
                "127.0.0.1",
                "127.0.0.1:1111",
                IcmpTypes::DestinationUnreachable.into(),
                &make_udp,
                &make_icmp4_with_body,
            ),
            TestInput(
                "2001:4860:4860::8888",
                "[2001:4860:4860::8888]:8888",
                "2001:4860:4860::4444",
                "[2001:4860:4860::4444]:4444",
                "::1",
                "[::1]:1111",
                Icmpv6Types::DestinationUnreachable.into(),
                &make_udp6,
                &make_icmp6_with_body,
            ),
        ] {
            let fw = StatefullFirewall::new();

            let actual_request = make_udp(src1_with_port, dst_with_port);
            let other_request = make_udp(src2_with_port, dst_with_port);

            let mut actual_response_body = vec![0; 4];
            actual_response_body.extend_from_slice(&actual_request);
            let actual_response = make_icmp(dst, src1, error_type, &actual_response_body);

            let mut other_response_body = vec![0; 4];
            other_response_body.extend_from_slice(&other_request);
            let other_response = make_icmp(dst, src2, error_type, &other_response_body);

            assert_eq!(
                fw.process_outbound_packet(&make_peer(), &actual_request),
                true
            );
            assert_eq!(
                fw.process_inbound_packet(&make_peer(), &other_response),
                false
            );
            assert_eq!(
                fw.process_inbound_packet(&make_peer(), &actual_response),
                true
            );
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_icmp_type() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            dst: &'static str,
            make_icmp: MakeIcmp,
            is_v4: bool,
        }

        let test_inputs = vec![
            TestInput { src1: "8.8.8.8",             src2: "8.8.4.4",              dst: "127.0.0.1", make_icmp: &make_icmp4, is_v4: true },
            TestInput { src1: "2001:4860:4860::8888",src2: "2001:4860:4860::8844", dst: "::1",       make_icmp: &make_icmp6, is_v4: false},
        ];
        for TestInput { src1, src2, dst, make_icmp, is_v4 } in test_inputs {
            // Set capacity to 0 to test only blocking of blacklisted icmp types
            let fw = StatefullFirewall::new_custom(0, LRU_TIMEOUT);

            // Firewall only allow inbound ICMP packets that are either whitelisted or that exist in the ICMP cache
            // The ICMP cache only accepts a small number of ICMP types, but unrelated to that, this test ignores the cache completely
            // As a result of that, no inbound packets are allowed here, but all outbound packets are
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::EchoRequest.into())), false);
            if is_v4 {
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::Timestamp.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::InformationRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::AddressMaskRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::Traceroute.into())), false);
            } else {
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, Icmpv6Types::PacketTooBig.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, Icmpv6Types::EchoRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, Icmpv6Types::RouterAdvert.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, Icmpv6Types::NeighborSolicit.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, Icmpv6Types::NeighborAdvert.into())), false);
            }
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src2, dst, IcmpTypes::EchoRequest.into())), false);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp(dst, src1, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp(dst, src2, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp(dst, src1, IcmpTypes::EchoRequest.into())), true);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::EchoReply.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src2, dst, IcmpTypes::EchoReply.into())), false);

            if is_v4 {
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::TimestampReply.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::AddressMaskReply.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::InformationReply.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::RouterSolicitation.into())), false);
            } else {
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::RouterSolicitation.into())), false);
            }
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::DestinationUnreachable.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::ParameterProblem.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::TimeExceeded.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(src1, dst, IcmpTypes::RedirectMessage.into())), false);
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
            advance_time(Duration::from_millis(200));
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
            advance_time(Duration::from_millis(15));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), true);

            //Should PASS (because TTL was extended)
            advance_time(Duration::from_millis(15));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), true);

            //Should FAIL (because TTL=100 < sleep(200))
            advance_time(Duration::from_millis(30));
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
                make_icmp: &make_icmp4,
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
            assert_eq!(fw.process_inbound_packet(&peer1.0, &make_icmp(&src, &dst, IcmpTypes::EchoRequest.into())), false);
            assert_eq!(fw.process_inbound_packet(&peer2.0, &make_icmp(&src, &dst, IcmpTypes::EchoRequest.into())), true);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_icmp() {
        struct TestInput {
            us: &'static str,
            them: &'static str,
            make_icmp: MakeIcmp,
            is_v4: bool,
        }

        let test_inputs = vec![
            TestInput{ us: "127.0.0.1", them: "8.8.8.8",              make_icmp: &make_icmp4, is_v4: true },
            TestInput{ us: "::1",       them: "2001:4860:4860::8888", make_icmp: &make_icmp6, is_v4: false },
        ];
        for TestInput { us, them, make_icmp, is_v4 } in test_inputs {
            // Set number of conntrack entries to 0 to test only the whitelist
            let fw = StatefullFirewall::new_custom(0, 20);

            let peer = make_random_peer();
            assert_eq!(fw.process_outbound_packet(&peer.0, &make_icmp(us, them, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoReply.into())), false);

            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoRequest.into())), false);
            if is_v4 {
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::Timestamp.into())), false);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::InformationRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::AddressMaskRequest.into())), false);
            }

            fw.add_to_peer_whitelist(peer);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoReply.into())), true);
            if is_v4 {
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::Timestamp.into())), true);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::InformationRequest.into())), true);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::AddressMaskRequest.into())), true);
            }
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
                make_icmp: &make_icmp4,
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
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), false);

            fw.add_to_peer_whitelist((&make_peer()).into());
            assert_eq!(fw.get_peer_whitelist().len(), 1);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), true);

            fw.remove_from_peer_whitelist((&make_peer()).into());
            assert_eq!(fw.get_peer_whitelist().len(), 0);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), false);
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
                make_udp: &make_udp, make_tcp: &make_tcp, make_icmp: &make_icmp4,
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
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&test_input.src, &test_input.dst, IcmpTypes::EchoRequest.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), false);

            fw.add_to_port_whitelist(PublicKey(make_peer()), FILE_SEND_PORT);
            assert_eq!(fw.get_port_whitelist().len(), 1);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&test_input.src, &test_input.dst, IcmpTypes::EchoRequest.into())), false);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), true);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(&test_input.src_socket(11111), &test_input.dst_socket(12345))), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(12345), TcpFlags::PSH)), false);

            fw.remove_from_port_whitelist(PublicKey(make_peer()));
            assert_eq!(fw.get_port_whitelist().len(), 0);

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT))), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&test_input.src, &test_input.dst, IcmpTypes::EchoRequest.into())), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(&test_input.src_socket(11111), &test_input.dst_socket(FILE_SEND_PORT), TcpFlags::PSH)), false);
        }
    }
}
