//! Telio firewall component used to track open connections
//! with other devices§

use log::error;
use lru_time_cache::LruCache;
use pnet_packet::{
    icmp::{IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    udp::UdpPacket,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use telio_crypto::PublicKey;
use telio_utils::{telio_log_debug, telio_log_trace};

const LRU_CAPACITY: usize = 4096; // Max entries to keep (sepatately for TCP, UDP, and others)
const LRU_TIMEOUT: u64 = 120_000; // 2min (https://datatracker.ietf.org/doc/html/rfc4787#section-4.3)

const TCP_FIRST_PKT_MASK: u16 = TcpFlags::SYN | TcpFlags::ACK;
const ICMP_BLOCK_TYPES_MASK: u32 = 1 << IcmpTypes::EchoRequest.0
    | 1 << IcmpTypes::Timestamp.0
    | 1 << IcmpTypes::InformationRequest.0
    | 1 << IcmpTypes::AddressMaskRequest.0;

/// File sending port
pub const FILE_SEND_PORT: u16 = 49111;

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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
struct IpConnWithPort {
    remote_addr: u32,
    remote_port: u16,
    local_addr: u32,
    local_port: u16,
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

    fn handle_outbound_udp(&self, ip: &Ipv4Packet, buffer: &[u8]) {
        let ip_header_len_bytes = (ip.get_header_length() as usize) * 4; //IPv4->IHL to bytes
        let udp_packet = unwrap_option_or_return!(UdpPacket::new(unwrap_option_or_return!(
            buffer.get(ip_header_len_bytes..)
        )));
        let key = IpConnWithPort {
            remote_addr: u32::from(ip.get_destination()),
            remote_port: udp_packet.get_destination(),
            local_addr: u32::from(ip.get_source()),
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

    fn handle_outbound_tcp(&self, ip: &Ipv4Packet, buffer: &[u8]) {
        let ip_header_len_bytes = (ip.get_header_length() as usize) * 4; //IPv4->IHL to bytes
        let tcp_packet = unwrap_option_or_return!(TcpPacket::new(unwrap_option_or_return!(
            buffer.get(ip_header_len_bytes..)
        )));
        let key = IpConnWithPort {
            remote_addr: u32::from(ip.get_destination()),
            remote_port: tcp_packet.get_destination(),
            local_addr: u32::from(ip.get_source()),
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

    fn handle_inbound_udp(
        &self,
        whitelist: &Whitelist,
        peer: &PublicKey,
        ip: &Ipv4Packet,
        buffer: &[u8],
    ) -> bool {
        let ip_header_len_bytes = (ip.get_header_length() as usize) * 4; //IPv4->IHL to bytes
        let udp_packet = unwrap_option_or_return!(
            UdpPacket::new(unwrap_option_or_return!(
                buffer.get(ip_header_len_bytes..),
                false
            )),
            false
        );
        let key = IpConnWithPort {
            remote_addr: u32::from(ip.get_source()),
            remote_port: udp_packet.get_source(),
            local_addr: u32::from(ip.get_destination()),
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

    fn handle_inbound_tcp(
        &self,
        whitelist: &Whitelist,
        peer: &PublicKey,
        ip: &Ipv4Packet,
        buffer: &[u8],
    ) -> bool {
        let ip_header_len_bytes = (ip.get_header_length() as usize) * 4; //IPv4->IHL to bytes
        let tcp_packet = unwrap_option_or_return!(
            TcpPacket::new(unwrap_option_or_return!(
                buffer.get(ip_header_len_bytes..),
                false
            )),
            false
        );
        let key = IpConnWithPort {
            remote_addr: u32::from(ip.get_source()),
            remote_port: tcp_packet.get_source(),
            local_addr: u32::from(ip.get_destination()),
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

    fn handle_inbound_icmp(
        &self,
        _whitelist: &Whitelist,
        peer: &PublicKey,
        ip: &Ipv4Packet,
        buffer: &[u8],
    ) -> bool {
        let ip_header_len_bytes = (ip.get_header_length() as usize) * 4; //IPv4->IHL to bytes
        let icmp_packet = unwrap_option_or_return!(
            IcmpPacket::new(unwrap_option_or_return!(
                buffer.get(ip_header_len_bytes..),
                false
            )),
            false
        );

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
        let ip = unwrap_option_or_return!(Ipv4Packet::new(buffer), false);
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

        if !check_valid(&ip) {
            telio_log_trace!("Outbound IP packet is not valid, dropping: {:?}", ip);
            return false;
        }

        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                self.handle_outbound_udp(&ip, buffer);
            }
            IpNextHeaderProtocols::Tcp => {
                self.handle_outbound_tcp(&ip, buffer);
            }
            _ => (),
        };

        telio_log_trace!("Accepting packet {:?} {:?}", ip, peer);
        true
    }

    /// Checks if incoming packet should be accepted.
    /// Does not extend pinhole lifetime on success
    /// Adds new connection to cache only if ip is whitelisted
    /// Allows all icmp packets except for request types
    fn process_inbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool {
        let ip = unwrap_option_or_return!(Ipv4Packet::new(buffer), false);
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

        if !check_valid(&ip) {
            telio_log_trace!("Inbound IP packet is not valid, dropping: {:?}", ip);
            return false;
        }

        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => self.handle_inbound_udp(&whitelist, &peer, &ip, buffer),
            IpNextHeaderProtocols::Tcp => self.handle_inbound_tcp(&whitelist, &peer, &ip, buffer),
            IpNextHeaderProtocols::Icmp => self.handle_inbound_icmp(&whitelist, &peer, &ip, buffer),
            _ => false,
        }
    }
}

/// The default initialization of Firewall object
impl Default for StatefullFirewall {
    fn default() -> Self {
        Self::new()
    }
}

fn check_valid(ip: &Ipv4Packet) -> bool {
    if ip.get_version() != 4 {
        return false; // non IPv4 => DROP
    }
    if ip.get_header_length() < 5 {
        return false; // IPv4->IHL < 5 => DROP
    }
    true
}

#[cfg(any(test, feature = "test_utils"))]
#[allow(missing_docs, unused)]
pub mod tests {
    use super::*;
    use pnet_packet::{
        icmp::{IcmpType, MutableIcmpPacket},
        ip::IpNextHeaderProtocol,
        ipv4::MutableIpv4Packet,
        tcp::MutableTcpPacket,
        udp::MutableUdpPacket,
        MutablePacket,
    };
    use std::time::Duration;
    use std::{net::Ipv4Addr, thread::sleep};
    use telio_crypto::SecretKey;

    const IP_HEADER_MIN: usize = 20; // IPv4 header minimal length in bytes
    const TCP_HEADER_MIN: usize = 20; // TCP header minimal length in bytes
    const UDP_HEADER: usize = 8; // UDP header length in bytes
    const ICMP_HEADER: usize = 8; // ICMP header length in bytes

    fn set_ipv4(
        ip: &mut MutableIpv4Packet,
        protocol: IpNextHeaderProtocol,
        header_length: u16,
        total_length: u16,
    ) {
        ip.set_next_level_protocol(protocol);
        ip.set_version(4);
        ip.set_header_length((header_length / 4) as u8);
        ip.set_total_length(total_length);
        ip.set_flags(2);
        ip.set_ttl(64);
        ip.set_source(Ipv4Addr::LOCALHOST);
        ip.set_destination(Ipv4Addr::new(8, 8, 8, 8));
    }

    fn make_random_peer() -> PublicKey {
        let sk = SecretKey::gen();
        sk.public()
    }

    fn make_peer() -> [u8; 32] {
        [1; 32]
    }

    pub fn make_udp(src: &str, dst: &str) -> Vec<u8> {
        let msg: &str = "Some message";
        let (saddr, sport) = src.split_once(":").expect("UDP: Bad src address");
        let (daddr, dport) = dst.split_once(":").expect("UDP: Bad dst address");

        let msg_len = msg.as_bytes().len(); // bytes
        let ip_len = IP_HEADER_MIN + UDP_HEADER + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("UDP: Bad IP buffer");
        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Udp,
            IP_HEADER_MIN as u16,
            ip_len as u16,
        );
        ip.set_source(saddr.parse().expect("UDP: Bad src IP"));
        ip.set_destination(daddr.parse().expect("UDP: Bad dst IP"));

        let mut udp =
            MutableUdpPacket::new(&mut raw[IP_HEADER_MIN..]).expect("UDP: Bad UDP buffer");
        udp.set_source(sport.parse().expect("UDP: Bad src port"));
        udp.set_destination(dport.parse().expect("UDP: Bad dst port"));
        udp.set_length((UDP_HEADER + msg_len) as u16);
        udp.set_checksum(0);
        udp.payload_mut().copy_from_slice(msg.as_bytes());

        raw
    }

    pub fn make_tcp(src: &str, dst: &str, flags: u16) -> Vec<u8> {
        let msg: &str = "Some message";
        let (saddr, sport) = src.split_once(":").expect("TCP: Bad src address");
        let (daddr, dport) = dst.split_once(":").expect("TCP: Bad dst address");

        let msg_len = msg.as_bytes().len(); // bytes
        let ip_len = IP_HEADER_MIN + TCP_HEADER_MIN + msg_len;
        let mut raw = vec![0u8; ip_len];

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("TCP: Bad IP buffer");
        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Tcp,
            IP_HEADER_MIN as u16,
            ip_len as u16,
        );
        ip.set_source(saddr.parse().expect("TCP: Bad src IP"));
        ip.set_destination(daddr.parse().expect("TCP: Bad dst IP"));

        let mut tcp =
            MutableTcpPacket::new(&mut raw[IP_HEADER_MIN..]).expect("TCP: Bad TCP buffer");
        tcp.set_source(sport.parse().expect("TCP: Bad src port"));
        tcp.set_destination(dport.parse().expect("TCP: Bad dst port"));
        tcp.set_checksum(0);
        tcp.payload_mut().copy_from_slice(msg.as_bytes());
        tcp.set_flags(flags);

        raw
    }

    fn make_icmp(src: &str, dst: &str, icmp_type: &IcmpType) -> Vec<u8> {
        let ip_len = IP_HEADER_MIN + ICMP_HEADER + 10;
        let mut raw = vec![0u8; ip_len];

        let mut packet =
            MutableIcmpPacket::new(&mut raw[IP_HEADER_MIN..]).expect("ICMP: Bad ICMP buffer");
        packet.set_icmp_type(icmp_type.clone());

        let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
        set_ipv4(
            &mut ip,
            IpNextHeaderProtocols::Icmp,
            IP_HEADER_MIN as u16,
            ip_len as u16,
        );
        ip.set_source(src.parse().expect("ICMP: Bad src IP"));
        ip.set_destination(dst.parse().expect("ICMP: Bad dst IP"));

        raw
    }

    #[test]
    fn firewall_packet_validation() {
        let mut raw = make_icmp("127.0.0.1", "8.8.8.8", &IcmpTypes::EchoRequest);
        let mut ip = MutableIpv4Packet::new(&mut raw).expect("PRE: Bad IP buffer");
        assert_eq!(check_valid(&ip.to_immutable()), true);

        ip.set_version(4);
        assert_eq!(check_valid(&ip.to_immutable()), true);

        ip.set_version(0); // Invalid IP version
        assert_eq!(check_valid(&ip.to_immutable()), false);

        ip.set_version(6); // Only Ipv4 supported
        assert_eq!(check_valid(&ip.to_immutable()), false);

        ip.set_version(4);
        ip.set_header_length(4); // Ipv4->IHL must be [5..15]
        assert_eq!(check_valid(&ip.to_immutable()), false);

        let icmp = MutableIcmpPacket::new(&mut raw[IP_HEADER_MIN..]).expect("PRE: Bad ICMP buffer");
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoRequest);
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
            PACKET_LENGTH as u16,
            PACKET_LENGTH as u16,
        );
        assert_eq!(check_valid(&ip.to_immutable()), true); // IPv4->IHL=15 => continue
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_udp() {
        let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

        // Should FAIL (no matching outgoing connections yet)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:2222")), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:3333")), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:4444")), false);
        assert_eq!(fw.udp.lock().unwrap().len(), 0);

        // Should PASS (adds 1111..4444 and drops 2222)
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:1111", "8.8.8.8:8888")), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:2222", "8.8.8.8:8888")), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:1111", "8.8.8.8:8888")), true);
        assert_eq!(fw.udp.lock().unwrap().len(), 2);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:3333", "8.8.8.8:8888")), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:1111", "8.8.8.8:8888")), true);
        assert_eq!(fw.udp.lock().unwrap().len(), 3);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:4444", "8.8.8.8:8888")), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:1111", "8.8.8.8:8888")), true);
        assert_eq!(fw.udp.lock().unwrap().len(), 3);

        // Should PASS (matching outgoing connections exist in LRUCache)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:3333")), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:4444")), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), true);

        // Should FAIL (was added but dropped from LRUCache)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:2222")), false);

        // Should FAIL (has no matching outgoing connection)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:5555")), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:7777", "127.0.0.1:1111")), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("127.0.0.1:1111", "8.8.8.8:8888")), false);
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_tcp() {
        let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

        // Should FAIL (no matching outgoing connections yet)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:1111", TcpFlags::SYN)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:2222", TcpFlags::SYN)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:3333", TcpFlags::SYN)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:4444", TcpFlags::SYN)), false);
        assert_eq!(fw.tcp.lock().unwrap().len(), 0);

        // Should PASS (adds 1111..4444 and drops 2222)
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp("127.0.0.1:1111", "8.8.8.8:8888", TcpFlags::SYN)), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp("127.0.0.1:2222", "8.8.8.8:8888", TcpFlags::SYN)), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp("127.0.0.1:1111", "8.8.8.8:8888", TcpFlags::SYN)), true);
        assert_eq!(fw.tcp.lock().unwrap().len(), 2);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp("127.0.0.1:3333", "8.8.8.8:8888", TcpFlags::SYN)), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp("127.0.0.1:1111", "8.8.8.8:8888", TcpFlags::SYN)), true);
        assert_eq!(fw.tcp.lock().unwrap().len(), 3);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp("127.0.0.1:4444", "8.8.8.8:8888", TcpFlags::SYN)), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp("127.0.0.1:1111", "8.8.8.8:8888", TcpFlags::SYN)), true);
        assert_eq!(fw.tcp.lock().unwrap().len(), 3);

        // Should PASS (matching outgoing connections exist in LRUCache)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:4444", TcpFlags::SYN)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:3333", TcpFlags::SYN)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:1111", TcpFlags::SYN)), true);

        // Should FAIL (was added but dropped from LRUCache)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:2222", TcpFlags::SYN)), false);

        // Should FAIL (has no matching outgoing connection)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:8888", "127.0.0.1:5555", TcpFlags::SYN)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("8.8.8.8:7777", "127.0.0.1:1111", TcpFlags::SYN)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("127.0.0.1:1111", "8.8.8.8:8888", TcpFlags::SYN)), false);
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_tcp_states() {
        let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

        let us = "127.0.0.1:1111";
        let them = "8.8.8.8:8888";
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN)), false);

        let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);

        assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN)), true);

        let ip_packet = Ipv4Packet::new(&outgoing_init_packet).expect("PRE: Bad IP buffer");
        let tcp_packet = TcpPacket::new(&outgoing_init_packet[IP_HEADER_MIN..]).expect("TCP: Bad TCP buffer");
        let conn_key = IpConnWithPort {
            remote_addr: u32::from(ip_packet.get_destination()),
            remote_port: tcp_packet.get_destination(),
            local_addr: u32::from(ip_packet.get_source()),
            local_port: tcp_packet.get_source(),
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

    #[rustfmt::skip]
    #[test]
    fn firewall_icmp() {
        let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT);

        // Should FAIL (should always block request type icmp, unless whitelisted)
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::EchoRequest)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::Timestamp)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::InformationRequest)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::AddressMaskRequest)), false);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.4.4", "127.0.0.1", &IcmpTypes::EchoRequest)), false);

        // Should PASS
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp("127.0.0.1", "8.8.8.8", &IcmpTypes::EchoRequest)), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp("127.0.0.1", "8.8.4.4", &IcmpTypes::EchoRequest)), true);
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_icmp("127.0.0.1", "8.8.8.8", &IcmpTypes::EchoRequest)), true);

        // Should PASS
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::EchoReply)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.4.4", "127.0.0.1", &IcmpTypes::EchoReply)), true);

        // Should PASS
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::TimestampReply)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::AddressMaskReply)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::DestinationUnreachable)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::InformationReply)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::ParameterProblem)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::RouterSolicitation)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::Traceroute)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::TimeExceeded)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("8.8.8.8", "127.0.0.1", &IcmpTypes::RedirectMessage)), true);
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_pinhole_timeout() {
        let fw = StatefullFirewall::new_custom(3, 100);

        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:1111", "8.8.8.8:8888")), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), true);
        sleep(Duration::from_millis(200));
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), false);
    }

    #[rustfmt::skip]
    #[test]
    #[ignore]
    fn firewall_pinhole_timeout_extending() {
        let capacity = 3;
        let ttl = 20;
        let fw = StatefullFirewall::new_custom(capacity, ttl);

        // Should PASS (adds 1111)
        assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp("127.0.0.1:1111", "8.8.8.8:8888")), true);

        //Should PASS
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), true);
        sleep(Duration::from_millis(15));
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), true);

        //Should PASS (because TTL was extended)
        sleep(Duration::from_millis(15));
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), true);

        //Should FAIL (because TTL=100 < sleep(200))
        sleep(Duration::from_millis(30));
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("8.8.8.8:8888", "127.0.0.1:1111")), false);
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
        let fw = StatefullFirewall::new();
        let peer1 = make_random_peer();
        let peer2 = make_random_peer();

        assert!(fw.get_peer_whitelist().is_empty());

        assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp("100.100.100.100:1234", "127.0.0.1:1111",)), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp("100.100.100.101:1234", "127.0.0.1:1111",)), false);

        fw.add_to_port_whitelist(peer2, 1111);
        assert_eq!(fw.get_port_whitelist().len(), 1);

        assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp("100.100.100.100:1234", "127.0.0.1:1111",)), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp("100.100.100.101:1234", "127.0.0.1:1111",)), true);
        assert_eq!(fw.udp.lock().unwrap().len(), 1);

        
        assert_eq!(fw.process_inbound_packet(&peer1.0, &make_tcp("100.100.100.100:1000", "127.0.0.1:1000", TcpFlags::SYN)), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp("100.100.100.101:2222", "127.0.0.1:1111", TcpFlags::SYN | TcpFlags::ACK)), true);
        assert_eq!(fw.tcp.lock().unwrap().len(), 0);
        // only this one should be added to cache
        assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp("100.100.100.101:1111", "127.0.0.1:1111", TcpFlags::SYN)), true);
        assert_eq!(fw.tcp.lock().unwrap().len(), 1);

        fw.add_to_peer_whitelist(peer2);
        assert_eq!(fw.process_inbound_packet(&peer1.0, &make_icmp("100.100.100.100", "127.0.0.1", &IcmpTypes::EchoRequest)), false);
        assert_eq!(fw.process_inbound_packet(&peer2.0, &make_icmp("100.100.100.101", "127.0.0.1",&IcmpTypes::EchoRequest)), true);
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_icmp() {
        let fw = StatefullFirewall::new();

        let us = "127.0.0.1";
        let them = "8.8.8.8";
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

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_udp_allow() {
        let fw = StatefullFirewall::new();

        let us = "127.0.0.1:1111";
        let them = "8.8.8.8:8888";
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

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_udp_block() {
        let fw = StatefullFirewall::new();

        let us = "127.0.0.1:1111";
        let them = "8.8.8.8:8888";
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

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_tcp_allow() {
        let fw = StatefullFirewall::new();

        let us = "127.0.0.1:1111";
        let them = "8.8.8.8:8888";
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

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_change_tcp_block() {
        let fw = StatefullFirewall::new();

        let us = "127.0.0.1:1111";
        let them = "8.8.8.8:8888";
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

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_peer() {
        let fw = StatefullFirewall::new();
        assert!(fw.get_peer_whitelist().is_empty());

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("100.100.100.100:1234", "127.0.0.1:1111",)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("100.100.100.101", "127.0.0.1",&IcmpTypes::EchoRequest)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("100.100.100.101:1234", "127.0.0.1:1111", TcpFlags::PSH)), false);

        fw.add_to_peer_whitelist((&make_peer()).into());
        assert_eq!(fw.get_peer_whitelist().len(), 1);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("100.100.100.100:1234", "127.0.0.1:1111",)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("100.100.100.101", "127.0.0.1",&IcmpTypes::EchoRequest)), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("100.100.100.101:1234", "127.0.0.1:1111", TcpFlags::PSH)), true);

        fw.remove_from_peer_whitelist((&make_peer()).into());
        assert_eq!(fw.get_peer_whitelist().len(), 0);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("100.100.100.100:1234", "127.0.0.1:1111",)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("100.100.100.101", "127.0.0.1",&IcmpTypes::EchoRequest)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("100.100.100.101:1234", "127.0.0.1:1111", TcpFlags::PSH)), false);
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_whitelist_port() {
        let fw = StatefullFirewall::new();
        assert!(fw.get_peer_whitelist().is_empty());
        assert!(fw.get_port_whitelist().is_empty());

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("100.100.100.100:11111", format!("127.0.0.1:{}", FILE_SEND_PORT).as_str())), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("100.100.100.100", "127.0.0.1",&IcmpTypes::EchoRequest)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("100.100.100.100:11111", format!("127.0.0.1:{}", FILE_SEND_PORT).as_str(), TcpFlags::PSH)), false);

        fw.add_to_port_whitelist(PublicKey(make_peer()), FILE_SEND_PORT);
        assert_eq!(fw.get_port_whitelist().len(), 1);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("100.100.100.100", "127.0.0.1",&IcmpTypes::EchoRequest)), false);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("100.100.100.100:11111", format!("127.0.0.1:{}", FILE_SEND_PORT).as_str())), true);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("100.100.100.100:11111", format!("127.0.0.1:{}", FILE_SEND_PORT).as_str(), TcpFlags::PSH)), true);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("100.100.100.100:11111", "127.0.0.1:12345")), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("100.100.100.100:11111", "127.0.0.1:12345", TcpFlags::PSH)), false);

        fw.remove_from_port_whitelist(PublicKey(make_peer()));
        assert_eq!(fw.get_port_whitelist().len(), 0);

        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp("100.100.100.100:11111", format!("127.0.0.1:{}", FILE_SEND_PORT).as_str())), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp("100.100.100.100", "127.0.0.1",&IcmpTypes::EchoRequest)), false);
        assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp("100.100.100.100:11111", format!("127.0.0.1:{}", FILE_SEND_PORT).as_str(), TcpFlags::PSH)), false);
    }
}
