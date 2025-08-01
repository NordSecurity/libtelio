use std::{
    convert::TryInto,
    fmt::{Debug, Formatter},
    io,
    net::IpAddr as StdIpAddr,
    time::Duration,
};

use parking_lot::Mutex;
use pnet_packet::{
    icmp::{destination_unreachable::IcmpCodes, IcmpPacket, IcmpTypes, MutableIcmpPacket},
    icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
    udp::UdpPacket,
    Packet,
};
use smallvec::{SmallVec, ToSmallVec};
use telio_utils::{telio_log_debug, telio_log_trace, telio_log_warn, Entry, LruCache};

use crate::firewall::{IpAddr, IpPacket, TCP_FIRST_PKT_MASK};

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    MalformedIpPacket,
    MalformedUdpPacket,
    MalformedTcpPacket,
    MalformedIcmpPacket,
    UnexpectedProtocol,
    InvalidIcmpErrorPayload,
    UnexpectedPacketType,
    NullPointer,
    NotImplemented,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

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

pub(crate) use unwrap_option_or_return;

const KEY_SIZE: usize = 32;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct IpConnWithPort {
    pub(crate) remote_addr: IpAddr,
    pub(crate) remote_port: u16,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
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

pub(crate) type AssociatedData = Option<SmallVec<[u8; KEY_SIZE]>>;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct Connection {
    pub(crate) link: IpConnWithPort,
    // Data associated with the packets, usually the public keys refering
    // to source peer for inbound connections and destination peer for outbound
    // connections, which may be used for tracking and filtering packets
    pub(crate) associated_data: AssociatedData,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct IcmpConn {
    remote_addr: IpAddr,
    local_addr: IpAddr,
    response_type: u8,
    identifier_sequence: u32,
    // Data associated with the packets, usually the public keys refering
    // to source peer for inbound connections and destination peer for outbound
    // connections, which may be used for tracking and filtering packets
    associated_data: AssociatedData,
}

enum IcmpKey {
    Conn(IcmpConn),
    Err(IcmpErrorKey),
}

#[derive(Clone, Debug)]
pub enum IcmpErrorKey {
    Udp(IpConnWithPort),
    Tcp(IpConnWithPort),
    Icmp(Box<IcmpConn>),
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

///
/// Packet direction
///
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LibfwDirection {
    /// Outgoing packets
    LibfwDirectionOutbound = 0,
    /// Incoming packets
    LibfwDirectionInbound = 1,
}

///
/// Connection state
///
#[allow(clippy::enum_variant_names)]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LibfwConnectionState {
    /// Connection established
    LibfwConnectionStateEstablished,
    /// Outgoing packets
    LibfwConnectionStateNew,
    /// Finished connections
    LibfwConnectionStateClosed,
}

#[derive(Clone, Debug)]
pub struct UdpConnectionInfo {
    pub(crate) is_remote_initiated: bool,
    pub(crate) last_out_pkg_chunk: Option<Vec<u8>>,
    pub(crate) state: LibfwConnectionState,
}

impl UdpConnectionInfo {
    /// UDP packet header contains at least 8 bytes and IP packet header is
    /// 20-60 bytes long, so we need to store up to 68 bytes of previus
    /// packet
    /// For IPv6 the fixed header is 40 bytes long. There is no upper limit for
    /// a header with extensions. Let's stick with the value for IPv4. In the worst
    /// case we will not be able to reset IPv6 connections with unusually long header.
    pub(crate) const LAST_PKG_MAX_CHUNK_LEN: usize = 60 + 8;
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct TcpConnectionInfo {
    pub(crate) tx_alive: bool,
    pub(crate) rx_alive: bool,
    pub(crate) conn_remote_initiated: bool,
    pub(crate) next_seq: Option<u32>,
    pub(crate) state: LibfwConnectionState,
}

pub(crate) struct Conntrack {
    /// Recent udp connections
    pub(crate) udp: Mutex<LruCache<Connection, UdpConnectionInfo>>,
    /// Recent tcp connections
    pub(crate) tcp: Mutex<LruCache<Connection, TcpConnectionInfo>>,
    /// Recent icmp connections
    pub(crate) icmp: Mutex<LruCache<IcmpConn, ()>>,
}

impl Conntrack {
    /// Constructs a new conntrack
    pub(crate) fn new(capacity: usize, ttl: u64) -> Self {
        let ttl = Duration::from_millis(ttl);
        Self {
            tcp: Mutex::new(LruCache::new(ttl, capacity)),
            udp: Mutex::new(LruCache::new(ttl, capacity)),
            icmp: Mutex::new(LruCache::new(ttl, capacity)),
        }
    }

    #[cfg(any(feature = "test_utils", test))]
    /// Return the size of conntrack entries for tcp and udp (for testing only).                                 
    pub fn get_state(&self) -> (usize, usize) {
        (self.tcp.lock().len(), self.udp.lock().len())
    }

    fn handle_outbound_udp<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: Option<&[u8]>,
    ) -> Result<LibfwConnectionState> {
        let link = Self::build_conn_info(ip, LibfwDirection::LibfwDirectionOutbound)?.0;
        let key = Connection {
            link,
            associated_data: associated_data.map(|data| data.to_smallvec()),
        };

        let Some(pkg_chunk) = ip
            .packet()
            .chunks(UdpConnectionInfo::LAST_PKG_MAX_CHUNK_LEN)
            .next()
        else {
            telio_log_warn!("Failed to extract headers of UDP packet for {key:?}");
            return Err(Error::MalformedUdpPacket);
        };

        let mut udp_cache = self.udp.lock();
        // If key already exists, dont change the value, just update timer with entry
        match udp_cache.entry(key, true) {
            Entry::Vacant(e) => {
                let mut last_chunk = Vec::with_capacity(UdpConnectionInfo::LAST_PKG_MAX_CHUNK_LEN);
                last_chunk.extend_from_slice(pkg_chunk);

                let conninfo = UdpConnectionInfo {
                    is_remote_initiated: false,
                    last_out_pkg_chunk: Some(last_chunk),
                    state: LibfwConnectionState::LibfwConnectionStateNew,
                };
                telio_log_trace!("Inserting new UDP conntrack entry {:?}", e.key());
                e.insert(conninfo);

                Ok(LibfwConnectionState::LibfwConnectionStateNew)
            }
            Entry::Occupied(mut o) => {
                let value = o.get_mut();

                // Take out the old one clear and copy data from new packet in
                // order to avoid allocation
                let mut last_chunk = value.last_out_pkg_chunk.take().unwrap_or_else(|| {
                    Vec::with_capacity(UdpConnectionInfo::LAST_PKG_MAX_CHUNK_LEN)
                });
                last_chunk.clear();
                last_chunk.extend_from_slice(pkg_chunk);

                if value.is_remote_initiated
                    && value.state == LibfwConnectionState::LibfwConnectionStateNew
                {
                    value.state = LibfwConnectionState::LibfwConnectionStateEstablished
                }

                value.last_out_pkg_chunk = Some(last_chunk);

                Ok(value.state)
            }
        }
    }

    fn handle_outbound_tcp<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: Option<&[u8]>,
    ) -> Result<LibfwConnectionState> {
        let (link, packet) = Self::build_conn_info(ip, LibfwDirection::LibfwDirectionOutbound)?;
        let key = Connection {
            link,
            associated_data: associated_data.map(|data| data.to_smallvec()),
        };
        let flags = packet.map(|p| p.get_flags()).unwrap_or(0);
        let mut tcp_cache = self.tcp.lock();

        if flags & TCP_FIRST_PKT_MASK == TcpFlags::SYN {
            telio_log_trace!("Inserting TCP conntrack entry {:?}", key.link);
            tcp_cache.insert(
                key,
                TcpConnectionInfo {
                    tx_alive: true,
                    rx_alive: true,
                    conn_remote_initiated: false,
                    next_seq: None,
                    state: LibfwConnectionState::LibfwConnectionStateNew,
                },
            );
            return Ok(LibfwConnectionState::LibfwConnectionStateNew);
        }

        if flags & TcpFlags::RST == TcpFlags::RST {
            telio_log_trace!("Removing TCP conntrack entry {:?}", key);
            tcp_cache.remove(&key);
            return Ok(LibfwConnectionState::LibfwConnectionStateClosed);
        }

        if flags & TcpFlags::FIN == TcpFlags::FIN {
            // For FIN packets we shouldn't bump the connection timer
            if let Entry::Occupied(mut e) = tcp_cache.entry(key.clone(), false) {
                telio_log_trace!("Connection {:?} closing", key);
                let TcpConnectionInfo {
                    tx_alive,
                    rx_alive,
                    state,
                    ..
                } = e.get_mut();
                *tx_alive = false;
                if !*rx_alive {
                    *state = LibfwConnectionState::LibfwConnectionStateClosed
                }
                return Ok(*state);
            }
        }

        if let Some(tcp_connection_info) = tcp_cache.get_mut(&key) {
            if tcp_connection_info.conn_remote_initiated
                && (flags & TCP_FIRST_PKT_MASK == TCP_FIRST_PKT_MASK)
            {
                tcp_connection_info.state = LibfwConnectionState::LibfwConnectionStateEstablished;
            }
            Ok(tcp_connection_info.state)
        } else {
            Ok(LibfwConnectionState::LibfwConnectionStateNew)
        }
    }

    fn handle_outbound_icmp<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: Option<&[u8]>,
    ) -> Result<LibfwConnectionState> {
        let mut icmp_cache = self.icmp.lock();
        if let IcmpKey::Conn(key) =
            Self::build_icmp_key(ip, associated_data, LibfwDirection::LibfwDirectionOutbound)?
        {
            // If key already exists, dont change the value, just update timer with entry
            if let Entry::Vacant(e) = icmp_cache.entry(key, true) {
                telio_log_trace!("Inserting new ICMP conntrack entry {:?}", e.key());
                e.insert(());
            }
        }

        Ok(LibfwConnectionState::LibfwConnectionStateNew)
    }

    #[allow(dead_code)]
    pub(crate) fn cleanup_udp_conn_on_drop<'a, P: IpPacket<'a>>(
        &self,
        ip: P,
        associated_data: Option<&[u8]>,
    ) -> Result<()> {
        let (link, _) = Self::build_conn_info(&ip, LibfwDirection::LibfwDirectionInbound)?;
        let key = Connection {
            link,
            associated_data: associated_data.map(|data| data.to_smallvec()),
        };

        self.udp.lock().remove(&key);

        Ok(())
    }

    fn handle_inbound_udp<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: Option<&[u8]>,
    ) -> Result<LibfwConnectionState> {
        let (link, _) = Self::build_conn_info(ip, LibfwDirection::LibfwDirectionInbound)?;
        let key = Connection {
            link,
            associated_data: associated_data.map(|data| data.to_smallvec()),
        };

        let mut udp_cache = self.udp.lock();

        match udp_cache.entry(key, true) {
            Entry::Occupied(mut occ) => {
                telio_log_trace!(
                    "Matched UDP conntrack entry {:?} {:?}",
                    occ.key(),
                    occ.get()
                );

                if LibfwConnectionState::LibfwConnectionStateNew == occ.get().state
                    && !occ.get().is_remote_initiated
                {
                    occ.get_mut().state = LibfwConnectionState::LibfwConnectionStateEstablished;
                }
                Ok(occ.get().state)
            }
            Entry::Vacant(vacc) => {
                let key = vacc.key();

                telio_log_trace!(
                    "Updating UDP conntrack entry {:?} {:?}",
                    key,
                    associated_data
                );
                vacc.insert(UdpConnectionInfo {
                    is_remote_initiated: true,
                    last_out_pkg_chunk: None,
                    state: LibfwConnectionState::LibfwConnectionStateNew,
                });
                Ok(LibfwConnectionState::LibfwConnectionStateNew)
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn cleanup_tcp_conn<'a, P: IpPacket<'a>>(
        &self,
        ip: P,
        associated_data: Option<&[u8]>,
        accepted: bool,
    ) -> Result<()> {
        let (link, _) = Self::build_conn_info(&ip, LibfwDirection::LibfwDirectionInbound)?;
        let key = Connection {
            link,
            associated_data: associated_data.map(|data| data.to_smallvec()),
        };

        let mut cache = self.tcp.lock();
        if let Entry::Occupied(mut occ) = cache.entry(key, false) {
            if !accepted && occ.get().conn_remote_initiated {
                occ.remove();
            }
        }

        Ok(())
    }

    // Conntrack entries are ment for packets handled locally - so
    fn handle_inbound_tcp<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: Option<&[u8]>,
    ) -> Result<LibfwConnectionState> {
        let (link, packet) = Self::build_conn_info(ip, LibfwDirection::LibfwDirectionInbound)?;
        let key = Connection {
            link,
            associated_data: associated_data.map(|data| data.to_smallvec()),
        };
        let local_port = key.link.local_port;
        telio_log_trace!("Processing TCP packet with {:?}", key);

        let mut cache = self.tcp.lock();
        // Dont update last access time in tcp, as it is handled by tcp flags
        match cache.entry(key, false) {
            Entry::Occupied(mut occ) => {
                let connection_info = occ.get_mut();
                telio_log_trace!(
                    "Matched conntrack entry {:?} {:?}",
                    associated_data,
                    connection_info
                );

                if let Some(pkt) = packet {
                    let flags = pkt.get_flags();
                    if flags & TcpFlags::RST == TcpFlags::RST {
                        telio_log_trace!(
                            "Removing TCP conntrack entry with {:?} for {:?}",
                            associated_data,
                            local_port
                        );
                        occ.remove();
                        return Ok(LibfwConnectionState::LibfwConnectionStateClosed);
                    }

                    if (flags & TcpFlags::FIN) == TcpFlags::FIN {
                        telio_log_trace!(
                            "Connection with {:?} for {:?} closing",
                            associated_data,
                            local_port
                        );
                        connection_info.rx_alive = false;
                    }

                    if !connection_info.tx_alive && !connection_info.rx_alive {
                        if (flags & TcpFlags::ACK) == TcpFlags::ACK {
                            telio_log_trace!(
                                "Removing TCP conntrack entry with {:?} for {:?}",
                                associated_data,
                                local_port
                            );
                            occ.remove();
                        } else {
                            occ.get_mut().state = LibfwConnectionState::LibfwConnectionStateClosed;
                        }

                        return Ok(LibfwConnectionState::LibfwConnectionStateClosed);
                    }

                    // restarts cache entry timeout
                    let next_seq = if (flags & TcpFlags::SYN) == TcpFlags::SYN {
                        pkt.get_sequence() + 1
                    } else {
                        pkt.get_sequence() + pkt.payload().len() as u32
                    };

                    connection_info.next_seq = Some(next_seq);
                    if !connection_info.conn_remote_initiated
                        && (flags & TCP_FIRST_PKT_MASK == TCP_FIRST_PKT_MASK)
                    {
                        occ.get_mut().state = LibfwConnectionState::LibfwConnectionStateEstablished;
                    }
                }

                Ok(occ.get().state)
            }
            Entry::Vacant(vacc) => {
                // Accept and should handle locally
                if let Some(pkt) = packet {
                    let key = vacc.key();
                    let flags = pkt.get_flags();
                    if flags & TCP_FIRST_PKT_MASK == TcpFlags::SYN {
                        let conn_info = TcpConnectionInfo {
                            tx_alive: true,
                            rx_alive: true,
                            conn_remote_initiated: true,
                            next_seq: Some(pkt.get_sequence() + 1),
                            state: LibfwConnectionState::LibfwConnectionStateNew,
                        };
                        telio_log_trace!(
                            "Updating TCP conntrack entry {:?} {:?} {:?}",
                            key,
                            associated_data,
                            conn_info
                        );
                        vacc.insert(conn_info.clone());
                    }
                }
                Ok(LibfwConnectionState::LibfwConnectionStateNew)
            }
        }
    }

    fn handle_inbound_icmp<'a, P: IpPacket<'a>>(
        &self,
        ip: &P,
        associated_data: Option<&[u8]>,
    ) -> Result<LibfwConnectionState> {
        match Self::build_icmp_key(ip, associated_data, LibfwDirection::LibfwDirectionInbound) {
            Ok(IcmpKey::Conn(key)) => {
                let mut icmp_cache = self.icmp.lock();
                if icmp_cache.get_mut(&key).is_some() {
                    telio_log_trace!("Matched ICMP conntrack entry {:?}", key);
                    telio_log_trace!("Removing ICMP conntrack entry {:?}", key);
                    icmp_cache.remove(&key);
                    Ok(LibfwConnectionState::LibfwConnectionStateEstablished)
                } else {
                    Ok(LibfwConnectionState::LibfwConnectionStateNew)
                }
            }
            Ok(IcmpKey::Err(icmp_error_key)) => {
                telio_log_trace!("Encountered ICMP error packet, checking nested packet");
                Ok(self.handle_inbound_icmp_error(icmp_error_key, associated_data))
            }
            Err(Error::UnexpectedPacketType) => {
                telio_log_trace!("Encountered ICMP packet type not tracked in this direction");
                Ok(LibfwConnectionState::LibfwConnectionStateNew)
            }
            Err(err) => Err(err),
        }
    }

    fn handle_inbound_icmp_error(
        &self,
        error_key: IcmpErrorKey,
        associated_data: Option<&[u8]>,
    ) -> LibfwConnectionState {
        match error_key {
            IcmpErrorKey::Icmp(icmp_key) => {
                let mut icmp_cache = self.icmp.lock();
                if icmp_cache.get(&icmp_key).is_some() {
                    telio_log_trace!("Removing ICMP conntrack entry {:?}", icmp_key);
                    icmp_cache.remove(&icmp_key);
                    return LibfwConnectionState::LibfwConnectionStateEstablished;
                }
            }
            IcmpErrorKey::Tcp(link) => {
                let tcp_key = Connection {
                    link,
                    associated_data: associated_data.map(|data| data.to_smallvec()),
                };

                let mut tcp_cache = self.tcp.lock();

                if tcp_cache.get(&tcp_key).is_some() {
                    telio_log_trace!("Removing TCP conntrack entry {:?}", tcp_key);
                    tcp_cache.remove(&tcp_key);
                    return LibfwConnectionState::LibfwConnectionStateEstablished;
                }
            }
            IcmpErrorKey::Udp(link) => {
                let udp_key = Connection {
                    link,
                    associated_data: associated_data.map(|data| data.to_smallvec()),
                };

                let mut udp_cache = self.udp.lock();
                if udp_cache.get(&udp_key).is_some() {
                    telio_log_trace!("Removing UDP conntrack entry {:?}", udp_key);
                    udp_cache.remove(&udp_key);
                    return LibfwConnectionState::LibfwConnectionStateEstablished;
                }
            }
        }
        LibfwConnectionState::LibfwConnectionStateNew
    }

    pub fn build_conn_info<'a, P: IpPacket<'a>>(
        ip: &P,
        direction: LibfwDirection,
    ) -> Result<(IpConnWithPort, Option<TcpPacket>)> {
        let proto = ip.get_next_level_protocol();
        let (src, dest, tcp_packet) = match proto {
            IpNextHeaderProtocols::Udp => match UdpPacket::new(ip.payload()) {
                Some(packet) => (packet.get_source(), packet.get_destination(), None),
                _ => {
                    telio_log_trace!("Could not create UDP packet from IP packet {:?}", ip);
                    return Err(Error::MalformedUdpPacket);
                }
            },
            IpNextHeaderProtocols::Tcp => match TcpPacket::new(ip.payload()) {
                Some(packet) => (packet.get_source(), packet.get_destination(), Some(packet)),
                _ => {
                    telio_log_trace!("Could not create TCP packet from IP packet {:?}", ip);
                    return Err(Error::MalformedUdpPacket);
                }
            },
            _ => return Err(Error::MalformedUdpPacket),
        };

        let key = if let LibfwDirection::LibfwDirectionInbound = direction {
            IpConnWithPort {
                remote_addr: ip.get_source().into(),
                remote_port: src,
                local_addr: ip.get_destination().into(),
                local_port: dest,
            }
        } else {
            IpConnWithPort {
                remote_addr: ip.get_destination().into(),
                remote_port: dest,
                local_addr: ip.get_source().into(),
                local_port: src,
            }
        };

        match proto {
            IpNextHeaderProtocols::Udp => Ok((key, None)),
            IpNextHeaderProtocols::Tcp => Ok((key, tcp_packet)),
            _ => Err(Error::UnexpectedProtocol),
        }
    }

    fn build_icmp_key<'a, P: IpPacket<'a>>(
        ip: &P,
        associated_data: Option<&[u8]>,
        direction: LibfwDirection,
    ) -> Result<IcmpKey> {
        let icmp_packet = match IcmpPacket::new(ip.payload()) {
            Some(packet) => packet,
            _ => {
                telio_log_trace!("Could not create ICMP packet from IP packet {:?}", ip);
                return Err(Error::MalformedIcmpPacket);
            }
        };
        let response_type = {
            use IcmpTypes as v4;
            use Icmpv6Types as v6;
            let it = icmp_packet.get_icmp_type().0;
            // Request messages get the icmp type of the corresponding reply message
            // Reply messages get their own icmp type, to match that of its corresponding request
            // We only create keys for outbound requests and inbound replies
            if let LibfwDirection::LibfwDirectionInbound = direction {
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
                    return Self::build_icmp_error_key(icmp_packet, associated_data, true);
                } else if (it == v6::DestinationUnreachable.0
                    || it == v6::PacketTooBig.0
                    || it == v6::ParameterProblem.0
                    || it == v6::TimeExceeded.0)
                    && ip.get_next_level_protocol() == IpNextHeaderProtocols::Icmpv6
                {
                    return Self::build_icmp_error_key(icmp_packet, associated_data, false);
                } else {
                    return Err(Error::UnexpectedPacketType);
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
                return Err(Error::UnexpectedPacketType);
            }
        };

        let identifier_sequence = {
            let bytes = icmp_packet
                .payload()
                .get(0..4)
                .and_then(|b| b.try_into().ok());
            let bytes = unwrap_option_or_return!(bytes, Err(Error::MalformedIcmpPacket));
            u32::from_ne_bytes(bytes)
        };
        let (remote_addr, local_addr) = if let LibfwDirection::LibfwDirectionInbound = direction {
            (ip.get_source().into(), ip.get_destination().into())
        } else {
            (ip.get_destination().into(), ip.get_source().into())
        };
        let key = IcmpConn {
            remote_addr,
            local_addr,
            response_type,
            identifier_sequence,
            associated_data: associated_data.map(|data| data.to_smallvec()),
        };

        Ok(IcmpKey::Conn(key))
    }

    fn build_icmp_error_key(
        icmp_packet: IcmpPacket,
        associated_data: Option<&[u8]>,
        is_v4: bool,
    ) -> Result<IcmpKey> {
        let inner_packet = match icmp_packet.payload().get(4..) {
            Some(bytes) => bytes,
            None => {
                telio_log_trace!("ICMP error body does not contain a nested packet");
                return Err(Error::MalformedIcmpPacket);
            }
        };
        Ok(IcmpKey::Err(if is_v4 {
            let packet = match <Ipv4Packet<'_> as IpPacket>::try_from(inner_packet) {
                Some(packet) => packet,
                _ => {
                    telio_log_trace!("ICMP error contains invalid IPv4 packet");
                    return Err(Error::InvalidIcmpErrorPayload);
                }
            };
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => IcmpErrorKey::Udp(
                    Self::build_conn_info(&packet, LibfwDirection::LibfwDirectionOutbound)?.0,
                ),
                IpNextHeaderProtocols::Tcp => IcmpErrorKey::Tcp(
                    Self::build_conn_info(&packet, LibfwDirection::LibfwDirectionOutbound)?.0,
                ),
                IpNextHeaderProtocols::Icmp => {
                    if let IcmpKey::Conn(conn) = Self::build_icmp_key(
                        &packet,
                        associated_data,
                        LibfwDirection::LibfwDirectionOutbound,
                    )? {
                        IcmpErrorKey::Icmp(Box::new(conn))
                    } else {
                        return Err(Error::MalformedIcmpPacket);
                    }
                }
                _ => {
                    return Err(Error::UnexpectedProtocol);
                }
            }
        } else {
            let packet = match <Ipv6Packet<'_> as IpPacket>::try_from(inner_packet) {
                Some(packet) => packet,
                _ => {
                    telio_log_trace!("ICMP error contains invalid IPv6 packet");
                    return Err(Error::InvalidIcmpErrorPayload);
                }
            };
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => IcmpErrorKey::Udp(
                    Self::build_conn_info(&packet, LibfwDirection::LibfwDirectionOutbound)?.0,
                ),
                IpNextHeaderProtocols::Tcp => IcmpErrorKey::Tcp(
                    Self::build_conn_info(&packet, LibfwDirection::LibfwDirectionOutbound)?.0,
                ),
                IpNextHeaderProtocols::Icmpv6 => {
                    if let IcmpKey::Conn(conn) = Self::build_icmp_key(
                        &packet,
                        associated_data,
                        LibfwDirection::LibfwDirectionOutbound,
                    )? {
                        IcmpErrorKey::Icmp(Box::new(conn))
                    } else {
                        return Err(Error::MalformedIcmpPacket);
                    }
                }
                _ => {
                    return Err(Error::UnexpectedProtocol);
                }
            }
        }))
    }

    pub(crate) fn reset_tcp_conns<F>(
        &self,
        associated_data: Option<&[u8]>,
        inject_packet_cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        let mut tcp_conn_cache = self.tcp.lock();

        telio_log_debug!(
            "Inspecting {} TCP connections for reset",
            tcp_conn_cache.len()
        );

        let iter = tcp_conn_cache.iter().filter_map(|(k, v)| {
            match (&k.associated_data, associated_data) {
                (Some(conn_assoc_data), Some(assoc_data)) if &**conn_assoc_data == assoc_data => {
                    // When we don't have the sequence number that means the
                    // connection is half open and we don't have a response
                    // from the remote peer yet. We need to skip this kind of
                    // connections
                    v.next_seq.map(|next_seq| (&k.link, next_seq, None))
                }
                (None, None) => v.next_seq.map(|next_seq| (&k.link, next_seq, None)),
                _ => None,
            }
        });

        self.send_tcp_rst_packets(iter, inject_packet_cb)
    }

    pub(crate) fn send_tcp_rst_packets<'a, I, F>(
        &self,
        connections: I,
        mut inject_packet_cb: F,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = (&'a IpConnWithPort, u32, Option<u32>)>,
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        const IPV4_LEN: usize = 20;
        const IPV6_LEN: usize = 40;
        const TCP_LEN: usize = 20;

        let mut ipv4buf = [0u8; IPV4_LEN];
        let mut ipv6buf = [0u8; IPV6_LEN];
        let mut tcpbuf = [0u8; TCP_LEN];

        // Write most of the fields for TCP and IP packets upfront
        #[allow(clippy::expect_used)]
        let mut tcppkg =
            MutableTcpPacket::new(&mut tcpbuf).expect("TCP buffer should not be too small");
        tcppkg.set_data_offset(5);

        #[allow(clippy::expect_used)]
        let mut ipv4pkg =
            MutableIpv4Packet::new(&mut ipv4buf).expect("IPv4 buffer should not be too small");
        ipv4pkg.set_version(4);
        ipv4pkg.set_header_length(5);
        ipv4pkg.set_total_length((IPV4_LEN + TCP_LEN) as _);
        ipv4pkg.set_flags(Ipv4Flags::DontFragment);
        ipv4pkg.set_ttl(0xFF);
        ipv4pkg.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        #[allow(clippy::expect_used)]
        let mut ipv6pkg =
            MutableIpv6Packet::new(&mut ipv6buf).expect("IPv4 buffer should not be too small");
        ipv6pkg.set_version(6);
        ipv6pkg.set_payload_length(TCP_LEN as _);
        ipv6pkg.set_next_header(IpNextHeaderProtocols::Tcp);
        ipv6pkg.set_hop_limit(0xff);

        let mut ipv4pkgbuf = [0u8; IPV4_LEN + TCP_LEN];
        let mut ipv6pkgbuf = [0u8; IPV6_LEN + TCP_LEN];

        for (key, next_seq, ack) in connections {
            tcppkg.set_source(key.remote_port);
            tcppkg.set_destination(key.local_port);
            tcppkg.set_sequence(next_seq);
            if let Some(ack) = ack {
                tcppkg.set_flags(TcpFlags::RST | TcpFlags::ACK);
                tcppkg.set_acknowledgement(ack);
            } else {
                tcppkg.set_flags(TcpFlags::RST);
            }

            match (key.local_addr, key.remote_addr) {
                (IpAddr::Ipv4(local_addr), IpAddr::Ipv4(remote_addr)) => {
                    let src = remote_addr.into();
                    let dst = local_addr.into();

                    ipv4pkg.set_source(src);
                    ipv4pkg.set_destination(dst);

                    tcppkg.set_checksum(pnet_packet::tcp::ipv4_checksum(
                        &tcppkg.to_immutable(),
                        &src,
                        &dst,
                    ));

                    ipv4pkg.set_checksum(0);
                    ipv4pkg.set_checksum(pnet_packet::ipv4::checksum(&ipv4pkg.to_immutable()));

                    telio_log_debug!("Injecting IPv4 TCP RST packet {key:#?}");

                    #[allow(index_access_check)]
                    ipv4pkgbuf[..IPV4_LEN].copy_from_slice(ipv4pkg.packet());

                    #[allow(index_access_check)]
                    ipv4pkgbuf[IPV4_LEN..].copy_from_slice(tcppkg.packet());

                    inject_packet_cb(&ipv4pkgbuf)?;
                }
                (IpAddr::Ipv6(local_addr), IpAddr::Ipv6(remote_addr)) => {
                    let src = remote_addr.into();
                    let dst = local_addr.into();

                    ipv6pkg.set_source(src);
                    ipv6pkg.set_destination(dst);

                    tcppkg.set_checksum(pnet_packet::tcp::ipv6_checksum(
                        &tcppkg.to_immutable(),
                        &src,
                        &dst,
                    ));

                    telio_log_debug!("Injecting IPv4 TCP RST packet {key:#?}");

                    #[allow(index_access_check)]
                    ipv6pkgbuf[..IPV6_LEN].copy_from_slice(ipv6pkg.packet());

                    #[allow(index_access_check)]
                    ipv6pkgbuf[IPV6_LEN..].copy_from_slice(tcppkg.packet());
                    inject_packet_cb(&ipv6pkgbuf)?;
                }
                _ => telio_log_warn!(
                    "Local and remote IP addrs version missmatch, this should never happen"
                ),
            }
        }

        Ok(())
    }

    pub(crate) fn send_icmp_port_unreachable_packets<'a, I, F>(
        &self,
        connections: I,
        mut inject_packet_cb: F,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = (&'a IpConnWithPort, &'a [u8])>,
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        const IPV4_HEADER_LEN: usize = 20;
        const IPV6_HEADER_LEN: usize = 40;
        const ICMP_HEADER_LEN: usize = 8;
        const ICMP_MAX_DATA_LEN: usize = UdpConnectionInfo::LAST_PKG_MAX_CHUNK_LEN;

        let mut ipv4pkgbuf = [0u8; IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_MAX_DATA_LEN];
        let mut ipv6pkgbuf = [0u8; IPV6_HEADER_LEN + ICMP_HEADER_LEN + ICMP_MAX_DATA_LEN];

        // Write most of the fields for ICMP and IP packets upfront
        #[allow(clippy::expect_used)]
        #[allow(index_access_check)]
        let mut ipv4pkg = MutableIpv4Packet::new(&mut ipv4pkgbuf[..IPV4_HEADER_LEN])
            .expect("IPv4 buffer should not be too small");
        ipv4pkg.set_version(4);
        ipv4pkg.set_header_length(5);
        ipv4pkg.set_flags(Ipv4Flags::DontFragment);
        ipv4pkg.set_ttl(0xFF);
        ipv4pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

        #[allow(clippy::expect_used)]
        #[allow(index_access_check)]
        let mut ipv6pkg = MutableIpv6Packet::new(&mut ipv6pkgbuf[..IPV6_HEADER_LEN])
            .expect("IPv6 buffer should not be too small");
        ipv6pkg.set_version(6);
        ipv6pkg.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6pkg.set_hop_limit(0xff);

        #[allow(clippy::expect_used)]
        #[allow(index_access_check)]
        let mut icmppkg = MutableIcmpPacket::new(
            &mut ipv4pkgbuf[IPV4_HEADER_LEN..(IPV4_HEADER_LEN + ICMP_HEADER_LEN)],
        )
        .expect("ICMP buffer should not be too small");
        icmppkg.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmppkg.set_icmp_code(IcmpCodes::DestinationPortUnreachable);

        #[allow(clippy::expect_used)]
        #[allow(index_access_check)]
        let mut icmpv6pkg = MutableIcmpv6Packet::new(
            &mut ipv6pkgbuf[IPV6_HEADER_LEN..(IPV6_HEADER_LEN + ICMP_HEADER_LEN)],
        )
        .expect("ICMP buffer should not be too small");
        icmpv6pkg.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        let icmpv6_port_unreachable = 4;
        icmpv6pkg.set_icmpv6_code(Icmpv6Code::new(icmpv6_port_unreachable));

        for (key, last_headers) in connections {
            match (key.local_addr, key.remote_addr) {
                (IpAddr::Ipv4(local_addr), IpAddr::Ipv4(remote_addr)) => {
                    let end = IPV4_HEADER_LEN + ICMP_HEADER_LEN + last_headers.len();

                    #[allow(index_access_check)]
                    let ipv4pkgbuf = &mut ipv4pkgbuf[..end];
                    #[allow(index_access_check)]
                    ipv4pkgbuf[(IPV4_HEADER_LEN + ICMP_HEADER_LEN)..].copy_from_slice(last_headers);

                    let src = remote_addr.into();
                    let dst = local_addr.into();

                    #[allow(clippy::expect_used)]
                    #[allow(index_access_check)]
                    let mut icmppkg = MutableIcmpPacket::new(&mut ipv4pkgbuf[IPV4_HEADER_LEN..])
                        .expect("ICMP buffer should not be too small");
                    icmppkg.set_checksum(0);
                    icmppkg.set_checksum(pnet_packet::icmp::checksum(&icmppkg.to_immutable()));
                    drop(icmppkg);

                    #[allow(clippy::expect_used)]
                    #[allow(index_access_check)]
                    let mut ipv4pkg = MutableIpv4Packet::new(&mut ipv4pkgbuf[..IPV4_HEADER_LEN])
                        .expect("IPv4 buffer should not be too small");
                    ipv4pkg.set_source(src);
                    ipv4pkg.set_destination(dst);
                    ipv4pkg.set_total_length(
                        (IPV4_HEADER_LEN + ICMP_HEADER_LEN + last_headers.len()) as _,
                    );

                    ipv4pkg.set_checksum(0);
                    ipv4pkg.set_checksum(pnet_packet::ipv4::checksum(&ipv4pkg.to_immutable()));

                    telio_log_debug!("Injecting IPv4 ICMP (for UDP) packet {key:#?}");
                    inject_packet_cb(ipv4pkgbuf)?;
                }
                (IpAddr::Ipv6(local_addr), IpAddr::Ipv6(remote_addr)) => {
                    let end = IPV6_HEADER_LEN + ICMP_HEADER_LEN + last_headers.len();

                    #[allow(index_access_check)]
                    let ipv6pkgbuf = &mut ipv6pkgbuf[..end];
                    #[allow(index_access_check)]
                    ipv6pkgbuf[(IPV6_HEADER_LEN + ICMP_HEADER_LEN)..].copy_from_slice(last_headers);

                    let src = remote_addr.into();
                    let dst = local_addr.into();

                    #[allow(clippy::expect_used)]
                    #[allow(index_access_check)]
                    let mut icmpv6pkg =
                        MutableIcmpv6Packet::new(&mut ipv6pkgbuf[IPV6_HEADER_LEN..])
                            .expect("ICMPv6 buffer should not be too small");
                    icmpv6pkg.set_checksum(0);
                    icmpv6pkg.set_checksum(pnet_packet::icmpv6::checksum(
                        &icmpv6pkg.to_immutable(),
                        &src,
                        &dst,
                    ));

                    #[allow(clippy::expect_used)]
                    #[allow(index_access_check)]
                    let mut ipv6pkg = MutableIpv6Packet::new(&mut ipv6pkgbuf[..IPV6_HEADER_LEN])
                        .expect("IPv4 buffer should not be too small");
                    ipv6pkg.set_source(src);
                    ipv6pkg.set_destination(dst);
                    ipv6pkg.set_payload_length((ICMP_HEADER_LEN + last_headers.len()) as _);

                    telio_log_debug!("Injecting IPv6 ICMP (for UDP) packet {key:#?}");
                    inject_packet_cb(ipv6pkgbuf)?;
                }
                _ => telio_log_warn!(
                    "Local and remote IP addrs version mismatch, this should never happen"
                ),
            }
        }

        Ok(())
    }

    pub(crate) fn reset_udp_conns<F>(
        &self,
        associated_data: Option<&[u8]>,
        inject_packet_cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        let mut udp_conn_cache = self.udp.lock();

        telio_log_debug!(
            "Inspecting {} UDP connections for reset",
            udp_conn_cache.len()
        );

        let iter = udp_conn_cache.iter().filter_map(|(k, v)| {
            // Skip connection without outbounded packages
            let last_headers = v.last_out_pkg_chunk.as_deref()?;

            match (&k.associated_data, associated_data) {
                (Some(conn_assoc_data), Some(assoc_data)) if &**conn_assoc_data == assoc_data => {
                    Some((&k.link, last_headers))
                }
                (None, None) => Some((&k.link, last_headers)),
                _ => None,
            }
        });

        self.send_icmp_port_unreachable_packets(iter, inject_packet_cb)
    }

    pub(crate) fn track_inbound_ip_packet<'a, P: IpPacket<'a>>(
        &self,
        associated_data: Option<&[u8]>,
        buffer: &'a [u8],
    ) -> Result<LibfwConnectionState> {
        let ip = unwrap_option_or_return!(P::try_from(buffer), Err(Error::MalformedIpPacket));
        let proto = ip.get_next_level_protocol();

        // Initially, we want to track the state of all of the connections
        match proto {
            IpNextHeaderProtocols::Udp => self.handle_inbound_udp(&ip, associated_data),
            IpNextHeaderProtocols::Tcp => self.handle_inbound_tcp(&ip, associated_data),
            IpNextHeaderProtocols::Icmp => self.handle_inbound_icmp(&ip, associated_data),
            IpNextHeaderProtocols::Icmpv6 => self.handle_inbound_icmp(&ip, associated_data),
            _ => Err(Error::UnexpectedProtocol),
        }
    }

    pub(crate) fn track_outbound_ip_packet<'a, P: IpPacket<'a>>(
        &self,
        associated_data: Option<&[u8]>,
        buffer: &'a [u8],
    ) -> Result<LibfwConnectionState> {
        let ip = unwrap_option_or_return!(P::try_from(buffer), Err(Error::MalformedIpPacket));
        let proto = ip.get_next_level_protocol();

        // Initially, we want to track the state of all of the connections
        match proto {
            IpNextHeaderProtocols::Udp => self.handle_outbound_udp(&ip, associated_data),
            IpNextHeaderProtocols::Tcp => self.handle_outbound_tcp(&ip, associated_data),
            IpNextHeaderProtocols::Icmp => self.handle_outbound_icmp(&ip, associated_data),
            IpNextHeaderProtocols::Icmpv6 => self.handle_outbound_icmp(&ip, associated_data),
            _ => Err(Error::UnexpectedProtocol),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::TryInto,
        io::{self, Write},
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
        time::Duration,
    };

    use pnet_packet::{
        icmp::{
            destination_unreachable::{self, DestinationUnreachablePacket},
            IcmpPacket, IcmpType, IcmpTypes, MutableIcmpPacket,
        },
        icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Type, Icmpv6Types},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
        udp::MutableUdpPacket,
        MutablePacket, Packet,
    };

    use crate::{
        conntrack::{Conntrack, Error, LibfwConnectionState},
        firewall::IpPacket,
    };

    const LRU_CACHE_SIZE: usize = 128;
    const LRU_CACHE_TTL: u64 = 128;

    const IPV4_HEADER_MIN: usize = 20; // IPv4 header minimal length in bytes
    const IPV6_HEADER_MIN: usize = 40; // IPv6 header minimal length in bytes
    const TCP_HEADER_MIN: usize = 20; // TCP header minimal length in bytes
    const UDP_HEADER: usize = 8; // UDP header length in bytes
    const ICMP_HEADER: usize = 8; // ICMP header length in bytes

    /// File sending port
    pub const FILE_SEND_PORT: u16 = 49111;

    fn advance_time(time: Duration) {
        sn_fake_clock::FakeClock::advance_time(time.as_millis() as u64);
    }

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

    pub fn make_tcp(src: &str, dst: &str, flags: u8) -> Vec<u8> {
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

    pub fn make_tcp6(src: &str, dst: &str, flags: u8) -> Vec<u8> {
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

    #[allow(dead_code)]
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

        #[allow(dead_code)]
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

    #[test]
    fn conntrack_establishing_outbound_udp_connection() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let src = "127.0.0.1:1111";
        let dst = "8.8.8.8:8888";

        let outbound_udp_packet = make_udp(src, dst);
        let inbound_udp_packet = make_udp(dst, src);

        // Initiate the connection
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Another outbound packet
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Inbound packet should change conn state to established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );
    }

    #[test]
    fn conntrack_establishing_inbound_udp_connection() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let src = "127.0.0.1:1111";
        let dst = "8.8.8.8:8888";

        let outbound_udp_packet = make_udp(src, dst);
        let inbound_udp_packet = make_udp(dst, src);

        // Initiate the connection
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Another outbound packet
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Inbound packet should change conn state to established
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );
    }

    #[test]
    fn conntrack_establishing_outbound_tcp_connection() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let src = "127.0.0.1:1111";
        let dst = "8.8.8.8:8888";

        let outbound_syn_packet = make_tcp(src, dst, TcpFlags::SYN);
        let outbound_syn_ack_packet = make_tcp(src, dst, TcpFlags::SYN | TcpFlags::ACK);
        let inbound_syn_ack_packet = make_tcp(dst, src, TcpFlags::SYN | TcpFlags::ACK);
        let inbound_fin_packet = make_tcp(dst, src, TcpFlags::FIN);
        let outbound_fin_packet = make_tcp(src, dst, TcpFlags::FIN);

        // Initiate the connection
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_syn_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Second oubound SYN packet shouldn't change conn state to established
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_syn_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Outbound SYN-ACK packet shouldn't change the state to established
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_syn_ack_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Inbound packet should change conn state to established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_syn_ack_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // First FIN packet should still get state Established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_fin_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // Second FIN from the same direction should also get Established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_fin_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // Inbound FIN should change connection state to closed
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_fin_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateClosed);
    }

    #[test]
    fn conntrack_establishing_inbound_tcp_connection() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let src = "127.0.0.1:1111";
        let dst = "8.8.8.8:8888";

        let inbound_syn_packet = make_tcp(dst, src, TcpFlags::SYN);
        let inbound_syn_ack_packet = make_tcp(dst, src, TcpFlags::SYN | TcpFlags::ACK);
        let outbound_syn_ack_packet = make_tcp(src, dst, TcpFlags::SYN | TcpFlags::ACK);
        let outbound_fin_packet = make_tcp(src, dst, TcpFlags::FIN);
        let inbound_fin_packet = make_tcp(dst, src, TcpFlags::FIN);

        // Initiate the connection
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_syn_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Second inbound SYN packet shouldn't change conn state to established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_syn_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Inbound SYN-ACK packet shouldn't change the state to established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_syn_ack_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Outbound packet should change conn state to established
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_syn_ack_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // First FIN packet should still get state Established
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_fin_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // Second FIN from the same direction should also get Established
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_fin_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // Inbound FIN should change connection state to closed
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_fin_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateClosed);
    }

    #[test]
    fn conntrack_establishing_outbound_icmp_connection() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let src = "127.0.0.1";
        let dst = "8.8.8.8";

        let outbound_icmp_req_packet =
            make_icmp4(src, dst, GenericIcmpType::V4(IcmpTypes::EchoRequest));
        let inbound_icmp_reply_packet =
            make_icmp4(dst, src, GenericIcmpType::V4(IcmpTypes::EchoReply));
        let inbound_icmp_req_packet =
            make_icmp4(dst, src, GenericIcmpType::V4(IcmpTypes::EchoRequest));

        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_icmp_req_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Inbound request packet is just ignored - not considered to be a part of the outgoing connection
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &inbound_icmp_req_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // It should be established for the first reply
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_icmp_reply_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // After the first reply is processed, the ICMP connection entry is removed
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_icmp_reply_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);
    }

    #[test]
    fn conntrack_ignoring_inbound_icmp_connection() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let src = "127.0.0.1";
        let dst = "8.8.8.8";

        let inbound_icmp_req_packet =
            make_icmp4(dst, src, GenericIcmpType::V4(IcmpTypes::EchoRequest));
        let outbound_icmp_resp_packet =
            make_icmp4(src, dst, GenericIcmpType::V4(IcmpTypes::EchoReply));

        // Inbound request should not create a conntrack entry
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_icmp_req_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // So the connection for outbound response should be still new
        let error = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_icmp_resp_packet)
            .expect_err("Currently outgoing ICMP replies are considered unexpected");
        assert_eq!(error, Error::UnexpectedPacketType);
    }

    #[test]
    fn removing_udp_entry_on_matching_icmp_error() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let udp_src = "127.0.0.1:1111";
        let udp_dst = "8.8.8.8:8888";

        let icmp_src = "127.0.0.1";
        let icmp_dst = "8.8.8.8";

        let outbound_udp_packet = make_udp(udp_dst, udp_src);
        let inbound_udp_packet = make_udp(udp_src, udp_dst);

        let mut data = vec![1, 0, 0, 1];
        data.extend_from_slice(&outbound_udp_packet);
        let inbound_icmp_resp_packet = make_icmp4_with_body(
            icmp_src,
            icmp_dst,
            IcmpTypes::DestinationUnreachable.into(),
            &data,
        );

        // Initiate the outbound connection
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // First inbound packet should make it established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // ICMP error message should also be treated as a part of established connection
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_icmp_resp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // But after ICMP error message the connection should be removed
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_udp_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);
    }

    #[test]
    fn removing_tcp_entry_on_rst() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let src = "127.0.0.1:1111";
        let dst = "8.8.8.8:8888";

        let outbound_syn_packet = make_tcp(src, dst, TcpFlags::SYN);
        let inbound_syn_ack_packet = make_tcp(dst, src, TcpFlags::SYN | TcpFlags::ACK);

        let inbound_rst_packet = make_tcp(dst, src, TcpFlags::RST);

        // Just normal connection establishment
        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &outbound_syn_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_syn_ack_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // Inbound RST packet - connection should be closed immediately
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_rst_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateClosed);

        // After that conntrack entry should be removed
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &inbound_syn_ack_packet)
            .expect("Unexpected conntrack error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);
    }

    #[test]
    fn firewall_tcp_conns_reset() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        // Outbound half opened connection
        assert_eq!(
            conntrack
                .track_outbound_ip_packet::<Ipv4Packet>(
                    None,
                    &make_tcp("127.0.0.1:12345", "104.104.104.104:54321", TcpFlags::SYN),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateNew
        );
        // Outbound opened connection
        assert_eq!(
            conntrack
                .track_outbound_ip_packet::<Ipv4Packet>(
                    None,
                    &make_tcp("127.0.0.1:12345", "103.103.103.103:54321", TcpFlags::SYN),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateNew
        );
        assert_eq!(
            conntrack
                .track_inbound_ip_packet::<Ipv4Packet>(
                    None,
                    &make_tcp(
                        "103.103.103.103:54321",
                        "127.0.0.1:12345",
                        TcpFlags::SYN | TcpFlags::ACK
                    ),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateEstablished
        );
        // Inbound connection
        assert_eq!(
            conntrack
                .track_inbound_ip_packet::<Ipv4Packet>(
                    None,
                    &make_tcp(
                        "100.100.100.100:12345",
                        &format!("127.0.0.1:{FILE_SEND_PORT}"),
                        TcpFlags::SYN
                    ),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateNew
        );
        // Inbound with data
        assert_eq!(
            conntrack
                .track_inbound_ip_packet::<Ipv4Packet>(
                    None,
                    &make_tcp(
                        "102.102.102.102:12345",
                        &format!("127.0.0.1:{FILE_SEND_PORT}"),
                        TcpFlags::SYN
                    ),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateNew
        );
        assert_eq!(
            conntrack
                .track_inbound_ip_packet::<Ipv4Packet>(
                    None,
                    &make_tcp(
                        "102.102.102.102:12345",
                        &format!("127.0.0.1:{FILE_SEND_PORT}"),
                        TcpFlags::PSH
                    ),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateNew
        );

        // Outbound IPv6 opened connection
        assert_eq!(
            conntrack
                .track_outbound_ip_packet::<Ipv6Packet>(
                    None,
                    &make_tcp6("[::1]:12345", "[1234::2]:54321", TcpFlags::SYN),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateNew
        );
        assert_eq!(
            conntrack
                .track_inbound_ip_packet::<Ipv6Packet>(
                    None,
                    &make_tcp6(
                        "[1234::2]:54321",
                        "[::1]:12345",
                        TcpFlags::SYN | TcpFlags::ACK
                    ),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateEstablished
        );
        // Inbound IPv6 connection
        assert_eq!(
            conntrack
                .track_inbound_ip_packet::<Ipv6Packet>(
                    None,
                    &make_tcp6(
                        "[4321::2]:54321",
                        &format!("[::1]:{FILE_SEND_PORT}"),
                        TcpFlags::SYN
                    ),
                )
                .expect("Unexpected error during packet tracking"),
            LibfwConnectionState::LibfwConnectionStateNew
        );

        #[derive(Default)]
        struct Sink {
            pkgs: Vec<Vec<u8>>,
        }

        impl io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.pkgs.push(buf.to_vec());
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut sink = Sink::default();
        conntrack
            .reset_tcp_conns(None, |packet| {
                sink.write(packet).expect("Error on writing into sink");
                Ok(())
            })
            .expect("Unexpected error on resetting TCP connections");

        // Connections are stored in LinkedHashMap which keeps insertion order
        assert_eq!(sink.pkgs.len(), 5);

        let ippkgs: Vec<_> = sink
            .pkgs
            .iter()
            .take(3)
            .map(|buf| Ipv4Packet::new(&buf).unwrap())
            .collect();

        let tcppkgs: Vec<_> = ippkgs
            .iter()
            .map(|ip| TcpPacket::new(ip.payload()).unwrap())
            .collect();

        // Check common conditions
        for ip in &ippkgs {
            assert_eq!(ip.get_version(), 4);
            assert_eq!(ip.get_header_length(), 5);
            assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        }

        for tcp in &tcppkgs {
            assert_eq!(tcp.get_flags(), TcpFlags::RST);
            assert_eq!(tcp.get_data_offset(), 5);
        }

        // Check specifics
        assert_eq!(ippkgs[0].get_source(), Ipv4Addr::new(103, 103, 103, 103));
        assert_eq!(ippkgs[0].get_destination(), Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(tcppkgs[0].get_source(), 54321);
        assert_eq!(tcppkgs[0].get_destination(), 12345);
        assert_eq!(tcppkgs[0].get_sequence(), 1);

        assert_eq!(ippkgs[1].get_source(), Ipv4Addr::new(100, 100, 100, 100));
        assert_eq!(ippkgs[1].get_destination(), Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(tcppkgs[1].get_source(), 12345);
        assert_eq!(tcppkgs[1].get_destination(), FILE_SEND_PORT);
        assert_eq!(tcppkgs[1].get_sequence(), 1);

        assert_eq!(ippkgs[2].get_source(), Ipv4Addr::new(102, 102, 102, 102));
        assert_eq!(ippkgs[2].get_destination(), Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(tcppkgs[2].get_source(), 12345);
        assert_eq!(tcppkgs[2].get_destination(), FILE_SEND_PORT);
        assert_eq!(tcppkgs[2].get_sequence(), 12);

        let ip6pkgs: Vec<_> = sink
            .pkgs
            .iter()
            .skip(3)
            .take(2)
            .map(|buf| Ipv6Packet::new(&buf).unwrap())
            .collect();

        let tcp6pkgs: Vec<_> = ip6pkgs
            .iter()
            .map(|ip| TcpPacket::new(ip.payload()).unwrap())
            .collect();

        // Check common conditions
        for ip in &ip6pkgs {
            assert_eq!(ip.get_version(), 6);
            assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        }

        for tcp in &tcp6pkgs {
            assert_eq!(tcp.get_flags(), TcpFlags::RST);
            assert_eq!(tcp.get_data_offset(), 5);
        }

        // Check specifics
        assert_eq!(
            ip6pkgs[0].get_source(),
            "1234::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ip6pkgs[0].get_destination(), Ipv6Addr::LOCALHOST);

        assert_eq!(tcp6pkgs[0].get_source(), 54321);
        assert_eq!(tcp6pkgs[0].get_destination(), 12345);
        assert_eq!(tcp6pkgs[0].get_sequence(), 1);

        assert_eq!(
            ip6pkgs[1].get_source(),
            "4321::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ip6pkgs[1].get_destination(), Ipv6Addr::LOCALHOST);

        assert_eq!(tcp6pkgs[1].get_source(), 54321);
        assert_eq!(tcp6pkgs[1].get_destination(), FILE_SEND_PORT);
        assert_eq!(tcp6pkgs[1].get_sequence(), 1);
    }

    #[test]
    fn firewall_udp_conns_reset() {
        let conntrack = Conntrack::new(LRU_CACHE_SIZE, LRU_CACHE_TTL);

        let test_udppkg = make_udp("127.0.0.2:12345", "127.0.0.3:54321");
        let test_udp6pkg = make_udp6("[::2]:12345", "[::3]:54321");

        // Outbound connections
        assert_eq!(
            conntrack
                .track_outbound_ip_packet::<Ipv4Packet>(None, &test_udppkg,)
                .expect("Conntrack tracking error"),
            LibfwConnectionState::LibfwConnectionStateNew
        );
        assert_eq!(
            conntrack
                .track_outbound_ip_packet::<Ipv6Packet>(None, &test_udp6pkg,)
                .expect("Conntrack tracking error"),
            LibfwConnectionState::LibfwConnectionStateNew
        );

        #[derive(Default)]
        struct Sink {
            pkgs: Vec<Vec<u8>>,
        }

        impl io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.pkgs.push(buf.to_vec());
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut sink = Sink::default();
        conntrack
            .reset_udp_conns(None, |packet| {
                sink.write(packet).expect("Error on sink write!");
                Ok(())
            })
            .expect("Unexpected Conntrack error on resetting UDP conns");

        // Connections are stored in LinkedHashMap which keeps insertion order
        assert_eq!(sink.pkgs.len(), 2);

        let ip = Ipv4Packet::new(&sink.pkgs[0]).unwrap();
        assert_eq!(ip.get_version(), 4);
        assert_eq!(ip.get_header_length(), 5);
        assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Icmp);
        assert_eq!(ip.get_source(), Ipv4Addr::new(127, 0, 0, 3));
        assert_eq!(ip.get_destination(), Ipv4Addr::new(127, 0, 0, 2));

        let icmp = IcmpPacket::new(ip.payload()).unwrap();
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::DestinationUnreachable);
        assert_eq!(
            icmp.get_icmp_code(),
            destination_unreachable::IcmpCodes::DestinationPortUnreachable
        );
        let icmp = DestinationUnreachablePacket::new(ip.payload()).unwrap();
        assert_eq!(icmp.payload(), &test_udppkg);

        let ip6 = Ipv6Packet::new(&sink.pkgs[1]).unwrap();
        assert_eq!(ip6.get_version(), 6);
        assert_eq!(ip6.get_next_level_protocol(), IpNextHeaderProtocols::Icmpv6);
        assert_eq!(ip6.get_source(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 3));
        assert_eq!(ip6.get_destination(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));

        let icmp6 = Icmpv6Packet::new(ip6.payload()).unwrap();
        assert_eq!(icmp6.get_icmpv6_type(), Icmpv6Types::DestinationUnreachable);
        assert_eq!(icmp6.get_icmpv6_code(), Icmpv6Code::new(4)); // DestinationPortUnreachable
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_pinhole_timeout() {
            let conntrack = Conntrack::new(3, 100);

        let src = "127.0.0.1:1111";
        let dst = "8.8.8.8:8888";

            assert_eq!(conntrack.track_outbound_ip_packet::<Ipv4Packet>(None, &make_udp(src, dst)).expect("Conntrack tracking error"), LibfwConnectionState::LibfwConnectionStateNew);
            assert_eq!(conntrack.track_inbound_ip_packet::<Ipv4Packet>(None, &make_udp(dst, src)).expect("Conntrack tracking error"), LibfwConnectionState::LibfwConnectionStateEstablished);
            advance_time(Duration::from_millis(200));
            assert_eq!(conntrack.track_inbound_ip_packet::<Ipv4Packet>(None, &make_udp(dst, src)).expect("Conntrack tracking error"), LibfwConnectionState::LibfwConnectionStateNew);
    }

    #[test]
    fn firewall_pinhole_timeout_extending() {
        let capacity = 3;
        let ttl = 20;

        let conntrack = Conntrack::new(capacity, ttl);

        let src = "127.0.0.1:1111";
        let dst = "8.8.8.8:8888";

        let conn_state = conntrack
            .track_outbound_ip_packet::<Ipv4Packet>(None, &make_udp(src, dst))
            .expect("Conntrack tracking error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);

        // Connection should move to established
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &make_udp(dst, src))
            .expect("Conntrack tracking error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // And flowing packets ...
        advance_time(Duration::from_millis(15));
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &make_udp(dst, src))
            .expect("Conntrack tracking error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // ... should keep it in established state
        advance_time(Duration::from_millis(15));
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &make_udp(dst, src))
            .expect("Conntrack tracking error");
        assert_eq!(
            conn_state,
            LibfwConnectionState::LibfwConnectionStateEstablished
        );

        // After exceeding LRU TTL the connection entry should be removed
        advance_time(Duration::from_millis(30));
        let conn_state = conntrack
            .track_inbound_ip_packet::<Ipv4Packet>(None, &make_udp(dst, src))
            .expect("Conntrack tracking error");
        assert_eq!(conn_state, LibfwConnectionState::LibfwConnectionStateNew);
    }
}
