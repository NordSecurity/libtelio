use std::{
    convert::TryInto,
    fmt::{Debug, Formatter},
    io,
    net::IpAddr as StdIpAddr,
    time::Duration,
};

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
use telio_utils::{Entry, LruCache};

use crate::{
    ffi::{
        LibfwLogLevel::{LibfwLogLevelDebug, LibfwLogLevelTrace, LibfwLogLevelWarn},
        Logger,
    },
    firewall::{IpAddr, IpPacket, TCP_FIRST_PKT_MASK},
};

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

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct Connection {
    pub(crate) link: IpConnWithPort,
    // Data associated with the packets, usually the public keys refering
    // to source peer for inbound connections and destination peer for outbound
    // connections, which may be used for tracking and filtering packets
    pub(crate) associated_data: SmallVec<[u8; telio_crypto::KEY_SIZE]>,
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
    associated_data: SmallVec<[u8; telio_crypto::KEY_SIZE]>,
}

type IcmpKey = Result<IcmpConn, IcmpErrorKey>;

#[derive(Clone, Debug)]
pub enum IcmpErrorKey {
    Udp(Option<IpConnWithPort>),
    Tcp(Option<IpConnWithPort>),
    Icmp(Option<Box<IcmpConn>>),
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
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LibfwConnectionState {
    /// Connection established
    LibfwConnectionStateEstablished,
    /// Outgoing packets
    LibfwConnectionStateNew,
}

///
/// Packet verdict
///
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LibfwVerdict {
    LibfwVerdictAccept,
    LibfwVerdictDrop,
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

pub(crate) struct Conntracker {
    /// Recent udp connections
    pub(crate) udp: parking_lot::Mutex<LruCache<Connection, UdpConnectionInfo>>,
    /// Recent tcp connections
    pub(crate) tcp: parking_lot::Mutex<LruCache<Connection, TcpConnectionInfo>>,
    /// Recent icmp connections
    pub(crate) icmp: parking_lot::Mutex<LruCache<IcmpConn, ()>>,

    pub(crate) logger: Logger,
}

impl Conntracker {
    /// Constructs a new conntracker
    pub fn new(capacity: usize, ttl: u64, logger: Logger) -> Self {
        let ttl = Duration::from_millis(ttl);
        Self {
            tcp: parking_lot::Mutex::new(LruCache::new(ttl, capacity)),
            udp: parking_lot::Mutex::new(LruCache::new(ttl, capacity)),
            icmp: parking_lot::Mutex::new(LruCache::new(ttl, capacity)),
            logger,
        }
    }

    #[cfg(feature = "test_utils")]
    /// Return the size of conntrack entries for tcp and udp (for testing only).
    pub fn get_state(&self) -> (usize, usize) {
        let tcp = self.tcp.lock().len();
        let udp = self.udp.lock().len();
        (tcp, udp)
    }

    pub fn get_udp_conn_info<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
        inbound: bool,
    ) -> Option<UdpConnectionInfo> {
        let link =
            unwrap_option_or_return!(Self::build_conn_info(&self.logger, ip, inbound), None).0;
        let key = Connection {
            link,
            associated_data: associated_data.to_smallvec(),
        };
        let mut udp_cache = self.udp.lock();
        match udp_cache.entry(key, false) {
            Entry::Occupied(occupied_entry) => Some(occupied_entry.get().clone()),
            Entry::Vacant(_) => None,
        }
    }

    pub fn get_tcp_conn_info<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
        inbound: bool,
    ) -> Option<TcpConnectionInfo> {
        let link =
            unwrap_option_or_return!(Self::build_conn_info(&self.logger, ip, inbound), None).0;
        let key = Connection {
            link,
            associated_data: associated_data.to_smallvec(),
        };
        let mut tcp_cache = self.tcp.lock();
        match tcp_cache.entry(key, false) {
            Entry::Occupied(occupied_entry) => Some(occupied_entry.get().clone()),
            Entry::Vacant(_) => None,
        }
    }

    pub fn handle_outbound_udp<'a>(&self, ip: &impl IpPacket<'a>, associated_data: &[u8]) {
        let link = unwrap_option_or_return!(Self::build_conn_info(&self.logger, ip, false)).0;
        let key = Connection {
            link,
            associated_data: associated_data.to_smallvec(),
        };

        let Some(pkg_chunk) = ip
            .packet()
            .chunks(UdpConnectionInfo::LAST_PKG_MAX_CHUNK_LEN)
            .next()
        else {
            self.logger.log(
                LibfwLogLevelWarn,
                format_args!("Failed to extract headers of UDP packet for {key:?}"),
            );
            return;
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
                self.logger.log(
                    LibfwLogLevelTrace,
                    format_args!("Inserting new UDP conntrack entry {:?}", e.key()),
                );
                e.insert(conninfo);
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
            }
        }
    }

    pub fn is_icmp_connection_tracked<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
        inbound: bool,
    ) -> bool {
        let key = unwrap_option_or_return!(
            Self::build_icmp_key(&self.logger, ip, associated_data, inbound).ok(),
            false
        );
        self.icmp.lock().peek(&key).is_some()
    }

    pub fn handle_outbound_tcp<'a>(&self, ip: &impl IpPacket<'a>, associated_data: &[u8]) {
        let (link, packet) =
            unwrap_option_or_return!(Self::build_conn_info(&self.logger, ip, false));
        let key = Connection {
            link,
            associated_data: associated_data.to_smallvec(),
        };
        let flags = packet.map(|p| p.get_flags()).unwrap_or(0);
        let mut tcp_cache = self.tcp.lock();
        let syn_ack = TcpFlags::SYN | TcpFlags::ACK;

        if flags & TCP_FIRST_PKT_MASK == TcpFlags::SYN {
            self.logger.log(
                LibfwLogLevelTrace,
                format_args!("Inserting TCP conntrack entry {:?}", key.link),
            );
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
        } else if flags & TcpFlags::RST == TcpFlags::RST {
            self.logger.log(
                LibfwLogLevelTrace,
                format_args!("Removing TCP conntrack entry {:?}", key),
            );
            tcp_cache.remove(&key);
        } else if flags & TcpFlags::FIN == TcpFlags::FIN {
            self.logger.log(
                LibfwLogLevelTrace,
                format_args!("Connection {:?} closing", key),
            );
            if let Entry::Occupied(mut e) = tcp_cache.entry(key, false) {
                let TcpConnectionInfo { tx_alive, .. } = e.get_mut();
                *tx_alive = false;
            }
        } else if flags & syn_ack == syn_ack {
            if let Some(tcp_connection_info) = tcp_cache.get_mut(&key) {
                tcp_connection_info.state = LibfwConnectionState::LibfwConnectionStateEstablished;
            }
        }
    }

    pub fn handle_outbound_icmp<'a>(&self, ip: &impl IpPacket<'a>, associated_data: &[u8]) {
        let mut icmp_cache = self.icmp.lock();
        if let Ok(key) = Self::build_icmp_key(&self.logger, ip, associated_data, false) {
            // If key already exists, dont change the value, just update timer with entry
            if let Entry::Vacant(e) = icmp_cache.entry(key, true) {
                self.logger.log(
                    LibfwLogLevelTrace,
                    format_args!("Inserting new ICMP conntrack entry {:?}", e.key()),
                );
                e.insert(());
            }
        }
    }

    pub fn handle_inbound_udp<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
        verdict: LibfwVerdict,
    ) {
        let (link, _) = unwrap_option_or_return!(Self::build_conn_info(&self.logger, ip, true));
        let key = Connection {
            link,
            associated_data: associated_data.to_smallvec(),
        };

        let mut udp_cache = self.udp.lock();

        match udp_cache.entry(key, true) {
            Entry::Occupied(mut occ) => {
                self.logger.log(
                    LibfwLogLevelTrace,
                    format_args!(
                        "Matched UDP conntrack entry {:?} {:?}",
                        occ.key(),
                        occ.get()
                    ),
                );

                if occ.get().is_remote_initiated && verdict == LibfwVerdict::LibfwVerdictDrop {
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Removing UDP conntrack entry {:?}", occ.key()),
                    );
                    occ.remove();
                } else if LibfwConnectionState::LibfwConnectionStateNew == occ.get().state {
                    occ.get_mut().state = LibfwConnectionState::LibfwConnectionStateEstablished;
                }
            }
            Entry::Vacant(vacc) => {
                let key = vacc.key();

                if let LibfwVerdict::LibfwVerdictAccept = verdict {
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!(
                            "Updating UDP conntrack entry {:?} {:?}",
                            key, associated_data
                        ),
                    );
                    vacc.insert(UdpConnectionInfo {
                        is_remote_initiated: true,
                        last_out_pkg_chunk: None,
                        state: LibfwConnectionState::LibfwConnectionStateNew,
                    });
                }
            }
        }
    }

    // Conntracker entries are ment for packets handled locally - so
    pub fn handle_inbound_tcp<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
        verdict: LibfwVerdict,
    ) {
        let (link, packet) =
            unwrap_option_or_return!(Self::build_conn_info(&self.logger, ip, true));
        let key = Connection {
            link,
            associated_data: associated_data.to_smallvec(),
        };
        let local_port = key.link.local_port;
        self.logger.log(
            LibfwLogLevelTrace,
            format_args!("Processing TCP packet with {:?}", key),
        );

        let mut cache = self.tcp.lock();
        // Dont update last access time in tcp, as it is handled by tcp flags
        match cache.entry(key, false) {
            Entry::Occupied(mut occ) => {
                let connection_info = occ.get_mut();
                self.logger.log(
                    LibfwLogLevelTrace,
                    format_args!(
                        "Matched conntrack entry {:?} {:?}",
                        associated_data, connection_info
                    ),
                );

                if let LibfwVerdict::LibfwVerdictDrop = verdict {
                    if connection_info.conn_remote_initiated {
                        self.logger.log(
                            LibfwLogLevelTrace,
                            format_args!("Removing TCP conntrack entry {:?}", associated_data),
                        );
                        occ.remove();
                        return;
                    }
                }

                if let Some(pkt) = packet {
                    let flags = pkt.get_flags();
                    let mut is_conn_reset = false;
                    if flags & TcpFlags::RST == TcpFlags::RST {
                        self.logger.log(
                            LibfwLogLevelTrace,
                            format_args!(
                                "Removing TCP conntrack entry with {:?} for {:?}",
                                associated_data, local_port
                            ),
                        );
                        is_conn_reset = true;
                    } else if (flags & TcpFlags::FIN) == TcpFlags::FIN {
                        self.logger.log(
                            LibfwLogLevelTrace,
                            format_args!(
                                "Connection with {:?} for {:?} closing",
                                associated_data, local_port
                            ),
                        );
                        connection_info.rx_alive = false;
                    } else if !connection_info.tx_alive
                        && !connection_info.rx_alive
                        && !connection_info.conn_remote_initiated
                    {
                        if (flags & TcpFlags::ACK) == TcpFlags::ACK {
                            self.logger.log(
                                LibfwLogLevelTrace,
                                format_args!(
                                    "Removing TCP conntrack entry with {:?} for {:?}",
                                    associated_data, local_port
                                ),
                            );
                            occ.remove();
                        }
                        return;
                    }

                    // restarts cache entry timeout
                    let next_seq = if (flags & TcpFlags::SYN) == TcpFlags::SYN {
                        pkt.get_sequence() + 1
                    } else {
                        pkt.get_sequence() + pkt.payload().len() as u32
                    };

                    connection_info.next_seq = Some(next_seq);
                    if is_conn_reset {
                        occ.remove();
                    } else {
                        // Connection which is not removed and packets are going in both directions should be established
                        occ.get_mut().state = LibfwConnectionState::LibfwConnectionStateEstablished;
                    }
                }
            }
            Entry::Vacant(vacc) => {
                // Accept and should handle locally
                if let (LibfwVerdict::LibfwVerdictAccept, Some(pkt)) = (verdict, packet) {
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
                        self.logger.log(
                            LibfwLogLevelTrace,
                            format_args!(
                                "Updating TCP conntrack entry {:?} {:?} {:?}",
                                key, associated_data, conn_info
                            ),
                        );
                        vacc.insert(conn_info);
                    }
                }
            }
        }
    }

    pub(crate) fn handle_inbound_icmp<'a, P: IpPacket<'a>>(
        &self,
        ip: &P,
        associated_data: &[u8],
    ) -> bool {
        match Self::build_icmp_key(&self.logger, ip, associated_data, true) {
            Ok(key) => {
                let mut icmp_cache = self.icmp.lock();
                let is_in_cache = icmp_cache.get(&key).is_some();
                if is_in_cache {
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Matched ICMP conntrack entry {:?}", key),
                    );
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Removing ICMP conntrack entry {:?}", key),
                    );
                    icmp_cache.remove(&key);
                }
                is_in_cache
            }
            Err(icmp_error_key) => {
                self.logger.log(
                    LibfwLogLevelTrace,
                    format_args!("Encountered ICMP error packet, checking nested packet"),
                );
                self.handle_icmp_error(icmp_error_key, associated_data)
            }
        }
    }

    fn handle_icmp_error(&self, error_key: IcmpErrorKey, associated_data: &[u8]) -> bool {
        match error_key {
            IcmpErrorKey::Icmp(Some(icmp_key)) => {
                let mut icmp_cache = self.icmp.lock();
                let is_in_cache = icmp_cache.get(&icmp_key).is_some();
                if is_in_cache {
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!(
                            "Nested packet in ICMP error packet matched ICMP conntrack entry {:?}",
                            icmp_key,
                        ),
                    );
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Removing ICMP conntrack entry {:?}", icmp_key),
                    );
                    icmp_cache.remove(&icmp_key);
                }
                is_in_cache
            }
            IcmpErrorKey::Tcp(Some(link)) => {
                let tcp_key = Connection {
                    link,
                    associated_data: associated_data.to_smallvec(),
                };

                let mut tcp_cache = self.tcp.lock();

                let is_in_cache = tcp_cache.get(&tcp_key).is_some();
                if is_in_cache {
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!(
                            "Nested packet in ICMP error packet matched TCP conntrack entry {:?}",
                            tcp_key,
                        ),
                    );
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Removing TCP conntrack entry {:?}", tcp_key),
                    );
                    tcp_cache.remove(&tcp_key);
                }
                is_in_cache
            }
            IcmpErrorKey::Udp(Some(link)) => {
                let udp_key = Connection {
                    link,
                    associated_data: associated_data.to_smallvec(),
                };

                let mut udp_cache = self.udp.lock();
                let is_in_cache = udp_cache.get(&udp_key).is_some();
                if is_in_cache {
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!(
                            "Nested packet in ICMP error packet matched UDP conntrack entry {:?}",
                            udp_key,
                        ),
                    );
                    self.logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Removing UDP conntrack entry {:?}", udp_key),
                    );
                    udp_cache.remove(&udp_key);
                }
                is_in_cache
            }
            _ => false,
        }
    }

    pub fn build_conn_info<'packet, 'logger, 'ip, P: IpPacket<'packet>>(
        logger: &'logger Logger,
        ip: &'ip P,
        inbound: bool,
    ) -> Option<(IpConnWithPort, Option<TcpPacket<'ip>>)> {
        let proto = ip.get_next_level_protocol();
        let (src, dest, tcp_packet) = match proto {
            IpNextHeaderProtocols::Udp => match UdpPacket::new(ip.payload()) {
                Some(packet) => (packet.get_source(), packet.get_destination(), None),
                _ => {
                    logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Could not create UDP packet from IP packet {:?}", ip),
                    );
                    return None;
                }
            },
            IpNextHeaderProtocols::Tcp => match TcpPacket::new(ip.payload()) {
                Some(packet) => (packet.get_source(), packet.get_destination(), Some(packet)),
                _ => {
                    logger.log(
                        LibfwLogLevelTrace,
                        format_args!("Could not create TCP packet from IP packet {:?}", ip),
                    );
                    return None;
                }
            },
            _ => return None,
        };

        let key = if inbound {
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
            IpNextHeaderProtocols::Udp => Some((key, None)),
            IpNextHeaderProtocols::Tcp => Some((key, tcp_packet)),
            _ => None,
        }
    }

    fn build_icmp_key<'a, P: IpPacket<'a>>(
        logger: &Logger,
        ip: &P,
        associated_data: &[u8],
        inbound: bool,
    ) -> IcmpKey {
        let icmp_packet = match IcmpPacket::new(ip.payload()) {
            Some(packet) => packet,
            _ => {
                logger.log(
                    LibfwLogLevelTrace,
                    format_args!("Could not create ICMP packet from IP packet {:?}", ip),
                );
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
                    return Self::build_icmp_error_key(logger, icmp_packet, associated_data, true);
                } else if (it == v6::DestinationUnreachable.0
                    || it == v6::PacketTooBig.0
                    || it == v6::ParameterProblem.0
                    || it == v6::TimeExceeded.0)
                    && ip.get_next_level_protocol() == IpNextHeaderProtocols::Icmpv6
                {
                    return Self::build_icmp_error_key(logger, icmp_packet, associated_data, false);
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
            associated_data: associated_data.to_smallvec(),
        };

        Ok(key)
    }

    fn build_icmp_error_key(
        logger: &Logger,
        icmp_packet: IcmpPacket,
        associated_data: &[u8],
        is_v4: bool,
    ) -> IcmpKey {
        let inner_packet = match icmp_packet.payload().get(4..) {
            Some(bytes) => bytes,
            None => {
                logger.log(
                    LibfwLogLevelTrace,
                    format_args!("ICMP error body does not contain a nested packet"),
                );
                return Err(IcmpErrorKey::None);
            }
        };
        let icmp_error_key = if is_v4 {
            let packet = match <Ipv4Packet<'_> as IpPacket>::try_from(inner_packet) {
                Some(packet) => packet,
                _ => {
                    logger.log(
                        LibfwLogLevelTrace,
                        format_args!("ICMP error contains invalid IPv4 packet"),
                    );
                    return Err(IcmpErrorKey::None);
                }
            };
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => IcmpErrorKey::Udp(
                    Self::build_conn_info(logger, &packet, false).map(|(key, _)| key),
                ),
                IpNextHeaderProtocols::Tcp => IcmpErrorKey::Tcp(
                    Self::build_conn_info(logger, &packet, false).map(|(key, _)| key),
                ),
                IpNextHeaderProtocols::Icmp => IcmpErrorKey::Icmp(
                    Self::build_icmp_key(logger, &packet, associated_data, false)
                        .ok()
                        .map(Box::new),
                ),
                _ => IcmpErrorKey::None,
            }
        } else {
            let packet = match <Ipv6Packet<'_> as IpPacket>::try_from(inner_packet) {
                Some(packet) => packet,
                _ => {
                    logger.log(
                        LibfwLogLevelTrace,
                        format_args!("ICMP error contains invalid IPv6 packet"),
                    );
                    return Err(IcmpErrorKey::None);
                }
            };
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => IcmpErrorKey::Udp(
                    Self::build_conn_info(logger, &packet, false).map(|(key, _)| key),
                ),
                IpNextHeaderProtocols::Tcp => IcmpErrorKey::Tcp(
                    Self::build_conn_info(logger, &packet, false).map(|(key, _)| key),
                ),
                IpNextHeaderProtocols::Icmpv6 => IcmpErrorKey::Icmp(
                    Self::build_icmp_key(logger, &packet, associated_data, false)
                        .ok()
                        .map(Box::new),
                ),
                _ => IcmpErrorKey::None,
            }
        };
        Err(icmp_error_key)
    }

    pub(crate) fn reset_tcp_conns<F>(
        &self,
        associated_data: &[u8],
        inject_packet_cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        let mut tcp_conn_cache = self.tcp.lock();

        self.logger.log(
            LibfwLogLevelDebug,
            format_args!(
                "Inspecting {} TCP connections for reset",
                tcp_conn_cache.len()
            ),
        );

        let iter = tcp_conn_cache.iter().filter_map(|(k, v)| {
            if &*k.associated_data == associated_data {
                // When we don't have the sequence number that means the
                // connection is half open and we don't have a response
                // from the remote peer yet. We need to skip this kind of
                // connections
                v.next_seq.map(|next_seq| (&k.link, next_seq, None))
            } else {
                None
            }
        });

        self.send_tcp_rst_packets(iter, inject_packet_cb)
    }

    pub fn send_tcp_rst_packets<'a, I, F>(
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

                    self.logger.log(
                        LibfwLogLevelDebug,
                        format_args!("Injecting IPv4 TCP RST packet {key:#?}"),
                    );

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

                    self.logger.log(
                        LibfwLogLevelDebug,
                        format_args!("Injecting IPv4 TCP RST packet {key:#?}"),
                    );

                    #[allow(index_access_check)]
                    ipv6pkgbuf[..IPV6_LEN].copy_from_slice(ipv6pkg.packet());

                    #[allow(index_access_check)]
                    ipv6pkgbuf[IPV6_LEN..].copy_from_slice(tcppkg.packet());
                    inject_packet_cb(&ipv6pkgbuf)?;
                }
                _ => self.logger.log(
                    LibfwLogLevelWarn,
                    format_args!(
                        "Local and remote IP addrs version missmatch, this should never happen"
                    ),
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

                    self.logger.log(
                        LibfwLogLevelDebug,
                        format_args!("Injecting IPv4 ICMP (for UDP) packet {key:#?}"),
                    );
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

                    self.logger.log(
                        LibfwLogLevelDebug,
                        format_args!("Injecting IPv6 ICMP (for UDP) packet {key:#?}"),
                    );
                    inject_packet_cb(ipv6pkgbuf)?;
                }
                _ => self.logger.log(
                    LibfwLogLevelWarn,
                    format_args!(
                        "Local and remote IP addrs version mismatch, this should never happen"
                    ),
                ),
            }
        }

        Ok(())
    }

    pub(crate) fn reset_udp_conns<F>(
        &self,
        associated_data: &[u8],
        inject_packet_cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        let mut udp_conn_cache = self.udp.lock();

        self.logger.log(
            LibfwLogLevelDebug,
            format_args!(
                "Inspecting {} UDP connections for reset",
                udp_conn_cache.len()
            ),
        );

        let iter = udp_conn_cache.iter().filter_map(|(k, v)| {
            // Skip connection without outbounded packages
            let last_headers = v.last_out_pkg_chunk.as_deref()?;

            if &*k.associated_data != associated_data {
                return None;
            }

            Some((&k.link, last_headers))
        });

        self.send_icmp_port_unreachable_packets(iter, inject_packet_cb)
    }

    pub(crate) fn handle_outbound_packet<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
    ) {
        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                self.handle_outbound_udp(ip, associated_data);
            }
            IpNextHeaderProtocols::Tcp => {
                self.handle_outbound_tcp(ip, associated_data);
            }
            IpNextHeaderProtocols::Icmp => {
                self.handle_outbound_icmp(ip, associated_data);
            }
            IpNextHeaderProtocols::Icmpv6 => {
                self.handle_outbound_icmp(ip, associated_data);
            }
            _ => (),
        };
    }

    pub(crate) fn handle_inbound_packet<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
        verdict: LibfwVerdict,
    ) {
        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                self.handle_inbound_udp(ip, associated_data, verdict);
            }
            IpNextHeaderProtocols::Tcp => {
                self.handle_inbound_tcp(ip, associated_data, verdict);
            }
            IpNextHeaderProtocols::Icmp => {
                self.handle_inbound_icmp(ip, associated_data);
            }
            IpNextHeaderProtocols::Icmpv6 => {
                self.handle_inbound_icmp(ip, associated_data);
            }
            _ => (),
        }
    }

    pub(crate) fn get_connection_state<'a>(
        &self,
        ip: &impl IpPacket<'a>,
        associated_data: &[u8],
        direction: LibfwDirection,
    ) -> Option<LibfwConnectionState> {
        let inbound = matches!(direction, LibfwDirection::LibfwDirectionInbound);
        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                if let Some(conn_info) = self.get_udp_conn_info(ip, associated_data, inbound) {
                    return Some(conn_info.state);
                }
            }
            IpNextHeaderProtocols::Tcp => {
                if let Some(conn_info) = self.get_tcp_conn_info(ip, associated_data, inbound) {
                    return Some(conn_info.state);
                }
            }
            IpNextHeaderProtocols::Icmp => {
                if self.is_icmp_connection_tracked(ip, associated_data, inbound) {
                    return Some(LibfwConnectionState::LibfwConnectionStateNew);
                }
            }
            IpNextHeaderProtocols::Icmpv6 => {
                if self.is_icmp_connection_tracked(ip, associated_data, inbound) {
                    return Some(LibfwConnectionState::LibfwConnectionStateNew);
                }
            }
            _ => (),
        }
        None
    }
}
