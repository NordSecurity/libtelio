//! Telio firewall component used to track open connections
//! with other devices§

use core::fmt;
use enum_map::{Enum, EnumMap};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use parking_lot::RwLock;
use pnet_packet::{
    icmp::{IcmpType, IcmpTypes},
    icmpv6::{Icmpv6Type, Icmpv6Types},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpFlags,
    Packet,
};
use smallvec::ToSmallVec;
use std::{
    convert::TryInto,
    fmt::Debug,
    io::{self},
    net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr, SocketAddr},
};

use telio_model::features::{FeatureFirewall, IpProtocol};
use telio_network_monitors::monitor::{LocalInterfacesObserver, LOCAL_ADDRS_CACHE};

use telio_crypto::PublicKey;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};

use crate::{
    chain::Chain as InternalChain,
    chain_helpers::{
        ConnectionState, Direction, FfiChainGuard, Filter, FilterData, NetworkFilterData,
        NextLevelProtocol, Rule,
    },
    conntrack::{
        unwrap_option_or_return, ConnectionState as CtkConnectionState, Conntrack,
        Direction as CtkDirection, Error, Result, UdpConnectionInfo,
    },
    ffi_chain::LibfwVerdict,
};

/// HashSet type used internally by firewall and returned by get_peer_whitelist
pub type HashSet<V> = rustc_hash::FxHashSet<V>;
/// HashMap type used internally by firewall and returned by get_port_whitelist
pub type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;

const LRU_CAPACITY: usize = 4096; // Max entries to keep (sepatately for TCP, UDP, and others)
const LRU_TIMEOUT: u64 = 120_000; // 2min (https://datatracker.ietf.org/doc/html/rfc4787#section-4.3)

pub(crate) const TCP_FIRST_PKT_MASK: u8 = TcpFlags::SYN | TcpFlags::ACK;

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub(crate) enum IpAddr {
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

#[allow(dead_code)]
pub(crate) trait Icmp: Sized {
    const BLOCKED_TYPES: [u8; 4];
}

impl Icmp for IcmpType {
    const BLOCKED_TYPES: [u8; 4] = ICMP_BLOCKED_TYPES;
}

impl Icmp for Icmpv6Type {
    const BLOCKED_TYPES: [u8; 4] = ICMPV6_BLOCKED_TYPES;
}

pub(crate) trait IpPacket<'a>: Sized + Debug + Packet {
    type Addr: Into<IpAddr> + Into<std::net::IpAddr>;
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
    fn clear_peer_whitelists(&self);

    /// Add peer to whitelist
    fn add_to_peer_whitelist(&self, peer: PublicKey, permissions: Permissions);

    /// Remove peer from whitelist
    fn remove_from_peer_whitelist(&self, peer: PublicKey, permissions: Permissions);

    /// Returns a whitelist of peers
    fn get_peer_whitelist(&self, permissions: Permissions) -> HashSet<PublicKey>;

    /// Adds vpn peer public key
    fn add_vpn_peer(&self, vpn_peer: PublicKey);

    /// Removes vpn peer
    fn remove_vpn_peer(&self);

    /// For new connections it opens a pinhole for incoming connection
    /// If connection is already cached, it resets its timer and extends its lifetime
    /// Only returns false for invalid or not ipv4 packets
    fn process_outbound_packet(
        &self,
        public_key: &[u8; 32],
        buffer: &[u8],
        sink: &mut dyn io::Write,
    ) -> bool;

    /// Checks if incoming packet should be accepted.
    /// Does not extend pinhole lifetime on success
    /// Adds new connection to cache only if ip is whitelisted
    /// Allows all icmp packets except for request types
    fn process_inbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool;

    /// Creates packets that are supposed to kill the existing connections.
    /// The end goal here is to fore the client app sockets to reconnect.
    fn reset_connections(&self, pubkey: &PublicKey, sink: &mut dyn io::Write) -> io::Result<()>;

    /// Saves local node Ip address into firewall object
    fn set_ip_addresses(&self, ip_addrs: Vec<StdIpAddr>);
}

/// Possible permissions of the peer
#[derive(Clone, Copy, Enum, Debug, PartialEq)]
pub enum Permissions {
    /// Permission to allow incoming connections
    IncomingConnections,
    /// Permission for peer to access local network
    LocalAreaConnections,
    /// Permission for peer to route traffic
    RoutingConnections,
}

impl Permissions {
    /// Array of permissions to iterate over
    pub const VALUES: [Self; 3] = [
        Self::IncomingConnections,
        Self::LocalAreaConnections,
        Self::RoutingConnections,
    ];
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Permissions::IncomingConnections => write!(f, "Incoming Connections"),
            Permissions::LocalAreaConnections => write!(f, "Local Area Connections"),
            Permissions::RoutingConnections => write!(f, "Routing Connections"),
        }
    }
}

#[derive(Default)]
struct Whitelist {
    /// List of whitelisted source peer and destination port pairs
    port_whitelist: HashMap<PublicKey, u16>,

    /// Whitelisted peers of different permissions
    peer_whitelists: EnumMap<Permissions, HashSet<PublicKey>>,

    /// Public key of vpn peer
    vpn_peer: Option<PublicKey>,
}

/// Statefull packet-filter firewall.
pub struct StatefullFirewall {
    /// Connection tracking
    conntrack: Conntrack,
    /// Firewall rule chain
    chain: RwLock<InternalChain>,
    /// Whitelist of networks/peers allowed to connect
    whitelist: RwLock<Whitelist>,
    /// Indicates whether the firewall should use IPv6
    allow_ipv6: bool,
    /// Local node ip addresses
    ip_addresses: RwLock<Vec<StdIpAddr>>,
    /// Custom IPv4 range to check against
    exclude_ip_range: Option<Ipv4Net>,
    /// Blacklist for outgoing TCP connections
    outgoing_tcp_blacklist: RwLock<Vec<SocketAddr>>,
    /// Blacklist for outgoing UDP connections
    outgoing_udp_blacklist: RwLock<Vec<SocketAddr>>,
}

impl LocalInterfacesObserver for StatefullFirewall {
    fn notify(&self) {
        self.recreate_chain();
    }
}

impl StatefullFirewall {
    /// Constructs firewall with default timeout (2 mins) and capacity (4096 entries).
    pub fn new(use_ipv6: bool, feature: &FeatureFirewall) -> Self {
        StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, use_ipv6, feature)
    }

    #[cfg(any(feature = "test_utils", test))]
    /// Return the size of conntrack entries for tcp and udp (for testing only).
    pub fn get_state(&self) -> (usize, usize) {
        self.conntrack.get_state()
    }

    /// Constructs firewall with custom capacity and timeout in ms (for testing only).
    fn new_custom(capacity: usize, ttl: u64, use_ipv6: bool, feature: &FeatureFirewall) -> Self {
        let result = Self {
            conntrack: Conntrack::new(capacity, ttl),
            chain: RwLock::new(InternalChain { rules: vec![] }),
            whitelist: RwLock::new(Whitelist::default()),
            allow_ipv6: use_ipv6,
            ip_addresses: RwLock::new(Vec::<StdIpAddr>::new()),
            exclude_ip_range: feature.exclude_private_ip_range.map(Into::into),
            outgoing_tcp_blacklist: RwLock::new(
                feature
                    .outgoing_blacklist
                    .iter()
                    .filter_map(|i| {
                        if i.protocol == IpProtocol::TCP {
                            Some(SocketAddr::new(i.ip, i.port))
                        } else {
                            None
                        }
                    })
                    .collect(),
            ),
            outgoing_udp_blacklist: RwLock::new(
                feature
                    .outgoing_blacklist
                    .iter()
                    .filter_map(|i| {
                        if i.protocol == IpProtocol::UDP {
                            Some(SocketAddr::new(i.ip, i.port))
                        } else {
                            None
                        }
                    })
                    .collect(),
            ),
        };
        result.recreate_chain();
        result
    }

    fn dst_net_all_ports_filter(net: IpNet, inverted: bool) -> Filter {
        Filter {
            filter_data: FilterData::DstNetwork(NetworkFilterData {
                network: net,
                port_range: (0, 65535),
            }),
            inverted,
        }
    }

    fn get_local_area_networks_filters(&self) -> Vec<Vec<Filter>> {
        // Create rules for peers with LocalAreaConnection permissions
        let ipv4_local_area_networks = [
            Ipv4Net::new_assert(StdIpv4Addr::new(10, 0, 0, 0), 8),
            Ipv4Net::new_assert(StdIpv4Addr::new(172, 16, 0, 0), 12),
            Ipv4Net::new_assert(StdIpv4Addr::new(192, 168, 0, 0), 16),
        ];

        // Include packets which are going to local IPv4 networks
        let mut ipv4_local_area_network_filters = ipv4_local_area_networks
            .map(|network| vec![Self::dst_net_all_ports_filter(IpNet::V4(network), false)]);

        // Exclude packets from the exclude range
        if let Some(exclude_range) = self.exclude_ip_range {
            for local_net_filters in ipv4_local_area_network_filters.iter_mut() {
                local_net_filters.push(Self::dst_net_all_ports_filter(
                    IpNet::V4(exclude_range),
                    true,
                ));
            }
        }

        let mut ipv6_local_area_network_filters = vec![
            // Include packets which are going to local network
            Self::dst_net_all_ports_filter(
                IpNet::V6(Ipv6Net::new_assert(
                    // TODO: Actually it Unique Local Address range should be (from what I found) fc00::/7,
                    // but it seems that we assume (and our tests do) that it is fc00::/6
                    StdIpv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
                    6,
                )),
                false,
            ),
            // Exclude packets which are going to local interfaces
            Self::dst_net_all_ports_filter(
                IpNet::V6(Ipv6Net::new_assert(
                    StdIpv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 0),
                    64,
                )),
                true,
            ),
        ];

        for ip in LOCAL_ADDRS_CACHE.lock().iter().map(|peer| peer.ip()) {
            if ip.is_ipv4() {
                for local_network_filters in ipv4_local_area_network_filters.iter_mut() {
                    local_network_filters
                        .push(Self::dst_net_all_ports_filter(IpNet::from(ip), true));
                }
            } else {
                ipv6_local_area_network_filters
                    .push(Self::dst_net_all_ports_filter(IpNet::from(ip), true));
            }
        }

        let mut result = Vec::from(ipv4_local_area_network_filters);
        result.push(ipv6_local_area_network_filters);
        result
    }

    fn recreate_chain(&self) {
        let mut rules = vec![];

        // Drop packets from UDP blacklist
        for peer in self.outgoing_udp_blacklist.read().iter() {
            rules.push(Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::Direction(Direction::Outbound),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::NextLevelProtocol(NextLevelProtocol::Udp),
                        inverted: false,
                    },
                    Self::dst_net_all_ports_filter(IpNet::from(peer.ip()), false),
                ],
                action: LibfwVerdict::LibfwVerdictReject,
            });
        }

        // Drop packets from TCP blacklist
        for peer in self.outgoing_tcp_blacklist.read().iter() {
            rules.push(Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::Direction(Direction::Outbound),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::NextLevelProtocol(NextLevelProtocol::Tcp),
                        inverted: false,
                    },
                    Self::dst_net_all_ports_filter(IpNet::from(peer.ip()), false),
                ],
                action: LibfwVerdict::LibfwVerdictReject,
            });
        }

        rules.push(Rule {
            filters: vec![Filter {
                filter_data: FilterData::Direction(Direction::Outbound),
                inverted: false,
            }],
            action: LibfwVerdict::LibfwVerdictAccept,
        });

        // Add VPN rule
        if let Some(vpn_pk) = self.whitelist.read().vpn_peer {
            rules.push(Rule {
                filters: vec![Filter {
                    filter_data: FilterData::AssociatedData(Some(vpn_pk.to_smallvec())),
                    inverted: false,
                }],
                action: LibfwVerdict::LibfwVerdictAccept,
            });
        }

        let local_network_filters = self.get_local_area_networks_filters();

        #[allow(clippy::indexing_slicing)]
        for peer in self.whitelist.read().peer_whitelists[Permissions::LocalAreaConnections].iter()
        {
            for local_net in local_network_filters.iter() {
                let mut filters = vec![Filter {
                    filter_data: FilterData::AssociatedData(Some(peer.to_smallvec())),
                    inverted: false,
                }];
                filters.extend_from_slice(local_net);
                rules.push(Rule {
                    filters,
                    action: LibfwVerdict::LibfwVerdictAccept,
                });
            }
        }

        // For nodes not included in the whitelist this packet should be dropped
        for filters in local_network_filters {
            rules.push(Rule {
                filters,
                action: LibfwVerdict::LibfwVerdictDrop,
            });
        }

        // Rules for incoming connections
        let local_ip = self.ip_addresses.read();
        for ip in local_ip.iter() {
            // Accept packets for whitelisted peers
            #[allow(clippy::indexing_slicing)]
            for peer in
                self.whitelist.read().peer_whitelists[Permissions::IncomingConnections].iter()
            {
                rules.push(Rule {
                    filters: vec![
                        Filter {
                            filter_data: FilterData::AssociatedData(Some(peer.to_smallvec())),
                            inverted: false,
                        },
                        Self::dst_net_all_ports_filter(IpNet::from(*ip), false),
                    ],
                    action: LibfwVerdict::LibfwVerdictAccept,
                });
            }

            // Accept packets for locally initiated connections
            rules.push(Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::ConntrackState(ConnectionState::Established),
                        inverted: false,
                    },
                    Self::dst_net_all_ports_filter(IpNet::from(*ip), false),
                ],
                action: LibfwVerdict::LibfwVerdictAccept,
            });

            // Accept certain TCP packets for finished connections
            rules.push(Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::ConntrackState(ConnectionState::Closed),
                        inverted: false,
                    },
                    Filter {
                        filter_data: FilterData::TcpFlags(
                            TcpFlags::ACK | TcpFlags::FIN | TcpFlags::RST,
                        ),
                        inverted: false,
                    },
                    Self::dst_net_all_ports_filter(IpNet::from(*ip), false),
                ],
                action: LibfwVerdict::LibfwVerdictAccept,
            });

            // Accept packets for whitelisted ports
            for proto in [NextLevelProtocol::Tcp, NextLevelProtocol::Udp] {
                for (peer, &port) in self.whitelist.read().port_whitelist.iter() {
                    rules.push(Rule {
                        filters: vec![
                            Filter {
                                filter_data: FilterData::AssociatedData(Some(peer.to_smallvec())),
                                inverted: false,
                            },
                            Filter {
                                filter_data: FilterData::NextLevelProtocol(proto),
                                inverted: false,
                            },
                            Filter {
                                filter_data: FilterData::DstNetwork(NetworkFilterData {
                                    network: IpNet::from(*ip),
                                    port_range: (port, port),
                                }),
                                inverted: false,
                            },
                        ],
                        action: LibfwVerdict::LibfwVerdictAccept,
                    });
                }
            }

            // Drop rest of the packets going to local interfaces
            rules.push(Rule {
                filters: vec![Self::dst_net_all_ports_filter(IpNet::from(*ip), false)],
                action: LibfwVerdict::LibfwVerdictDrop,
            });
        }

        #[allow(clippy::indexing_slicing)]
        for peer in self.whitelist.read().peer_whitelists[Permissions::RoutingConnections].iter() {
            rules.push(Rule {
                filters: vec![Filter {
                    filter_data: FilterData::AssociatedData(Some(peer.to_smallvec())),
                    inverted: false,
                }],
                action: LibfwVerdict::LibfwVerdictAccept,
            });
        }

        let ffi_chain_guard: FfiChainGuard = (rules.as_slice()).into();
        if let Ok(internal_chain) = (&ffi_chain_guard.ffi_chain).try_into() {
            *self.chain.write() = internal_chain;
        } else {
            telio_log_error!("FFI chain we produced is malformed!");
        }
    }

    fn process_outbound_ip_packet<'a, P: IpPacket<'a>>(
        &self,
        public_key: &[u8; 32],
        buffer: &'a [u8],
        sink: &mut dyn io::Write,
        conn_state: CtkConnectionState,
    ) -> Result<bool> {
        let ip = unwrap_option_or_return!(P::try_from(buffer), Err(Error::MalformedIpPacket));
        let peer: PublicKey = PublicKey(*public_key);

        if !ip.check_valid() {
            telio_log_trace!("Outbound IP packet is not valid, dropping: {:?}", ip);
            return Ok(false);
        }

        let verdict = self.chain.read().process_packet(
            conn_state,
            &ip,
            Some(public_key),
            CtkDirection::Outbound,
        );

        if let LibfwVerdict::LibfwVerdictReject = verdict {
            match ip.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    let link = Conntrack::build_conn_info(&ip, CtkDirection::Outbound)?.0;
                    let Some(first_chunk) = ip
                        .packet()
                        .chunks(UdpConnectionInfo::LAST_PKG_MAX_CHUNK_LEN)
                        .next()
                    else {
                        telio_log_warn!("Failed to extract headers of UDP packet for {peer:?}");
                        return Err(Error::MalformedUdpPacket);
                    };

                    _ = self.conntrack.send_icmp_port_unreachable_packets(
                        std::iter::once((&link, first_chunk)),
                        |packet: &[u8]| sink.write_all(packet),
                    );

                    return Ok(false);
                }
                IpNextHeaderProtocols::Tcp => {
                    let (link, tcp_packet) =
                        Conntrack::build_conn_info(&ip, CtkDirection::Outbound)?;
                    let tcp_packet = unwrap_option_or_return!(tcp_packet, Ok(false));
                    _ = self.conntrack.send_tcp_rst_packets(
                        std::iter::once((&link, 0, Some(tcp_packet.get_sequence() + 1))),
                        |packet: &[u8]| sink.write_all(packet),
                    );

                    return Ok(false);
                }
                _ => {
                    telio_log_warn!("Unexpected packet type rejected - skipping");
                }
            }
        }

        telio_log_trace!("Accepting packet {:?} {:?}", ip, peer);
        Ok(true)
    }

    fn process_inbound_ip_packet<'a, P: IpPacket<'a>>(
        &self,
        public_key: &[u8; 32],
        buffer: &'a [u8],
        conn_state: CtkConnectionState,
    ) -> Result<bool> {
        let ip = unwrap_option_or_return!(P::try_from(buffer), Err(Error::MalformedIpPacket));

        if !ip.check_valid() {
            telio_log_trace!("Inbound IP packet is not valid, dropping: {:?}", ip);
            return Ok(false);
        }

        Ok(self.chain.read().process_packet(
            conn_state,
            &ip,
            Some(public_key),
            CtkDirection::Inbound,
        ) == LibfwVerdict::LibfwVerdictAccept)
    }

    fn cleanup_conntrack_inbound<'a, P: IpPacket<'a>>(
        &self,
        public_key: &[u8; 32],
        buffer: &'a [u8],
        accepted: bool,
    ) {
        let ip = unwrap_option_or_return!(P::try_from(buffer));
        let peer = PublicKey(*public_key);
        let proto = ip.get_next_level_protocol();

        match proto {
            IpNextHeaderProtocols::Udp => {
                if !accepted
                    && self
                        .conntrack
                        .cleanup_udp_conn_on_drop(ip, Some(&peer))
                        .is_err()
                {
                    telio_log_warn!("Failed to cleanup UDP conntrack entry");
                }
            }
            IpNextHeaderProtocols::Tcp => {
                if self
                    .conntrack
                    .cleanup_tcp_conn(ip, Some(&peer), accepted)
                    .is_err()
                {
                    telio_log_warn!("Failed to cleanup TCP conntrack entry");
                }
            }
            _ => (),
        }
    }
}

impl Firewall for StatefullFirewall {
    fn clear_port_whitelist(&self) {
        telio_log_debug!("Clearing firewall port whitelist");
        self.whitelist.write().port_whitelist.clear();
        self.recreate_chain();
    }

    fn add_to_port_whitelist(&self, peer: PublicKey, port: u16) {
        telio_log_debug!("Adding {peer:?}:{port} network to firewall port whitelist");
        self.whitelist.write().port_whitelist.insert(peer, port);
        self.recreate_chain();
    }

    fn remove_from_port_whitelist(&self, peer: PublicKey) {
        telio_log_debug!("Removing {peer:?} network from firewall port whitelist");
        self.whitelist.write().port_whitelist.remove(&peer);
        self.recreate_chain();
    }

    fn get_port_whitelist(&self) -> HashMap<PublicKey, u16> {
        self.whitelist.read().port_whitelist.clone()
    }

    fn clear_peer_whitelists(&self) {
        telio_log_debug!("Clearing all firewall whitelist");
        self.whitelist
            .write()
            .peer_whitelists
            .iter_mut()
            .for_each(|(_, whitelist)| whitelist.clear());
        self.recreate_chain();
    }

    #[allow(clippy::indexing_slicing)]
    fn add_to_peer_whitelist(&self, peer: PublicKey, permissions: Permissions) {
        self.whitelist.write().peer_whitelists[permissions].insert(peer);
        self.recreate_chain();
    }

    #[allow(clippy::indexing_slicing)]
    fn remove_from_peer_whitelist(&self, peer: PublicKey, permissions: Permissions) {
        self.whitelist.write().peer_whitelists[permissions].remove(&peer);
        self.recreate_chain();
    }

    #[allow(clippy::indexing_slicing)]
    fn get_peer_whitelist(&self, permissions: Permissions) -> HashSet<PublicKey> {
        self.whitelist.read().peer_whitelists[permissions].clone()
    }

    fn add_vpn_peer(&self, vpn_peer: PublicKey) {
        self.whitelist.write().vpn_peer = Some(vpn_peer);
        self.recreate_chain();
    }

    fn remove_vpn_peer(&self) {
        self.whitelist.write().vpn_peer = None;
        self.recreate_chain();
    }

    fn process_outbound_packet(
        &self,
        public_key: &[u8; 32],
        buffer: &[u8],
        sink: &mut dyn io::Write,
    ) -> bool {
        match unwrap_option_or_return!(buffer.first(), false) >> 4 {
            4 => {
                let conn_state = self
                    .conntrack
                    .track_outbound_ip_packet::<Ipv4Packet>(Some(public_key), buffer)
                    .unwrap_or_else(|_| {
                        telio_log_warn!("Conntrack failed for outbound IPv4 packet");
                        CtkConnectionState::New
                    });
                self.process_outbound_ip_packet::<Ipv4Packet>(public_key, buffer, sink, conn_state)
                    .unwrap_or(false)
            }
            6 if self.allow_ipv6 => {
                let conn_state = self
                    .conntrack
                    .track_outbound_ip_packet::<Ipv6Packet>(Some(public_key), buffer)
                    .unwrap_or_else(|_| {
                        telio_log_warn!("Conntrack failed for outbound IPv4 packet");
                        // Some packets are unexpected, but we still let them through, like outbound ICMP reply
                        CtkConnectionState::New
                    });
                self.process_outbound_ip_packet::<Ipv6Packet>(public_key, buffer, sink, conn_state)
                    .unwrap_or(false)
            }
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
            4 => {
                let Ok(conn_state) = self
                    .conntrack
                    .track_inbound_ip_packet::<Ipv4Packet>(Some(public_key), buffer)
                else {
                    telio_log_warn!("Contrack failed to process the packet");
                    return false;
                };
                let result = self
                    .process_inbound_ip_packet::<Ipv4Packet>(public_key, buffer, conn_state)
                    .unwrap_or(false);
                self.cleanup_conntrack_inbound::<Ipv4Packet>(public_key, buffer, result);
                result
            }
            6 if self.allow_ipv6 => {
                let Ok(conn_state) = self
                    .conntrack
                    .track_inbound_ip_packet::<Ipv6Packet>(Some(public_key), buffer)
                else {
                    telio_log_warn!("Contrack failed to process the packet");
                    return false;
                };
                let result = self
                    .process_inbound_ip_packet::<Ipv6Packet>(public_key, buffer, conn_state)
                    .unwrap_or(false);
                self.cleanup_conntrack_inbound::<Ipv6Packet>(public_key, buffer, result);
                result
            }
            version => {
                telio_log_warn!("Unexpected IP version {version} for inbound packet");
                false
            }
        }
    }

    fn reset_connections(&self, pubkey: &PublicKey, sink: &mut dyn io::Write) -> io::Result<()> {
        telio_log_debug!("Constructing connetion reset packets");

        self.conntrack
            .reset_tcp_conns(Some(pubkey), |packet: &[u8]| sink.write_all(packet))?;
        self.conntrack
            .reset_udp_conns(Some(pubkey), |packet: &[u8]| sink.write_all(packet))?;

        Ok(())
    }

    fn set_ip_addresses(&self, ip_addrs: Vec<StdIpAddr>) {
        if ip_addrs != *self.ip_addresses.read() {
            *self.ip_addresses.write().as_mut() = ip_addrs;
            self.recreate_chain();
        }
    }
}

/// The default initialization of Firewall object
impl Default for StatefullFirewall {
    fn default() -> Self {
        Self::new(true, &FeatureFirewall::default())
    }
}

#[cfg(any(test, feature = "test_utils"))]
#[allow(missing_docs, unused)]
pub mod tests {
    use crate::conntrack::{Connection, ConnectionState, IpConnWithPort, TcpConnectionInfo};

    use super::*;
    use pnet_packet::{
        icmp::{
            destination_unreachable::{self, DestinationUnreachablePacket},
            IcmpPacket, IcmpType, MutableIcmpPacket,
        },
        icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Type, MutableIcmpv6Packet},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::MutableIpv4Packet,
        ipv6::MutableIpv6Packet,
        tcp::{MutableTcpPacket, TcpPacket},
        udp::MutableUdpPacket,
        MutablePacket,
    };
    use smallvec::{SmallVec, ToSmallVec};
    use std::{
        convert::TryInto,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr as StdSocketAddr, SocketAddrV4, SocketAddrV6},
        str::FromStr,
        time::Duration,
    };
    use telio_crypto::SecretKey;
    use telio_model::features::FirewallBlacklistTuple;

    type MakeUdp = &'static dyn Fn(&str, &str) -> Vec<u8>;
    type MakeTcp = &'static dyn Fn(&str, &str, u8) -> Vec<u8>;
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

    impl StatefullFirewall {
        fn process_outbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool {
            Firewall::process_outbound_packet(self, public_key, buffer, &mut &io::sink())
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
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &FeatureFirewall::default());
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
            // Should FAIL (no matching outgoing connections yet)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src1)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src2)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src3)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src4)), false);
            assert_eq!(fw.conntrack.udp.lock().len(), 0);

            // Should PASS (adds 1111..4444 and drops 2222)
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src2, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.conntrack.udp.lock().len(), 2);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src3, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.conntrack.udp.lock().len(), 3);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src4, dst1)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), true);
            assert_eq!(fw.conntrack.udp.lock().len(), 3);

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
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),]);

            // Should FAIL (no matching outgoing connections yet)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src1, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src2, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src3, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src4, TcpFlags::SYN)), false);
            assert_eq!(fw.conntrack.tcp.lock().len(), 0);

            // Should PASS (adds 1111..4444 and drops 2222)
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src2, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 2);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src3, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 3);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src4, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 3);

            // Should PASS (matching outgoing connections exist in LRUCache)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src4, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src3, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src1, TcpFlags::SYN | TcpFlags::ACK)), true);

            // Should FAIL (was added but dropped from LRUCache)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src2, TcpFlags::SYN)), false);

            // Should FAIL (has no matching outgoing connection)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst1, src5, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(dst2, src1, TcpFlags::SYN)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src1, dst1, TcpFlags::SYN)), false);
        }
    }

    fn ip_address_set_multiple_times() {
        let ip_vec = vec![
            StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
            StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        let new_ip_vec = vec![
            StdIpAddr::V4(StdIpv4Addr::new(192, 168, 1, 1)),
            StdIpAddr::V6(StdIpv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 1)),
        ];

        let fw = StatefullFirewall::new(false, &FeatureFirewall::default());

        assert_eq!(fw.ip_addresses.read().len(), 0);

        fw.set_ip_addresses(ip_vec.clone());
        assert_eq!(fw.ip_addresses.read().len(), 2);
        assert_eq!(*fw.ip_addresses.read(), ip_vec);

        fw.set_ip_addresses(ip_vec.clone());
        assert_eq!(fw.ip_addresses.read().len(), 2);
        assert_eq!(*fw.ip_addresses.read(), ip_vec);

        fw.set_ip_addresses(new_ip_vec.clone());
        assert_eq!(fw.ip_addresses.read().len(), 2);
        assert_eq!(*fw.ip_addresses.read(), new_ip_vec);
    }

    #[rustfmt::skip]
    #[test]
    fn ipv6_blocked() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            src3: &'static str,
            src4: &'static str,
            src5: &'static str,
            dst1: &'static str,
            dst2: &'static str,
            make_udp: MakeUdp,
            is_ipv4: bool
        }

        let test_inputs = vec![
            TestInput{
                src1: "127.0.0.1:1111", src2: "127.0.0.1:2222",
                src3: "127.0.0.1:3333", src4: "127.0.0.1:4444",
                src5: "127.0.0.1:5555",
                dst1: "8.8.8.8:8888", dst2: "8.8.8.8:7777",
                make_udp: &make_udp,
                is_ipv4: true
            },
            TestInput{
                src1: "[::1]:1111", src2: "[::1]:2222",
                src3: "[::1]:3333", src4: "[::1]:4444",
                src5: "[::1]:5555",
                dst1: "[2001:4860:4860::8888]:8888",
                dst2: "[2001:4860:4860::8888]:7777",
                make_udp: &make_udp6,
                is_ipv4: false
            },
        ];
        for TestInput { src1, src2, src3, src4, src5, dst1, dst2, make_udp , is_ipv4} in test_inputs {
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, false, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
            // Should FAIL (no matching outgoing connections yet)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src1)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src2)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src3)), false);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src4)), false);
            assert_eq!(fw.conntrack.udp.lock().len(), 0);

            // Should PASS (adds 1111..4444 and drops 2222)
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src2, dst1)), is_ipv4);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
            assert_eq!(fw.conntrack.udp.lock().len(), if is_ipv4 { 2 } else { 0 });
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src3, dst1)), is_ipv4);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
            assert_eq!(fw.conntrack.udp.lock().len(), if is_ipv4 { 3 } else { 0 });
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src4, dst1)), is_ipv4);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src1, dst1)), is_ipv4);
            assert_eq!(fw.conntrack.udp.lock().len(), if is_ipv4 { 3 } else { 0 });

            // Should PASS (matching outgoing connections exist in LRUCache)
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src3)), is_ipv4);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src4)), is_ipv4);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst1, src1)), is_ipv4);

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
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
            let peer = make_peer();

            assert_eq!(fw.process_inbound_packet(&peer, &make_tcp(them, us, TcpFlags::SYN)), false);

            let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN)), true);

            let link = IpConnWithPort {
                remote_addr: test_input.them_ip(),
                remote_port: test_input.them_port(),
                local_addr: test_input.us_ip(),
                local_port: test_input.us_port(),
            };
            let tcp_key = Connection { link , associated_data: Some(peer.to_smallvec()) };

            assert_eq!(fw.conntrack.tcp.lock().get(&tcp_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: true, conn_remote_initiated: false, next_seq: Some(1), state: ConnectionState::Established
            }));

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::RST)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN)), false);
            assert_eq!(fw.conntrack.tcp.lock().len(), 0);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::FIN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::FIN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::ACK)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::PSH)), false);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::ACK)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 0);
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
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),]);
            let peer = make_peer();

            let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);
            assert_eq!(fw.process_outbound_packet(&peer, &outgoing_init_packet), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
            let link = IpConnWithPort {
                remote_addr: test_input.them_ip(),
                remote_port: test_input.them_port(),
                local_addr: test_input.us_ip(),
                local_port: test_input.us_port(),
            };
            let conn_key = Connection { link , associated_data: Some(peer.to_smallvec()) };

            assert_eq!(fw.conntrack.tcp.lock().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: true, conn_remote_initiated: false, next_seq: None, state: ConnectionState::New
            }));

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::FIN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);

            assert_eq!(fw.conntrack.tcp.lock().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: false, conn_remote_initiated: false, next_seq: Some(12), state: CtkConnectionState::Established
            }));

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::FIN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);

            assert_eq!(fw.conntrack.tcp.lock().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: false, rx_alive: false, conn_remote_initiated: false, next_seq: Some(12), state: CtkConnectionState::Closed
            }));

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::ACK)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 0);
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
            let fw = StatefullFirewall::new_custom(3, ttl, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),]);
            let peer = make_peer();

            let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &outgoing_init_packet), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
            let link = IpConnWithPort {
                remote_addr: test_input.them_ip(),
                remote_port: test_input.them_port(),
                local_addr: test_input.us_ip(),
                local_port: test_input.us_port(),
            };
            let conn_key = Connection { link , associated_data: Some(peer.to_smallvec()) };

            assert_eq!(fw.conntrack.tcp.lock().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: true, conn_remote_initiated: false, next_seq: None, state: CtkConnectionState::New
            }));

            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::FIN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);

            assert_eq!(fw.conntrack.tcp.lock().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: true, rx_alive: false, conn_remote_initiated: false, next_seq: Some(12), state: CtkConnectionState::Established
            }));

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(us, them, TcpFlags::FIN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);

            // update tcp cache entry timeout
            assert_eq!(fw.conntrack.tcp.lock().get(&conn_key), Some(&TcpConnectionInfo{
                tx_alive: false, rx_alive: false, conn_remote_initiated: false, next_seq: Some(12), state: CtkConnectionState::Closed
            }));

            // process inbound packet (should not update ttl, because not ACK, but entry should still exist)
            advance_time(Duration::from_millis(ttl / 2));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::PSH)), false);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);

            // process inbound packet (should not update ttl, because not ACK, and entry should be removed after timeout)
            advance_time(Duration::from_millis(ttl / 2 + 1));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(them, us, TcpFlags::PSH)), false);
            assert_eq!(fw.conntrack.tcp.lock().len(), 0);
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
            let fw = StatefullFirewall::new_custom(2, LRU_TIMEOUT, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),]);

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
            let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &FeatureFirewall::default());
            fw.set_ip_addresses(vec![StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),]);

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

        const V4_DST_IP: &str = "8.8.8.8";
        const V4_SRC_IP: &str = "127.0.0.1";

        const V6_DST_IP: &str = "2001:4860:4860::8888";
        const V6_SRC_IP: &str = "::1";

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

                    let fw = StatefullFirewall::new_custom(
                        LRU_CAPACITY,
                        LRU_TIMEOUT,
                        true,
                        &FeatureFirewall::default(),
                    );
                    fw.set_ip_addresses(vec![
                        StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                        StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    ]);
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
        for TestInput(dst, src, request_type, error_type, make_icmp) in [
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
            let fw = StatefullFirewall::new_custom(
                LRU_CAPACITY,
                LRU_TIMEOUT,
                true,
                &FeatureFirewall::default(),
            );
            fw.set_ip_addresses(vec![
                StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);

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
            dst,
            dst_with_port,
            src2,
            src2_with_port,
            src1,
            src1_with_port,
            error_type,
            make_tcp,
            make_icmp,
        ) in [
            TestInput(
                "8.8.8.8",
                "8.8.8.8:8888",
                "127.0.0.1",
                "127.0.0.1:4444",
                "127.0.0.1",
                "127.0.0.1:1111",
                IcmpTypes::DestinationUnreachable.into(),
                &make_tcp,
                &make_icmp4_with_body,
            ),
            TestInput(
                "2001:4860:4860::8888",
                "[2001:4860:4860::8888]:8888",
                "2001:4860:4860::8844",
                "[2001:4860:4860::8844]:4444",
                "::1",
                "[::1]:1111",
                Icmpv6Types::DestinationUnreachable.into(),
                &make_tcp6,
                &make_icmp6_with_body,
            ),
        ] {
            let fw = StatefullFirewall::new_custom(
                LRU_CAPACITY,
                LRU_TIMEOUT,
                true,
                &FeatureFirewall::default(),
            );
            fw.set_ip_addresses(vec![
                StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);

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
            dst,
            dst_with_port,
            src2,
            src2_with_port,
            src1,
            src1_with_port,
            error_type,
            make_udp,
            make_icmp,
        ) in [
            TestInput(
                "8.8.8.8",
                "8.8.8.8:8888",
                "127.0.0.1",
                "127.0.0.1:4444",
                "127.0.0.1",
                "127.0.0.1:1111",
                IcmpTypes::DestinationUnreachable.into(),
                &make_udp,
                &make_icmp4_with_body,
            ),
            TestInput(
                "2001:4860:4860::8888",
                "[2001:4860:4860::8888]:8888",
                "2001:4860:4860::8844",
                "[2001:4860:4860::8844]:4444",
                "::1",
                "[::1]:1111",
                Icmpv6Types::DestinationUnreachable.into(),
                &make_udp6,
                &make_icmp6_with_body,
            ),
        ] {
            let fw = StatefullFirewall::new_custom(
                LRU_CAPACITY,
                LRU_TIMEOUT,
                true,
                &FeatureFirewall::default(),
            );
            fw.set_ip_addresses(vec![
                StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);

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
            let fw = StatefullFirewall::new_custom(0, LRU_TIMEOUT, true, &FeatureFirewall::default(),);

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
    fn outgoing_blacklist() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_udp: MakeUdp,
            make_tcp: MakeTcp,
        }

        let test_inputs = vec![
            TestInput{ src: "127.0.0.1:1111", dst: "8.8.8.8:8888",                make_udp: &make_udp,  make_tcp: &make_tcp },
            TestInput{ src: "[::1]:1111",     dst: "[2001:4860:4860::8888]:8888", make_udp: &make_udp6, make_tcp: &make_tcp6 },
        ];

        let blacklist = vec![
            FirewallBlacklistTuple {protocol: IpProtocol::UDP, ip: "8.8.8.8".parse().unwrap(), port: 8888},
            FirewallBlacklistTuple {protocol: IpProtocol::UDP, ip: "2001:4860:4860::8888".parse().unwrap(), port: 8888 },
            FirewallBlacklistTuple {protocol: IpProtocol::TCP, ip: "8.8.8.8".parse().unwrap(), port: 8888},
            FirewallBlacklistTuple {protocol: IpProtocol::TCP, ip: "2001:4860:4860::8888".parse().unwrap(), port: 8888 }
        ];

        for TestInput { src, dst, make_udp, make_tcp } in test_inputs {
            let fw = StatefullFirewall::new_custom(3, 100, true, &FeatureFirewall {
                outgoing_blacklist: blacklist.clone(),
                ..Default::default()
            },);
            fw.set_ip_addresses(vec![
                StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src, dst)), false);
            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_tcp(src, dst, 0)), false);
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
            let fw = StatefullFirewall::new_custom(3, 100, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![
                StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);

            assert_eq!(fw.process_outbound_packet(&make_peer(), &make_udp(src, dst)), true);
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), true);
            advance_time(Duration::from_millis(200));
            assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(dst, src)), false);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_pinhole_timeout_extending() {
        let capacity = 3;
        let ttl = 20;

        struct TestInput { src: &'static str, dst: &'static str, make_udp: MakeUdp, }
        let test_inputs = vec![
            TestInput{ src: "[::1]:1111",     dst: "[2001:4860:4860::8888]:8888",  make_udp: &make_udp6, },
            TestInput{ src: "127.0.0.1:1111", dst: "8.8.8.8:8888",                 make_udp: &make_udp, },
        ];

        for TestInput { src, dst, make_udp } in test_inputs {
            let fw = StatefullFirewall::new_custom(capacity, ttl, true, &FeatureFirewall::default(),);

            fw.set_ip_addresses(vec![
                StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);

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
        let fw = StatefullFirewall::new_custom(LRU_CAPACITY,LRU_TIMEOUT,true, &FeatureFirewall::default(),);
        assert!(fw.get_peer_whitelist(Permissions::IncomingConnections).is_empty());

        let peer = make_random_peer();
        fw.add_to_peer_whitelist(peer, Permissions::IncomingConnections);
        fw.add_to_peer_whitelist(make_random_peer(), Permissions::IncomingConnections);
        assert_eq!(fw.get_peer_whitelist(Permissions::IncomingConnections).len(), 2);

        fw.remove_from_peer_whitelist(peer, Permissions::IncomingConnections);
        assert_eq!(fw.get_peer_whitelist(Permissions::IncomingConnections).len(), 1);

        fw.clear_peer_whitelists();
        assert!(fw.get_peer_whitelist(Permissions::IncomingConnections).is_empty());
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

        for TestInput { src1, src2, src3, src4, src5, dst1, dst2, make_udp, make_tcp, make_icmp } in &test_inputs {
                let expected = [(0,0), (1,1)];
                let mut feature = FeatureFirewall::default();
                feature.neptun_reset_conns = true;
                let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &feature);
                fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
                let peer1 = make_random_peer();
                let peer2 = make_random_peer();

                assert!(fw.get_peer_whitelist(Permissions::IncomingConnections).is_empty());

                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp(src1, dst1,)), false);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp(src2, dst1,)), false);
                assert_eq!(expected[0], fw.get_state(), "record: {}", true);

                fw.add_to_port_whitelist(peer2, 1111);
                assert_eq!(fw.get_port_whitelist().len(), 1);

                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp(src1, dst1,)), false);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp(src2, dst1,)), true);
                assert_eq!(fw.conntrack.udp.lock().len(), 1);


                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_tcp(src3, dst2, TcpFlags::SYN)), false);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp(src4, dst1, TcpFlags::SYN | TcpFlags::ACK)), true);
                assert_eq!(fw.conntrack.tcp.lock().len(), 0);
                // only this one should be added to cache
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp(src5, dst1, TcpFlags::SYN)), true);
                assert_eq!(fw.conntrack.tcp.lock().len(), 1);
                assert_eq!(expected[1], fw.get_state());

                fw.add_to_peer_whitelist(peer2, Permissions::IncomingConnections);
                let src = src1.parse::<StdSocketAddr>().unwrap().ip().to_string();
                let dst = dst1.parse::<StdSocketAddr>().unwrap().ip().to_string();
                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_icmp(&src, &dst, IcmpTypes::EchoRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_icmp(&src, &dst, IcmpTypes::EchoRequest.into())), true);
                assert_eq!(expected[1], fw.get_state());
            }
    }

    #[rustfmt::skip]
    #[test]
    fn firewall_vpn_peer() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            dst1: &'static str,
            make_udp: MakeUdp,
            make_tcp: MakeTcp,
        }
        let test_inputs = vec![
            TestInput {
                src1: "100.100.100.100:1234",
                src2: "100.100.100.100:1000",
                dst1: "127.0.0.1:1111",
                make_udp: &make_udp,
                make_tcp: &make_tcp,
            },
            TestInput {
                src1: "[2001:4860:4860::8888]:1234",
                src2: "[2001:4860:4860::8888]:1000",
                dst1: "[::1]:1111",
                make_udp: &make_udp6,
                make_tcp: &make_tcp6,
            }
        ];
        let synack : u8 = TcpFlags::SYN | TcpFlags::ACK;
        let syn : u8 = TcpFlags::SYN;
            for TestInput { src1, src2, dst1, make_udp, make_tcp } in &test_inputs {
                let expected = [(0,0), (1,1), (1,0)];
                let mut feature = FeatureFirewall::default();
                let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &feature);
                fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
                let peer1 = make_random_peer();
                let peer2 = make_random_peer();

                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp(src1, dst1,)), false);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp(src2, dst1,)), false);
                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_tcp(src1, dst1, synack)), false);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp(src2, dst1, synack)), false);
                assert_eq!(expected[0], fw.get_state());

                fw.add_vpn_peer(peer1);
                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp(src1, dst1,)), true);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp(src2, dst1,)), false);

                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_tcp(src1, dst1, syn)), true);
                assert_eq!(fw.process_outbound_packet(&peer1.0, &make_tcp(dst1, src1, synack)), true);

                assert_eq!(expected[1], fw.get_state());

                fw.remove_vpn_peer();
                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_udp(src1, dst1,)), false);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_udp(src2, dst1,)), false);
                assert_eq!(fw.process_inbound_packet(&peer1.0, &make_tcp(src1, dst1, 0)), true);
                assert_eq!(fw.process_inbound_packet(&peer2.0, &make_tcp(src2, dst1, 0)), false);
                assert_eq!(expected[2], fw.get_state());
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

        let expected = (0,0);
        for TestInput { us, them, make_icmp, is_v4 } in &test_inputs {
            let mut feature = FeatureFirewall::default();
            // Set number of conntrack entries to 0 to test only the whitelist
            let fw = StatefullFirewall::new_custom(0, 20, true, &feature);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);

            let peer = make_random_peer();
            assert_eq!(fw.process_outbound_packet(&peer.0, &make_icmp(us, them, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoReply.into())), false);

            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoRequest.into())), false);
            if *is_v4 {
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::Timestamp.into())), false);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::InformationRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::AddressMaskRequest.into())), false);
            }
            assert_eq!(expected, fw.get_state());

            fw.add_to_peer_whitelist(peer, Permissions::IncomingConnections);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoRequest.into())), true);
            assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp(them, us, IcmpTypes::EchoReply.into())), true);
            if *is_v4 {
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::Timestamp.into())), true);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::InformationRequest.into())), true);
                assert_eq!(fw.process_inbound_packet(&peer.0, &make_icmp4(them, us, IcmpTypes::AddressMaskRequest.into())), true);
            }
            assert_eq!(expected, fw.get_state());
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
            let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);

            let them_peer = make_random_peer();

            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), false);
            fw.add_to_port_whitelist(them_peer, 8888); // NOTE: this doesn't change anything about this test
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_udp(us, them)), true);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            assert_eq!(fw.conntrack.udp.lock().len(), 1);

            // Should PASS because we started the session
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            fw.remove_from_port_whitelist(them_peer); // NOTE: also has no impact on this test
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            assert_eq!(fw.conntrack.udp.lock().len(), 1);
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
            let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
            let them_peer = make_random_peer();

            fw.add_to_port_whitelist(them_peer,1111);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_udp(us, them)), true);
            assert_eq!(fw.conntrack.udp.lock().len(), 1);

            // The already started connection should still work
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            fw.remove_from_port_whitelist(them_peer);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_udp(them, us)), true);
            assert_eq!(fw.conntrack.udp.lock().len(), 1);
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
            let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);

            let them_peer = make_random_peer();

            fw.add_to_port_whitelist(them_peer, 8888); // NOTE: this doesn't change anything about the test
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), false);
            assert_eq!(fw.conntrack.tcp.lock().len(), 0);
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_tcp(us, them, TcpFlags::SYN)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)), true);


            // Should PASS because we started the session
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), true);
            fw.remove_from_port_whitelist(them_peer);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
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
            let fw = StatefullFirewall::new_custom(LRU_CAPACITY,LRU_TIMEOUT,true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);

            let them_peer = make_random_peer();

            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN)), false);
            fw.add_to_port_whitelist(them_peer, 1111);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, TcpFlags::SYN)), true);
            assert_eq!(fw.process_outbound_packet(&them_peer.0, &make_tcp(us, them, TcpFlags::SYN | TcpFlags::ACK)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);


            // Firewall allows already established connections
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), true);
            fw.remove_from_port_whitelist(them_peer);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
            assert_eq!(fw.process_inbound_packet(&them_peer.0, &make_tcp(them, us, 0)), true);
            assert_eq!(fw.conntrack.tcp.lock().len(), 1);
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
            let expected = [(0,0),(0,1)];
            for TestInput { src1, src2, dst, make_udp, make_tcp, make_icmp } in &test_inputs {
                let mut feature = FeatureFirewall::default();
                let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &feature);
                fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
                assert!(fw.get_peer_whitelist(Permissions::IncomingConnections).is_empty());

                let src2_ip = src2.parse::<StdSocketAddr>().unwrap().ip().to_string();
                let dst_ip = dst.parse::<StdSocketAddr>().unwrap().ip().to_string();

                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), false);
                assert_eq!(expected[0], fw.get_state());

                fw.add_to_peer_whitelist((&make_peer()).into(), Permissions::IncomingConnections);
                assert_eq!(fw.get_peer_whitelist(Permissions::IncomingConnections).len(), 1);

                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), true);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), true);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), true);
                assert_eq!(expected[1], fw.get_state());

                fw.remove_from_peer_whitelist((&make_peer()).into(), Permissions::IncomingConnections);
                assert_eq!(fw.get_peer_whitelist(Permissions::IncomingConnections).len(), 0);

                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, dst,)), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_icmp(&src2_ip, &dst_ip, IcmpTypes::EchoRequest.into())), false);
                assert_eq!(fw.process_inbound_packet(&make_peer(), &make_tcp(src2, dst, TcpFlags::PSH)), false);

                assert_eq!(expected[0], fw.get_state());
            }
    }

    #[test]
    fn firewall_test_permissions() {
        struct TestInput {
            src1: &'static str,
            src2: &'static str,
            local_dst: &'static str,
            area_dst: &'static str,
            external_dst: &'static str,
            make_udp: MakeUdp,
            make_tcp: MakeTcp,
        }
        let test_inputs = vec![
            TestInput {
                src1: "100.100.100.100:1234",
                src2: "100.100.100.101:1234",
                local_dst: "127.0.0.1:1111",
                area_dst: "192.168.0.1:1111",
                external_dst: "13.32.4.21:1111",
                make_udp: &make_udp,
                make_tcp: &make_tcp,
            },
            TestInput {
                src1: "[2001:4860:4860::8888]:1234",
                src2: "[2001:4860:4860::8844]:1234",
                local_dst: "[::1]:1111",
                area_dst: "[fe80:4860:4860::8844]:2222",
                external_dst: "[2001:4860:4860::8888]:8888",
                make_udp: &make_udp6,
                make_tcp: &make_tcp6,
            },
        ];

        let expected = [(0, 1), (0, 2), (0, 0)];
        for TestInput {
            src1,
            src2,
            local_dst,
            area_dst,
            external_dst,
            make_udp,
            make_tcp,
        } in &test_inputs
        {
            let mut feature = FeatureFirewall::default();
            feature.neptun_reset_conns = true;
            let fw = StatefullFirewall::new_custom(LRU_CAPACITY, LRU_TIMEOUT, true, &feature);
            fw.set_ip_addresses(vec![
                StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);
            assert!(fw
                .get_peer_whitelist(Permissions::IncomingConnections)
                .is_empty());
            assert!(fw
                .get_peer_whitelist(Permissions::RoutingConnections)
                .is_empty());
            assert!(fw
                .get_peer_whitelist(Permissions::LocalAreaConnections)
                .is_empty());

            // No permissions. Incoming packet should FAIL
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, local_dst,)));
            assert!(
                !fw.process_inbound_packet(&make_peer(), &make_tcp(src1, local_dst, TcpFlags::PSH))
            );

            // Allow incoming connection
            fw.add_to_peer_whitelist((&make_peer()).into(), Permissions::IncomingConnections);
            assert_eq!(
                fw.get_peer_whitelist(Permissions::IncomingConnections)
                    .len(),
                1
            );

            // Packet destined for local node
            assert!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, local_dst,)));
            assert!(
                fw.process_inbound_packet(&make_peer(), &make_tcp(src1, local_dst, TcpFlags::PSH))
            );
            // Packet destined for foreign node but within local area. Should FAIL
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, area_dst,)));
            assert!(
                !fw.process_inbound_packet(&make_peer(), &make_tcp(src1, area_dst, TcpFlags::PSH))
            );
            // Packet destined for totally external node. Should FAIL
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, external_dst,)));
            assert!(!fw.process_inbound_packet(
                &make_peer(),
                &make_tcp(src1, external_dst, TcpFlags::PSH)
            ));
            assert_eq!(expected[0], fw.get_state(),);

            // Allow local area connections
            fw.add_to_peer_whitelist((&make_peer()).into(), Permissions::LocalAreaConnections);
            assert_eq!(
                fw.get_peer_whitelist(Permissions::LocalAreaConnections)
                    .len(),
                1
            );
            // Packet destined for foreign node but within local area
            assert!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, area_dst,)));
            assert!(
                fw.process_inbound_packet(&make_peer(), &make_tcp(src1, area_dst, TcpFlags::PSH))
            );
            // Packet destined for totally external node. Should FAIL
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, external_dst,)));
            assert!(!fw.process_inbound_packet(
                &make_peer(),
                &make_tcp(src1, external_dst, TcpFlags::PSH)
            ));

            // Allow routing permissiongs but no local area connection
            fw.remove_from_peer_whitelist((&make_peer()).into(), Permissions::LocalAreaConnections);
            assert_eq!(
                fw.get_peer_whitelist(Permissions::LocalAreaConnections)
                    .len(),
                0
            );
            // The old connections are still tracked
            assert_eq!(expected[1], fw.get_state(),);

            fw.add_to_peer_whitelist((&make_peer()).into(), Permissions::RoutingConnections);
            assert_eq!(
                fw.get_peer_whitelist(Permissions::RoutingConnections).len(),
                1
            );
            // Packet destined for foreign node but within local area. Should FAIL
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, area_dst,)));
            assert!(
                !fw.process_inbound_packet(&make_peer(), &make_tcp(src1, area_dst, TcpFlags::PSH))
            );
            // Packet destined for totally external node
            assert!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, external_dst,)));
            assert!(fw.process_inbound_packet(
                &make_peer(),
                &make_tcp(src1, external_dst, TcpFlags::PSH)
            ));

            // We have one new connection entry
            assert_eq!(expected[1], fw.get_state(),);

            // Allow only routing
            fw.remove_from_peer_whitelist((&make_peer()).into(), Permissions::IncomingConnections);
            assert_eq!(
                fw.get_peer_whitelist(Permissions::IncomingConnections)
                    .len(),
                0
            );

            // Packet destined for local node. Should FAIL
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, local_dst,)));
            assert!(
                !fw.process_inbound_packet(&make_peer(), &make_tcp(src1, local_dst, TcpFlags::PSH))
            );
            // Packet destined for totally external node
            assert!(fw.process_inbound_packet(&make_peer(), &make_udp(src1, external_dst,)));
            assert!(fw.process_inbound_packet(
                &make_peer(),
                &make_tcp(src1, external_dst, TcpFlags::PSH)
            ));

            // Now we should have only the entry for external destinations
            assert_eq!(expected[0], fw.get_state(),);
            fw.remove_from_peer_whitelist((&make_peer()).into(), Permissions::RoutingConnections);
            assert_eq!(
                fw.get_peer_whitelist(Permissions::RoutingConnections).len(),
                0
            );

            // All packets should FAIL
            // Packet destined for local node
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, local_dst,)));
            assert!(
                !fw.process_inbound_packet(&make_peer(), &make_tcp(src1, local_dst, TcpFlags::PSH))
            );
            // Packet destined for foreign node but within local area
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, area_dst,)));
            assert!(
                !fw.process_inbound_packet(&make_peer(), &make_tcp(src1, area_dst, TcpFlags::PSH))
            );
            // Packet destined for totally external node
            assert!(!fw.process_inbound_packet(&make_peer(), &make_udp(src1, external_dst,)));
            assert!(!fw.process_inbound_packet(
                &make_peer(),
                &make_tcp(src1, external_dst, TcpFlags::PSH)
            ));
            assert_eq!(expected[2], fw.get_state(),);
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
            let fw = StatefullFirewall::new_custom(LRU_CAPACITY,LRU_TIMEOUT,true, &FeatureFirewall::default(),);
            fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))), StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]);
            assert!(fw.get_peer_whitelist(Permissions::IncomingConnections).is_empty());
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

    #[test]
    fn firewall_tcp_conns_reset() {
        let fw = StatefullFirewall::new_custom(
            LRU_CAPACITY,
            LRU_TIMEOUT,
            true,
            &FeatureFirewall::default(),
        );
        fw.set_ip_addresses(vec![
            StdIpv4Addr::LOCALHOST.into(),
            StdIpv6Addr::LOCALHOST.into(),
        ]);
        let peer = make_peer();
        fw.add_to_port_whitelist(PublicKey(peer), FILE_SEND_PORT);

        // Outbound half opened connection
        assert!(fw.process_outbound_packet(
            &peer,
            &make_tcp("127.0.0.1:12345", "104.104.104.104:54321", TcpFlags::SYN),
        ));
        // Outbound opened connection
        assert!(fw.process_outbound_packet(
            &peer,
            &make_tcp("127.0.0.1:12345", "103.103.103.103:54321", TcpFlags::SYN),
        ));
        assert!(fw.process_inbound_packet(
            &peer,
            &make_tcp(
                "103.103.103.103:54321",
                "127.0.0.1:12345",
                TcpFlags::SYN | TcpFlags::ACK
            ),
        ));
        // Inbound connection
        assert!(fw.process_inbound_packet(
            &peer,
            &make_tcp(
                "100.100.100.100:12345",
                &format!("127.0.0.1:{FILE_SEND_PORT}"),
                TcpFlags::SYN
            ),
        ));
        // Inbound with data
        assert!(fw.process_inbound_packet(
            &peer,
            &make_tcp(
                "102.102.102.102:12345",
                &format!("127.0.0.1:{FILE_SEND_PORT}"),
                TcpFlags::SYN
            ),
        ));
        assert!(fw.process_inbound_packet(
            &peer,
            &make_tcp(
                "102.102.102.102:12345",
                &format!("127.0.0.1:{FILE_SEND_PORT}"),
                TcpFlags::PSH
            ),
        ));
        // Outbound IPv6 opened connection
        assert!(fw.process_outbound_packet(
            &peer,
            &make_tcp6("[::1]:12345", "[1234::2]:54321", TcpFlags::SYN),
        ));
        assert!(fw.process_inbound_packet(
            &peer,
            &make_tcp6(
                "[1234::2]:54321",
                "[::1]:12345",
                TcpFlags::SYN | TcpFlags::ACK
            ),
        ));
        // Inbound IPv6 connection
        assert!(fw.process_inbound_packet(
            &peer,
            &make_tcp6(
                "[4321::2]:54321",
                &format!("[::1]:{FILE_SEND_PORT}"),
                TcpFlags::SYN
            ),
        ));

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
        fw.reset_connections(&PublicKey(peer), &mut sink);

        // Connections are stored in LinkedHashMap which keeps insertion order
        assert_eq!(sink.pkgs.len(), 5);

        let mut ippkgs: Vec<_> = sink
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

        let mut ip6pkgs: Vec<_> = sink
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
        let fw = StatefullFirewall::new_custom(
            LRU_CAPACITY,
            LRU_TIMEOUT,
            true,
            &FeatureFirewall::default(),
        );
        let peer = make_peer();
        fw.add_to_port_whitelist(PublicKey(peer), FILE_SEND_PORT);

        let test_udppkg = make_udp("127.0.0.2:12345", "127.0.0.3:54321");
        let test_udp6pkg = make_udp6("[::2]:12345", "[::3]:54321");
        // Outbound connections
        assert!(fw.process_outbound_packet(&peer, &test_udppkg,));
        assert!(fw.process_outbound_packet(&peer, &test_udp6pkg,));

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
        fw.reset_connections(&PublicKey(peer), &mut sink);

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

    #[test]
    fn firewall_icmp_ddos_vulnerability() {
        let dst1 = "8.8.8.8:8888";
        let dst2 = "8.8.8.8";
        let src1 = "127.0.0.1:2000";
        let src2 = "127.0.0.1";

        let fw = StatefullFirewall::new_custom(2, LRU_TIMEOUT, false, &FeatureFirewall::default());
        fw.set_ip_addresses(vec![(StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1)))]);
        let good_peer = make_random_peer();
        let bad_peer = make_random_peer();

        let tcp_syn_outbound = make_tcp(src1, dst1, TcpFlags::SYN);
        let tcp_synack_inbound = make_tcp(dst1, src1, TcpFlags::SYN | TcpFlags::ACK);

        let udp_outbound = make_udp(src1, dst1);
        let udp_inbound = make_udp(dst1, src1);

        let mut data = vec![1, 0, 0, 1];
        let tcp = make_tcp(src1, dst1, TcpFlags::ACK);
        data.extend_from_slice(&tcp);

        let icmp_tcp_error_inbound =
            make_icmp4_with_body(dst2, src2, IcmpTypes::DestinationUnreachable.into(), &data);

        // tcp & udp outbound: allowed
        assert!(fw.process_outbound_packet(&good_peer.0, &tcp_syn_outbound));
        // inject error package from bad peer
        assert!(!fw.process_inbound_packet(&bad_peer.0, &icmp_tcp_error_inbound));
        // expect that connection continues normally
        assert!(fw.process_inbound_packet(&good_peer.0, &tcp_synack_inbound));
    }

    #[test]
    fn firewall_tcp_rst_attack_vulnerability() {
        let us = "127.0.0.1:1111";
        let them = "8.8.8.8:8888";
        let random = "192.168.0.1:7777";

        let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, false, &Default::default());
        fw.set_ip_addresses(vec![
            (StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))),
            StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ]);
        let outgoing_init_packet = make_tcp(us, them, TcpFlags::SYN);
        let incoming_rst_packet = make_tcp(them, us, TcpFlags::RST);

        let peer_bad = make_random_peer();
        let peer_good = make_peer();

        assert!(fw.process_outbound_packet(&peer_good, &outgoing_init_packet),);
        assert!(!fw.process_inbound_packet(&peer_bad.0, &incoming_rst_packet),);
        assert!(fw.process_inbound_packet(
            &peer_good,
            &make_tcp(them, us, TcpFlags::SYN | TcpFlags::ACK)
        ),);
        assert!(fw.process_inbound_packet(&peer_good, &make_tcp(them, us, TcpFlags::SYN)),);
    }

    #[test]
    fn firewall_udp_spoffing_and_injection_vulnerability() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_udp: MakeUdp,
        }

        let test_inputs = [
            TestInput {
                src: "127.0.0.1:1111",
                dst: "8.8.8.8:8888",
                make_udp: &make_udp,
            },
            TestInput {
                src: "[::1]:1111",
                dst: "[2001:4860:4860::8888]:8888",
                make_udp: &make_udp6,
            },
        ];

        let expected = (0, 1);
        for TestInput { src, dst, make_udp } in &test_inputs {
            let mut feature = FeatureFirewall::default();
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &feature);
            fw.set_ip_addresses(vec![
                (StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);
            let outgoing_packet = make_udp(src, dst);
            let incoming_packet = make_udp(dst, src);

            let peer_bad = make_random_peer();
            let peer_good = make_random_peer();

            assert_eq!((0, 0), fw.get_state());
            fw.add_to_peer_whitelist(peer_good, Permissions::IncomingConnections);
            fw.add_to_port_whitelist(peer_good, 1111);

            // Should Pass as it is inbound for trusted peer
            assert!(fw.process_inbound_packet(&peer_good.0, &incoming_packet),);
            assert!(fw.process_outbound_packet(&peer_good.0, &outgoing_packet),);

            // Should FAIL as it is a spoofed package
            assert!(!fw.process_inbound_packet(&peer_bad.0, &incoming_packet),);

            // Good peers should still communicate normaly
            assert!(fw.process_inbound_packet(&peer_good.0, &incoming_packet),);
            assert!(fw.process_outbound_packet(&peer_good.0, &outgoing_packet),);
            assert_eq!(expected, fw.get_state());
        }
    }

    #[test]
    fn firewall_remote_initiated_tcp_reaches_established_after_outbound_synack() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_tcp: MakeTcp,
        }

        let test_inputs = [
            TestInput {
                src: "127.0.0.1:1111",
                dst: "8.8.8.8:8888",
                make_tcp: &make_tcp,
            },
            TestInput {
                src: "[::1]:1111",
                dst: "[2001:4860:4860::8888]:8888",
                make_tcp: &make_tcp6,
            },
        ];
        let peer = make_peer();
        let mut features = FeatureFirewall::default();
        features.neptun_reset_conns = true;

        for TestInput { src, dst, make_tcp } in test_inputs {
            let remote = std::net::SocketAddr::from_str(dst).unwrap();
            let local = std::net::SocketAddr::from_str(src).unwrap();
            let key = Connection {
                link: IpConnWithPort {
                    remote_addr: remote.ip().into(),
                    remote_port: remote.port(),
                    local_addr: local.ip().into(),
                    local_port: local.port(),
                },
                associated_data: Some(peer.to_smallvec()),
            };

            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &features);
            fw.add_vpn_peer(PublicKey::new(peer));

            assert!(fw.process_inbound_packet(&peer, &make_tcp(dst, src, TcpFlags::SYN)));
            assert_eq!(
                fw.conntrack.tcp.lock().get(&key).unwrap().state,
                CtkConnectionState::New
            );
            assert!(fw.process_outbound_packet(
                &peer,
                &make_tcp(src, dst, TcpFlags::SYN | TcpFlags::ACK)
            ));

            assert_eq!(
                fw.conntrack.tcp.lock().get(&key).unwrap().state,
                CtkConnectionState::Established
            );
        }
    }

    #[test]
    fn firewall_remote_initiated_tcp_stays_in_new_if_no_outbound_synack() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_tcp: MakeTcp,
        }

        let test_inputs = [
            TestInput {
                src: "127.0.0.1:1111",
                dst: "8.8.8.8:8888",
                make_tcp: &make_tcp,
            },
            TestInput {
                src: "[::1]:1111",
                dst: "[2001:4860:4860::8888]:8888",
                make_tcp: &make_tcp6,
            },
        ];

        let peer = make_peer();
        let mut features = FeatureFirewall::default();
        features.neptun_reset_conns = true;

        for outbound_flags in
            (0..u8::max_value()).filter(|flags| *flags & (TcpFlags::SYN | TcpFlags::ACK) == 0)
        {
            for TestInput { src, dst, make_tcp } in &test_inputs {
                let remote = std::net::SocketAddr::from_str(dst).unwrap();
                let local = std::net::SocketAddr::from_str(src).unwrap();
                let key = Connection {
                    link: IpConnWithPort {
                        remote_addr: remote.ip().into(),
                        remote_port: remote.port(),
                        local_addr: local.ip().into(),
                        local_port: local.port(),
                    },
                    associated_data: Some(peer.to_smallvec()),
                };
                let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &features);
                fw.add_vpn_peer(PublicKey::new(peer));

                assert!(fw.process_inbound_packet(&peer, &make_tcp(dst, src, TcpFlags::SYN)));
                assert_eq!(
                    fw.conntrack.tcp.lock().get(&key).unwrap().state,
                    CtkConnectionState::New
                );

                if fw.process_outbound_packet(&peer, &make_tcp(src, dst, outbound_flags)) {
                    if let Some(value) = fw.conntrack.tcp.lock().get(&key) {
                        assert_eq!(value.state, CtkConnectionState::New);
                    }
                }
            }
        }
    }

    #[test]
    fn firewall_locally_initiated_tcp_reaches_established_after_inbound_synack() {
        struct TestInput {
            src: &'static str,
            dst: &'static str,
            make_tcp: MakeTcp,
        }

        let test_inputs = [
            TestInput {
                src: "127.0.0.1:1111",
                dst: "8.8.8.8:8888",
                make_tcp: &make_tcp,
            },
            TestInput {
                src: "[::1]:1111",
                dst: "[2001:4860:4860::8888]:8888",
                make_tcp: &make_tcp6,
            },
        ];
        let peer = make_peer();
        let mut features = FeatureFirewall::default();

        for TestInput { src, dst, make_tcp } in test_inputs {
            let remote = std::net::SocketAddr::from_str(dst).unwrap();
            let local = std::net::SocketAddr::from_str(src).unwrap();
            let key = Connection {
                link: IpConnWithPort {
                    remote_addr: remote.ip().into(),
                    remote_port: remote.port(),
                    local_addr: local.ip().into(),
                    local_port: local.port(),
                },
                associated_data: Some(peer.to_smallvec()),
            };
            let fw = StatefullFirewall::new_custom(3, LRU_TIMEOUT, true, &features);
            fw.set_ip_addresses(vec![
                (StdIpAddr::V4(StdIpv4Addr::new(127, 0, 0, 1))),
                StdIpAddr::V6(StdIpv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]);

            assert!(fw.process_outbound_packet(&peer, &make_tcp(src, dst, TcpFlags::SYN)));
            assert_eq!(
                fw.conntrack.tcp.lock().get(&key).unwrap().state,
                CtkConnectionState::New
            );
            assert!(fw
                .process_inbound_packet(&peer, &make_tcp(dst, src, TcpFlags::SYN | TcpFlags::ACK)));

            assert_eq!(
                fw.conntrack.tcp.lock().get(&key).unwrap().state,
                CtkConnectionState::Established
            );
        }
    }
}
