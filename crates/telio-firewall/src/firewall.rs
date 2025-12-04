//! Telio firewall component used to track open connections
//! with other devices§

use core::fmt;
use enum_map::{Enum, EnumMap};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use parking_lot::RwLock;
use pnet_packet::{
    icmp::{IcmpType, IcmpTypes},
    icmpv6::{Icmpv6Type, Icmpv6Types},
    tcp::TcpFlags,
};
use smallvec::ToSmallVec;
use std::{
    ffi::c_void,
    fmt::Debug,
    io::{self},
    net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr, SocketAddr},
};

use telio_model::features::{FeatureFirewall, IpProtocol};
use telio_network_monitors::monitor::{LocalInterfacesObserver, LOCAL_ADDRS_CACHE};

use telio_crypto::PublicKey;
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};

use crate::{
    chain_helpers::{
        ConnectionState, Direction, FfiChainGuard, Filter, FilterData, NetworkFilterData,
        NextLevelProtocol, Rule,
    },
    ffi_chain::{LibfwChain, LibfwVerdict},
    libfirewall_api::{
        libfw_configure_chain, libfw_deinit, libfw_init, libfw_process_inbound_packet,
        libfw_process_outbound_packet, libfw_set_log_callback,
        libfw_trigger_stale_connection_close, LibfwFirewall,
    },
    log::LibfwLogLevel,
};

/// HashSet type used internally by firewall and returned by get_peer_whitelist
pub type HashSet<V> = rustc_hash::FxHashSet<V>;
/// HashMap type used internally by firewall and returned by get_port_whitelist
pub type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;

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
    fn reset_connections(&self, pubkey: &PublicKey, sink: &mut dyn io::Write);

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
    /// Libfirewall instance
    firewall: *mut LibfwFirewall,
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

// Access to internal firewall structs is guarded by locks, so that should be fine
unsafe impl Sync for StatefullFirewall {}
unsafe impl Send for StatefullFirewall {}

impl LocalInterfacesObserver for StatefullFirewall {
    fn notify(&self) {
        self.recreate_chain();
    }
}

impl Drop for StatefullFirewall {
    fn drop(&mut self) {
        unsafe {
            libfw_deinit(self.firewall);
        }
    }
}

impl StatefullFirewall {
    /// Constructs firewall with libfw structure pointer
    pub fn new(use_ipv6: bool, feature: &FeatureFirewall) -> Self {
        // Let's initialize libfirewall logging first.
        // We use TRACE level, which will be telio's level in pracice,
        // as we use telio logging macros inside.
        libfw_set_log_callback(LibfwLogLevel::LibfwLogLevelTrace, Some(log_callback));

        let result = Self {
            firewall: libfw_init(),
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

        // Drop all IPv6 packets when we don't allow ipv6 traffic
        const ALL_IP_V6_ADDRS: IpNet = IpNet::V6(Ipv6Net::new_assert(StdIpv6Addr::UNSPECIFIED, 0));
        if !self.allow_ipv6 {
            rules.push(Rule {
                filters: vec![Self::dst_net_all_ports_filter(ALL_IP_V6_ADDRS, false)],
                action: LibfwVerdict::LibfwVerdictDrop,
            });
        }

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
        unsafe {
            libfw_configure_chain(
                self.firewall,
                (&ffi_chain_guard.ffi_chain) as *const LibfwChain,
            )
        };
    }
}

extern "C" fn write_to_sink(
    data: *mut c_void,
    buffer: *const u8,
    buffer_len: usize,
    _assoc_data: *const u8,
    _assoc_data_len: usize,
) {
    let sink_ptr = data as *mut &mut dyn io::Write;
    let sink = unsafe { &mut (*sink_ptr) };

    let packet_data = unsafe { std::slice::from_raw_parts(buffer, buffer_len) };

    if let Err(err) = sink.write(packet_data) {
        telio_log_error!("Could not inject the packet: {:?}", err);
    }
}

extern "C" fn log_callback(level: LibfwLogLevel, log_line: *const std::ffi::c_char) {
    let log_cstr = unsafe { std::ffi::CStr::from_ptr(log_line as *mut std::os::raw::c_char) };
    let Ok(log_str) = log_cstr.to_str() else {
        telio_log_warn!("UNREADEABLE LOG");
        return;
    };
    match level {
        LibfwLogLevel::LibfwLogLevelTrace => telio_log_trace!("{}", log_str),
        LibfwLogLevel::LibfwLogLevelDebug => telio_log_debug!("{}", log_str),
        LibfwLogLevel::LibfwLogLevelInfo => telio_log_info!("{}", log_str),
        LibfwLogLevel::LibfwLogLevelWarn => telio_log_warn!("{}", log_str),
        LibfwLogLevel::LibfwLogLevelErr => telio_log_error!("{}", log_str),
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
        let sink_ptr = &sink as *const &mut dyn io::Write;
        LibfwVerdict::LibfwVerdictAccept
            == unsafe {
                libfw_process_outbound_packet(
                    self.firewall,
                    buffer.as_ptr(),
                    buffer.len(),
                    public_key as *const u8,
                    public_key.len(),
                    sink_ptr as *mut c_void,
                    Some(write_to_sink),
                )
            }
    }

    /// Checks if incoming packet should be accepted.
    /// Does not extend pinhole lifetime on success
    /// Adds new connection to cache only if ip is whitelisted
    /// Allows all icmp packets except for request types
    fn process_inbound_packet(&self, public_key: &[u8; 32], buffer: &[u8]) -> bool {
        LibfwVerdict::LibfwVerdictAccept
            == unsafe {
                libfw_process_inbound_packet(
                    self.firewall,
                    buffer.as_ptr(),
                    buffer.len(),
                    public_key as *const u8,
                    public_key.len(),
                    std::ptr::null_mut(),
                    None,
                )
            }
    }

    fn reset_connections(&self, pubkey: &PublicKey, sink: &mut dyn io::Write) {
        telio_log_debug!("Constructing connetion reset packets");
        let sink_ptr = &sink as *const &mut dyn io::Write;
        unsafe {
            libfw_trigger_stale_connection_close(
                self.firewall,
                pubkey.as_ptr(),
                pubkey.len(),
                sink_ptr as *mut c_void,
                Some(write_to_sink),
                None,
            );
        }
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

#[cfg(test)]
#[allow(missing_docs, unused)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use telio_model::features::FeatureFirewall;

    use crate::firewall::{Firewall, StatefullFirewall};

    #[test]
    fn ip_address_set_multiple_times() {
        let ip_vec = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        let new_ip_vec = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 1)),
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
}
