//! Telio firewall component used to track open connections
//! with other devices§

use core::fmt;
use enum_map::{Enum, EnumMap};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
#[cfg(not(target_vendor = "apple"))]
use libloading::library_filename;
use parking_lot::RwLock;
use pnet_packet::{
    icmp::{IcmpType, IcmpTypes},
    icmpv6::{Icmpv6Type, Icmpv6Types},
    tcp::TcpFlags,
};
use std::{
    ffi::{c_void, CString},
    fmt::Debug,
    io::{self},
    net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr},
};
use thiserror::Error;

use telio_model::{
    features::{FeatureFirewall, IpProtocol},
    tp_lite_stats::{TpLiteStatsCallback, TpLiteStatsOptions},
};
use telio_network_monitors::monitor::LocalInterfacesObserver;

use telio_crypto::PublicKey;
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};

use crate::{
    chain_helpers::{
        ConnectionState, Direction, FfiChainGuard, Filter, FilterData, NetworkFilterData,
        NextLevelProtocol, Rule,
    },
    libfirewall::{LibfwChain, LibfwFirewall, LibfwLogLevel, LibfwResult, LibfwVerdict},
    tp_lite_stats::{collect_stats, CallbackManager},
};

#[mockall_double::double]
use crate::libfirewall::Libfirewall;

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

/// Type for chain configuration function
pub(crate) type ConfigureChainFn =
    Box<dyn Fn(&FirewallConfig, &FirewallState, &[StdIpAddr]) -> FfiChainGuard + Send + Sync>;

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
pub trait Firewall: Sync + Send {
    /// Applies a new firewall state and updates the chain if it differs from current state
    fn apply_state(&self, state: FirewallState);

    /// Returns a clone of the current firewall state
    fn get_state(&self) -> FirewallState;

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
    fn process_inbound_packet(&self, public_key: &[u8; 32], buffer: &mut [u8]) -> bool;

    /// Creates packets that are supposed to kill the existing connections.
    /// The end goal here is to force the client app sockets to reconnect.
    fn reset_connections(&self, pubkey: &PublicKey, sink: &mut dyn io::Write);
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

/// Whitelist configuration for the firewall
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Whitelist {
    /// List of whitelisted source peer and destination port pairs
    pub port_whitelist: HashMap<PublicKey, u16>,
    /// Whitelisted peers of different permissions
    pub peer_whitelists: EnumMap<Permissions, HashSet<PublicKey>>,
    /// Public key of vpn peer
    pub vpn_peer: Option<PublicKey>,
}

/// Runtime state for firewall rules that can be updated dynamically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirewallState {
    /// Whitelist configuration
    pub whitelist: Whitelist,
    /// Local node ip addresses
    pub ip_addresses: Vec<StdIpAddr>,
}

/// Configuration for firewall initialization.
/// These parameters are set once during firewall creation and cannot be changed.
#[derive(Clone, Debug, PartialEq)]
pub struct FirewallConfig {
    /// Whether IPv6 traffic is allowed
    pub allow_ipv6: bool,
    /// Feature firewall configuration
    pub feature: FeatureFirewall,
}

/// Stateful packet-filter firewall.
pub struct StatefulFirewall {
    /// Firewall loaded library
    firewall_lib: Libfirewall,
    /// Libfirewall instance
    firewall: *mut LibfwFirewall,
    /// Firewall configuration set at initialization
    config: FirewallConfig,
    /// Current firewall state
    state: RwLock<FirewallState>,
    /// Last known host interface IPs reported by network monitor.
    interface_ips: RwLock<Vec<StdIpAddr>>,
    /// Chain configuration function
    configure_chain_fn: ConfigureChainFn,
    /// Callback for TP-Lite stats
    tp_lite_stats_cb: CallbackManager,
}

// Access to internal firewall structs is guarded by locks, so that should be fine
unsafe impl Sync for StatefulFirewall {}
unsafe impl Send for StatefulFirewall {}

impl LocalInterfacesObserver for StatefulFirewall {
    fn notify(&self, addrs: &[StdIpAddr]) {
        telio_log_debug!("Firewall notified about network changes: {:?}", addrs);

        *self.interface_ips.write() = addrs.to_vec();
        self.refresh_chain();
    }
}

impl Drop for StatefulFirewall {
    fn drop(&mut self) {
        unsafe {
            self.firewall_lib.libfw_deinit(self.firewall);
        }
    }
}

/// Firewall errors
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to load libfirewall
    #[error(transparent)]
    LibfirewallLoadFailed(libloading::Error),
    /// Failed to initialize firewall
    #[error("Firewall initialization failed")]
    FirewallInitFailed,
    /// Invalid TP-Lite stats collection config
    #[error("Invalid TP-Lite stats collection config")]
    InvalidTpLiteConfig,
    /// Failed to initialize TP-Lite stats collection
    #[error("TP-Lite stats collection initialization failed with error code {0}")]
    TpLiteInitFailed(LibfwResult::Type),
}

impl StatefulFirewall {
    /// Constructs firewall with libfw structure pointer
    pub fn new(use_ipv6: bool, feature: FeatureFirewall) -> Result<Self, Error> {
        Self::new_with_fn(use_ipv6, feature, Box::new(configure_chain))
    }

    /// Constructs firewall with a custom chain configuration function
    pub(crate) fn new_with_fn(
        use_ipv6: bool,
        feature: FeatureFirewall,
        configure_chain_fn: ConfigureChainFn,
    ) -> Result<Self, Error> {
        let firewall_lib = Self::load_fw_module().map_err(Error::LibfirewallLoadFailed)?;

        // Let's initialize libfirewall logging first.
        // We use TRACE level, which will be telio's level in pracice,
        // as we use telio logging macros inside.
        unsafe {
            firewall_lib
                .libfw_set_log_callback(LibfwLogLevel::LibfwLogLevelTrace, Some(log_callback));
        }

        // Create firewall instance
        let firewall = unsafe { firewall_lib.libfw_init() };
        if firewall.is_null() {
            return Err(Error::FirewallInitFailed);
        }

        let config = FirewallConfig {
            allow_ipv6: use_ipv6,
            feature,
        };

        let state = FirewallState::default();

        let result = Self {
            firewall_lib,
            firewall,
            config,
            state: RwLock::new(state.clone()),
            interface_ips: RwLock::new(Vec::new()),
            configure_chain_fn,
            tp_lite_stats_cb: CallbackManager::new(),
        };

        result.refresh_chain();

        Ok(result)
    }

    #[cfg(not(target_vendor = "apple"))]
    fn load_fw_module() -> Result<Libfirewall, libloading::Error> {
        unsafe { Libfirewall::new(library_filename("firewall")) }
    }

    #[cfg(target_vendor = "apple")]
    fn load_fw_module() -> Result<Libfirewall, libloading::Error> {
        const EXPECTED_PATH: &str = "@rpath/firewallFFI.framework/firewallFFI";
        const FALLBACK_PATH: &str = "libfirewall.dylib";

        unsafe {
            match Libfirewall::new(EXPECTED_PATH) {
                Ok(lib) => Ok(lib),
                Err(err) => {
                    telio_log_warn!(
                    "Failed to load firewall module from: {EXPECTED_PATH}, trying from: {FALLBACK_PATH}"
                );

                    // try fallback path
                    if let Ok(lib) = Libfirewall::new(FALLBACK_PATH) {
                        telio_log_warn!(
                            "Using firewall module from fallback path: {FALLBACK_PATH}"
                        );
                        return Ok(lib);
                    }

                    Err(err)
                }
            }
        }
    }

    fn refresh_chain(&self) {
        let interface_ips = self.interface_ips.read().clone();
        self.refresh_chain_with_interface_ips(&interface_ips);
    }

    fn refresh_chain_with_interface_ips(&self, interface_ips: &[StdIpAddr]) {
        let state = self.state.read().clone();
        let ffi_chain = (self.configure_chain_fn)(&self.config, &state, interface_ips);
        unsafe {
            self.firewall_lib
                .libfw_configure_chain(self.firewall, (&ffi_chain.ffi_chain) as *const LibfwChain);
        }
    }

    /// Register callback to get metrics and domains blocked by TP-Lite
    ///
    /// Requires firewall to be enabled through enable_firewall()
    ///
    /// Passing empty list of IPs will disable the collection of TP-Lite stats
    pub fn enable_tp_lite_stats_collection(
        &self,
        config: TpLiteStatsOptions,
        collect_stats_cb: Box<dyn TpLiteStatsCallback>,
    ) -> Result<(), Error> {
        let config = serde_json::to_string(&config).map_err(|err| {
            telio_log_warn!("Failed to convert TP-Lite config to json. {err:?}");
            Error::InvalidTpLiteConfig
        })?;
        let config = CString::new(config).map_err(|err| {
            telio_log_warn!("Failed to convert TP-Lite config to FFI string. {err:?}");
            Error::InvalidTpLiteConfig
        })?;
        // There can be a scenario where the old callback gets dropped, but libfw
        // tries to invoke it before we set the new callback.
        // To prevent that from happening we keep the old callback around until libfw has been updated.
        let mut old_cb = Box::new(collect_stats_cb);
        {
            let mut cb = self.tp_lite_stats_cb.callback.write();
            std::mem::swap(&mut old_cb, &mut cb);
        }
        let res = unsafe {
            self.firewall_lib.libfw_enable_tp_lite_stats_collection(
                self.firewall,
                config.as_ptr(),
                self.tp_lite_stats_cb.as_raw_ptr(),
                Some(collect_stats),
            )
        };
        match res {
            LibfwResult::LibfwSuccess => Ok(()),
            _ => {
                telio_log_warn!("Failed to init TP-Lite stats collection. Error code: {res:?}");
                Err(Error::TpLiteInitFailed(res))
            }
        }
    }

    /// Disable collection of TP-Lite stats
    pub fn disable_tp_lite_stats_collection(&self) {
        unsafe {
            self.firewall_lib
                .libfw_disable_tp_lite_stats_collection(self.firewall)
        };
    }
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

fn get_local_area_networks_filters(
    exclude_ip_range: Option<Ipv4Net>,
    local_ifs_addrs: &[StdIpAddr],
) -> Vec<Vec<Filter>> {
    // Create rules for peers with LocalAreaConnection permissions
    let ipv4_local_area_networks = [
        Ipv4Net::new_assert(StdIpv4Addr::new(10, 0, 0, 0), 8),
        Ipv4Net::new_assert(StdIpv4Addr::new(172, 16, 0, 0), 12),
        Ipv4Net::new_assert(StdIpv4Addr::new(192, 168, 0, 0), 16),
    ];

    // Include packets which are going to local IPv4 networks
    let mut ipv4_local_area_network_filters = ipv4_local_area_networks
        .map(|network| vec![dst_net_all_ports_filter(IpNet::V4(network), false)]);

    // Exclude packets from the exclude range
    if let Some(exclude_range) = exclude_ip_range {
        for local_net_filters in ipv4_local_area_network_filters.iter_mut() {
            local_net_filters.push(dst_net_all_ports_filter(IpNet::V4(exclude_range), true));
        }
    }

    let mut ipv6_local_area_network_filters = vec![
        // Include packets which are going to local network
        dst_net_all_ports_filter(
            IpNet::V6(Ipv6Net::new_assert(
                // TODO: Actually it Unique Local Address range should be (from what I found) fc00::/7,
                // but it seems that we assume (and our tests do) that it is fc00::/6
                StdIpv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
                6,
            )),
            false,
        ),
        // Exclude packets which are going to local interfaces
        dst_net_all_ports_filter(
            IpNet::V6(Ipv6Net::new_assert(
                StdIpv6Addr::new(0xfd74, 0x656c, 0x696f, 0, 0, 0, 0, 0),
                64,
            )),
            true,
        ),
    ];

    for ip in local_ifs_addrs.iter() {
        if ip.is_ipv4() {
            for local_network_filters in ipv4_local_area_network_filters.iter_mut() {
                local_network_filters.push(dst_net_all_ports_filter(IpNet::from(*ip), true));
            }
        } else {
            ipv6_local_area_network_filters.push(dst_net_all_ports_filter(IpNet::from(*ip), true));
        }
    }

    let mut result = Vec::from(ipv4_local_area_network_filters);
    result.push(ipv6_local_area_network_filters);
    result
}

/// Configures the firewall chain based on the provided configuration.
pub(crate) fn configure_chain(
    config: &FirewallConfig,
    state: &FirewallState,
    local_ifs_addrs: &[StdIpAddr],
) -> FfiChainGuard {
    let mut rules = vec![];

    // Drop all IPv6 packets when we don't allow ipv6 traffic
    const ALL_IP_V6_ADDRS: IpNet = IpNet::V6(Ipv6Net::new_assert(StdIpv6Addr::UNSPECIFIED, 0));
    if !config.allow_ipv6 {
        rules.push(Rule {
            filters: vec![dst_net_all_ports_filter(ALL_IP_V6_ADDRS, false)],
            action: LibfwVerdict::LibfwVerdictDrop,
        });
    }

    // Reject packets from blacklist
    for blacklist_entry in &config.feature.outgoing_blacklist {
        let next_level_protocol = match blacklist_entry.protocol {
            IpProtocol::UDP => NextLevelProtocol::Udp,
            IpProtocol::TCP => NextLevelProtocol::Tcp,
        };
        rules.push(Rule {
            filters: vec![
                Filter {
                    filter_data: FilterData::Direction(Direction::Outbound),
                    inverted: false,
                },
                Filter {
                    filter_data: FilterData::NextLevelProtocol(next_level_protocol),
                    inverted: false,
                },
                dst_net_all_ports_filter(IpNet::from(blacklist_entry.ip), false),
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
    if let Some(vpn_pk) = state.whitelist.vpn_peer {
        rules.push(Rule {
            filters: vec![Filter {
                filter_data: FilterData::AssociatedData(Some(vpn_pk.to_vec())),
                inverted: false,
            }],
            action: LibfwVerdict::LibfwVerdictAccept,
        });
    }

    let local_network_filters = get_local_area_networks_filters(
        config.feature.exclude_private_ip_range.map(Into::into),
        local_ifs_addrs,
    );

    #[allow(clippy::indexing_slicing)]
    for peer in state.whitelist.peer_whitelists[Permissions::LocalAreaConnections].iter() {
        for local_net in local_network_filters.iter() {
            let mut filters = vec![Filter {
                filter_data: FilterData::AssociatedData(Some(peer.to_vec())),
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
    for ip in &state.ip_addresses {
        // Accept packets for whitelisted peers
        #[allow(clippy::indexing_slicing)]
        for peer in state.whitelist.peer_whitelists[Permissions::IncomingConnections].iter() {
            rules.push(Rule {
                filters: vec![
                    Filter {
                        filter_data: FilterData::AssociatedData(Some(peer.to_vec())),
                        inverted: false,
                    },
                    dst_net_all_ports_filter(IpNet::from(*ip), false),
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
                dst_net_all_ports_filter(IpNet::from(*ip), false),
            ],
            action: LibfwVerdict::LibfwVerdictAccept,
        });

        // And packets related to them
        rules.push(Rule {
            filters: vec![
                Filter {
                    filter_data: FilterData::ConntrackState(ConnectionState::Related),
                    inverted: false,
                },
                dst_net_all_ports_filter(IpNet::from(*ip), false),
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
                dst_net_all_ports_filter(IpNet::from(*ip), false),
            ],
            action: LibfwVerdict::LibfwVerdictAccept,
        });

        // Accept packets for whitelisted ports
        for proto in [NextLevelProtocol::Tcp, NextLevelProtocol::Udp] {
            for (peer, &port) in &state.whitelist.port_whitelist {
                rules.push(Rule {
                    filters: vec![
                        Filter {
                            filter_data: FilterData::AssociatedData(Some(peer.to_vec())),
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
            filters: vec![dst_net_all_ports_filter(IpNet::from(*ip), false)],
            action: LibfwVerdict::LibfwVerdictDrop,
        });
    }

    #[allow(clippy::indexing_slicing)]
    for peer in state.whitelist.peer_whitelists[Permissions::RoutingConnections].iter() {
        rules.push(Rule {
            filters: vec![Filter {
                filter_data: FilterData::AssociatedData(Some(peer.to_vec())),
                inverted: false,
            }],
            action: LibfwVerdict::LibfwVerdictAccept,
        });
    }

    (rules.as_slice()).into()
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

impl Firewall for StatefulFirewall {
    fn apply_state(&self, new_state: FirewallState) {
        if *self.state.read() == new_state {
            return;
        }
        *self.state.write() = new_state;

        self.refresh_chain();
    }

    fn get_state(&self) -> FirewallState {
        self.state.read().clone()
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
                self.firewall_lib.libfw_process_outbound_packet(
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
    fn process_inbound_packet(&self, public_key: &[u8; 32], buffer: &mut [u8]) -> bool {
        LibfwVerdict::LibfwVerdictAccept
            == unsafe {
                self.firewall_lib.libfw_process_inbound_packet(
                    self.firewall,
                    buffer.as_mut_ptr(),
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
            self.firewall_lib.libfw_trigger_stale_connection_close(
                self.firewall,
                pubkey.as_ptr(),
                pubkey.len(),
                sink_ptr as *mut c_void,
                Some(write_to_sink),
                None,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex as ParkingLotMutex;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    impl StatefulFirewall {
        /// Creates a mock firewall for testing with provided mock library
        fn new_mock(
            use_ipv6: bool,
            feature: FeatureFirewall,
            configure_chain_fn: ConfigureChainFn,
        ) -> Self {
            let mut result = Self {
                firewall: 0x1 as *mut crate::libfirewall::LibfwFirewall,
                firewall_lib: crate::libfirewall::MockLibfirewall::default(),
                state: RwLock::new(FirewallState::default()),
                interface_ips: RwLock::new(Vec::new()),
                config: FirewallConfig {
                    allow_ipv6: use_ipv6,
                    feature,
                },
                configure_chain_fn,
                tp_lite_stats_cb: CallbackManager::new(),
            };

            result
                .get_libfirewall_mock()
                .expect_libfw_configure_chain()
                .once()
                .returning(|_, _| crate::libfirewall::LibfwResult::LibfwSuccess);

            result.refresh_chain();

            result
        }

        /// Get mutable reference to mock library for setting expectations
        fn get_libfirewall_mock(&mut self) -> &mut crate::libfirewall::MockLibfirewall {
            &mut self.firewall_lib
        }
    }

    #[test]
    fn test_notify_triggers_refresh_with_callback_addrs() {
        let captured_addrs = Arc::new(ParkingLotMutex::new(Vec::<Vec<StdIpAddr>>::new()));
        let addrs_clone = captured_addrs.clone();
        let spy_fn =
            move |_config: &FirewallConfig, _state: &FirewallState, addrs: &[StdIpAddr]| {
                addrs_clone.lock().push(addrs.to_vec());
                (Vec::<Rule>::new().as_slice()).into()
            };

        let mut firewall =
            StatefulFirewall::new_mock(true, FeatureFirewall::default(), Box::new(spy_fn));

        firewall
            .get_libfirewall_mock()
            .expect_libfw_configure_chain()
            .times(2)
            .returning(|_, _| crate::libfirewall::LibfwResult::LibfwSuccess);

        firewall
            .get_libfirewall_mock()
            .expect_libfw_deinit()
            .once()
            .returning(|_| {});

        firewall.notify(&[StdIpAddr::V4(Ipv4Addr::new(192, 168, 0, 11))]);
        firewall.notify(&[StdIpAddr::V4(Ipv4Addr::new(192, 168, 0, 12))]);

        let calls = captured_addrs.lock();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0], Vec::<StdIpAddr>::new());
        assert_eq!(
            calls[1],
            vec![StdIpAddr::V4(Ipv4Addr::new(192, 168, 0, 11))]
        );
        assert_eq!(
            calls[2],
            vec![StdIpAddr::V4(Ipv4Addr::new(192, 168, 0, 12))]
        );
    }

    #[test]
    fn test_notify_addrs_are_used_by_subsequent_refreshes() {
        let captured_addrs = Arc::new(ParkingLotMutex::new(Vec::<Vec<StdIpAddr>>::new()));
        let addrs_clone = captured_addrs.clone();
        let spy_fn =
            move |_config: &FirewallConfig, _state: &FirewallState, addrs: &[StdIpAddr]| {
                addrs_clone.lock().push(addrs.to_vec());
                (Vec::<Rule>::new().as_slice()).into()
            };

        let mut firewall =
            StatefulFirewall::new_mock(true, FeatureFirewall::default(), Box::new(spy_fn));

        firewall
            .get_libfirewall_mock()
            .expect_libfw_configure_chain()
            .times(2)
            .returning(|_, _| crate::libfirewall::LibfwResult::LibfwSuccess);

        firewall
            .get_libfirewall_mock()
            .expect_libfw_deinit()
            .once()
            .returning(|_| {});

        let notify_addrs = vec![StdIpAddr::V4(Ipv4Addr::new(192, 168, 77, 7))];
        firewall.notify(&notify_addrs);
        firewall.apply_state(FirewallState {
            ip_addresses: vec![StdIpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            ..Default::default()
        });

        assert_eq!(captured_addrs.lock().len(), 3);
        assert_eq!(captured_addrs.lock()[1], notify_addrs);
        assert_eq!(captured_addrs.lock()[2], notify_addrs);
    }
}
