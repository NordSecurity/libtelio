use std::{
    ffi::{c_char, c_void},
    ptr,
};

mod conntrack;
mod instant;
mod lru_cache;
mod packet;

///
/// Type for firewall instance
///
pub struct LibfwFirewall {}

///
/// Possible verdicts for packets.
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwVerdict {
    LibfwVerdictAccept = 0,
    LibfwVerdictHandleLocally = 1,
    LibfwVerdictDrop = 2,
}

///
/// Conntracker connection states
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwConnetionState {
    LibfwConnectionStateNew = 0,
    LibfwConnectionStateEstablished = 1,
}

///
/// Packet direction
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwDirection {
    LibfwDirectionOutbound = 0,
    LibfwDirectionInbound = 1,
}

///
/// IP type
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwIpVersion {
    LibfwIptypeIpv4 = 0,
    LibfwIptypeIpv6 = 1,
}

///
/// IP data
///
#[repr(C)]
#[derive(Copy, Clone)]
pub union libfw_ip_data_t {
    ipv4_bytes: [u8; 4],
    ipv6_octets: [u8; 16],
}

///
/// IP representation
///
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LibfwIpAddr {
    ip_type: LibfwIpVersion,
    ip_data: libfw_ip_data_t,
}

///
/// Filter by subnet and port range
///
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LibfwNetworkFilter {
    network_addr: LibfwIpAddr,
    network_mask: LibfwIpAddr,
    port_range_start: u16,
    port_range_end: u16,
}

///
/// Filter by the associate data
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LibfwAssociatedData {
    associated_data: *const u8,
    associated_data_len: usize,
}

///
/// Filter types
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwFilterType {
    LibfwFilterAssociatedData = 0,
    LibfwFilterConntrackState = 1,
    LibfwFilterSrcNetwork = 2,
    LibfwFilterDstNetwork = 3,
    LibfwFilterDirection = 4,
}

///
/// Data for the certain filter type
///
#[repr(C)]
#[derive(Copy, Clone)]
pub union LibfwFilterData {
    associated_data_filter: LibfwAssociatedData,
    conntrack_state_filter: LibfwConnetionState,
    network_filter: LibfwNetworkFilter,
    direction_filter: LibfwDirection,
}

///
/// Struct describing a single Libfw filter
///
#[repr(C)]
#[derive(Clone)]
pub struct LibfwFilter {
    /// Filter may be inverted, meaning, that it is considered
    /// a match only if filter does *not* match
    inverted: bool,

    /// Defines a type of filter to match
    /// the packets against. There are a few
    /// possible filter types:
    /// * LIBFW_FILTER_ASSOCIATED_DATA - matches
    ///   packets based on their associated data.
    ///   This Normally means public key for NordLynx
    /// * LIBFW_FILTER_CONNTRACK_STATE - matches
    ///   connection tracking table state. This can be
    ///   either "new connection" or "established connection"
    /// * LIBFW_FILTER_[SRC|DST]_NETWORK - matches against
    ///   either source or destination network or IP address
    /// * LIBFW_FILTER_DIRECTION - matches either inbound or
    ///   outbound packet direction.
    filter_type: LibfwFilterType,

    /// Contains corresponding filter data
    filter: LibfwFilterData,
}

/// A definition of firewall rule it consists of filters which
/// determine whether rule applies to packet being processed.
/// And action, which determins what to do with the rule
#[repr(C)]
#[derive(Clone)]
pub struct LibfwRule {
    /// List of filters all of which match
    /// in order to consider rule's action
    filter: *const LibfwFilter,

    /// Length of the filter list
    filter_count: usize,

    /// Defines an action to be taken when filter
    /// matches packet. Generally either accept and
    /// stop processing rule chain or drop and stop
    /// processing rule chain.
    action: LibfwVerdict,
}

/// A chain of rules.
///
/// Rules are processed in order specified in the chain.
/// If _some_ rule in the chain matches and a verdict is
/// determined - the chain processing terminated.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct LibfwChain {
    /// Chain size
    rule_count: usize,

    /// List of the rules
    rules: *const LibfwRule,
}

///
/// Log levels used in LibfwLogCallback
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwLogLevel {
    LibfwLogLevelTrace = 0,
    LibfwLogLevelDebug = 1,
    LibfwLogLevelInfo = 2,
    LibfwLogLevelWarn = 3,
    LibfwLogLevelErr = 4,
}

///
/// Possible FW errors
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwError {
    LibfwSuccess,
    LibfwErrorInvalidChain,
    LibfwErrorNotImplemented,
    //... Expected to be extended during development
}

///
/// A callback type for providing logs from
/// library into VPN protocol implementation
///
/// @level - log level as defined in @LIBFW_LOG_LEVEL
/// @log_line - zero-terminated log line
///
pub type LibfwLogCallback = Option<extern "C" fn(level: LibfwLogLevel, log_line: *const c_char)>;

///
/// A callback type to enable libfirewall to
/// inject packets into VPN tunnel interface
///
/// Normally only called when stale connection
/// closing is triggered.
///
/// @param data - The same pointer as passed in @ref libfw_init. It is meant to
///              provide facilities for callback implementors to add context
///              information to the callback itself. If integrators of libfirewall
///              does not need context information - `null` may be passed in
///              @ref libfw_init
/// @param packet - byte array of IP packet
/// @param packet_len - length in bytes of IP packet in @param packet
/// @param associated_data - if associated data was passed in inbound
///                          and outbound packet processing function
///                          this field will provide the same associated
///                          data. Inteded to be used as peer identifier
///                          in case of nordlynx
/// @param associated_data_len - the length in bytes of associated data
///
pub type LibfwInjectPacketCallback = Option<
    extern "C" fn(
        data: *mut LibfwFirewall,
        packet: *const u8,
        packet_len: usize,
        associated_data: *const u8,
        associated_data_len: usize,
    ),
>;

///
/// Setup logging
///
/// Register a log callback which will receive
/// and handle all logs from libfirewall
///
/// @param min_log_level - minimum log level to produce logs. For debug builds
///                        LIBFW_TRACE is not available
/// @param log_cb - callback for logs
///
#[no_mangle]
pub extern "C" fn libfw_set_log_callback(
    _min_log_level: LibfwLogLevel,
    _log_cb: LibfwLogCallback,
) -> LibfwError {
    LibfwError::LibfwErrorNotImplemented
}

///
/// A function used to initialize libfirewall instance
///
/// @return pointer to initialized fw instance on success, NULL on failure
///
#[no_mangle]
pub extern "C" fn libfw_init() -> *mut LibfwFirewall {
    ptr::null_mut()
}

///
/// Configures chain of rules for the firewall to follow
///
/// @param fw - pointer returned by @ref libfw_init
/// @param chain - chain of the firewall rules
///
#[no_mangle]
pub extern "C" fn libfw_configure_chain(_fw: *mut LibfwFirewall, _chain: LibfwChain) -> LibfwError {
    LibfwError::LibfwErrorNotImplemented
}

///
/// Retrieves currently configured chain of firewall rules
///
/// @param fw - pointer to initialized firewall
/// @param output - output parameter, returns currenlty configured chain
///
#[no_mangle]
pub extern "C" fn libfw_dump_chain(
    _fw: *mut LibfwFirewall,
    _output: *const LibfwChain,
) -> LibfwError {
    LibfwError::LibfwErrorNotImplemented
}

///
/// A function which triggers stale connection closing
///
/// @param fw - pointer returned by @ref libfw_init
/// @param inject_packet_cb_data - a pointer which will be passed in the
///                                inject_packet callback unmodified
/// @param inject_packet_cb - callback which will be used by libfw to inject
///                           packets into virtual tunnel interface
///
#[no_mangle]
pub extern "C" fn libfw_trigger_stale_connection_close(
    _fw: *mut LibfwFirewall,
    _inject_packet_cb_data: *mut c_void,
    _inject_packet_cb: LibfwInjectPacketCallback,
) -> LibfwError {
    LibfwError::LibfwErrorNotImplemented
}

///
/// A function which processes inbound packets (coming from VPN server to device)
///
/// @param fw - pointer returned by @ref libfw_init
/// @param packet - pointer to byte array comprising of IP packet
/// @param packet_len - size of packet in bytes
/// @param associated_data - identifier of peer. Should contain peer's public key
///                          for NordLynx and be Null for other protcols
/// @param associated_data_len - size of @param associated_data in bytes
///
/// @return - returns LIBFW_VERDICT, integrators should allow packet to go through if
///           and only if function returns LIBFW_VERDICT_ACCEPT
///
#[no_mangle]
pub extern "C" fn libfw_process_inbound_packet(
    _fw: *mut LibfwFirewall,
    _packet: *mut u8,
    _packet_len: usize,
    _associated_data: *mut u8,
    _associated_data_len: usize,
) -> LibfwVerdict {
    LibfwVerdict::LibfwVerdictAccept
}

///
/// A function which processes outbound packets (coming from device to VPN server)
///
/// @param fw - pointer returned by @ref libfw_init
/// @param packet - pointer to byte array comprising of IP packet
/// @param packet_len - size of packet in bytes
/// @param associated_data - identifier of peer. Should contain peer's public key
///                          for NordLynx and be Null for other protcols
/// @param associated_data_len - size of @param associated_data in bytes
///
/// @return - returns LIBFW_VERDICT, integrators should allow packet to go through if
///           and only if function retruns LIBFW_VERDICT_ACCEPT
///
#[no_mangle]
pub extern "C" fn libfw_process_outbound_packet(
    _fw: *mut LibfwFirewall,
    _packet: *const u8,
    _packet_len: usize,
    _associated_data: *const u8,
    _associated_data_len: usize,
) -> LibfwVerdict {
    LibfwVerdict::LibfwVerdictAccept
}

///
/// Destructs firewall instance.
///
/// After this function returns it is guaranteed that
/// no callbacks will be called anymore
///
/// @param fw - pointer returned by @ref libfw_init
///
#[no_mangle]
pub extern "C" fn libfw_deinit(_fw: *mut LibfwFirewall) {}
