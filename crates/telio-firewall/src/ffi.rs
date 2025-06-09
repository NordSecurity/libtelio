//! FFI bindings for the dynamic version of library

use core::slice;
use std::{
    convert::TryInto,
    ffi::{c_char, c_void},
    ptr::null,
};

use pnet_packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use telio_utils::telio_log_warn;

use crate::{
    chain::{Chain, LibfwChain, LibfwIpAddr, LibfwIpVersion},
    conntrack::{unwrap_option_or_return, Conntracker, LibfwDirection, LibfwVerdict},
    error::LibfwError,
    firewall::IpPacket,
};

const LRU_CAPACITY: usize = 4096; // Max entries to keep (sepatately for TCP, UDP, and others)
const LRU_TIMEOUT: u64 = 120_000; // 2min (https://datatracker.ietf.org/doc/html/rfc4787#section-4.3)

///
/// Type for firewall instance
///
pub struct LibfwFirewall {
    chain: Option<Chain>,
    conntracker: Conntracker,
    alow_ipv6: bool,
}

///
/// Log levels used in LibfwLogCallback
///
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum LibfwLogLevel {
    /// Trace level
    LibfwLogLevelTrace = 0,
    /// Warn level
    LibfwLogLevelDebug = 1,
    /// Debug level
    LibfwLogLevelInfo = 2,
    /// Warn level
    LibfwLogLevelWarn = 3,
    /// Error level
    LibfwLogLevelErr = 4,
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
///
pub type LibfwInjectPacketCallback =
    Option<extern "C" fn(data: *mut c_void, packet: *const u8, packet_len: usize) -> LibfwError>;

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
    Box::into_raw(Box::new(LibfwFirewall {
        chain: None,
        conntracker: Conntracker::new(LRU_CAPACITY, LRU_TIMEOUT),
        alow_ipv6: false,
    }))
}

///
/// Configures chain of rules for the firewall to follow.
///
/// The provided chain will be copied and won't be modified in any way. The library
/// won't try to deallocate it, so freeing the memory after using this chain is the
/// user's responsibility.
///
/// @param fw - pointer returned by @ref libfw_init
/// @param chain - chain of the firewall rules
///
/// # Safety
///
/// This function dereferences pointer to firewall - user must ensure that this is
/// the pointer returned by `libfw_init`.
#[no_mangle]
pub unsafe extern "C" fn libfw_configure_chain(
    firewall: *mut LibfwFirewall,
    chain: LibfwChain,
) -> LibfwError {
    // TODO: Check if the chain is valid
    match (&chain).try_into() {
        Ok(chain) => {
            (*firewall).chain = Some(chain);
            LibfwError::LibfwSuccess
        }
        Err(err) => err,
    }
}

///
/// Retrieves currently configured chain of firewall rules.
///
/// The returned chain should be used only as read-only and should be freed only using
/// `libfw_cleanup_dumped_chain` - it might not be compatible with your allocator and thus
/// trying to deallocate it in any other way may lead to severe memory problems.
///
/// @param fw - pointer to initialized firewall
/// @param output - output parameter, returns currently configured chain
///
/// # Safety
///
/// This function dereferences pointer to firewall - user must ensure that this is
/// the pointer returned by `libfw_init`.
#[no_mangle]
pub unsafe extern "C" fn libfw_dump_chain(firewall: *mut LibfwFirewall) -> *const LibfwChain {
    if firewall.is_null() {
        return null();
    }

    if let Some(chain) = unsafe { &(*firewall).chain } {
        Box::into_raw(Box::new(chain.into()))
    } else {
        null()
    }
}

///
/// Frees chain dumped with `libfw_dump_chain` (it shouldn't be used on any other chain instances, though!)
///
/// @param chain - chain to be freed
///
/// # Safety
///
/// Dereferences a raw pointer to the chain, assuming that the provided chain is obtained with
/// calling `libfw_dump_chain` function - calling it on user-allocated chain, or any other pointer
/// causes undefined behavior.
///
#[no_mangle]
pub unsafe extern "C" fn libfw_cleanup_dumped_chain(chain: *const LibfwChain) {
    if chain.is_null() {
        return;
    }

    let _ = Box::from_raw(chain as *mut LibfwChain);
}

///
/// A function which triggers stale connection closing
///
/// @param fw - pointer returned by @ref libfw_init
/// @param associated_ip -
/// @param associated_data - data associated with connections to be closed,
///                          typically peer public key
/// @param associated_data_len - len of the associated data
/// @param inject_packet_cb_data - a pointer which will be passed in the
///                                inject_packet callback unmodified
/// @param inject_packet_cb - callback which will be used by libfw to inject
///                           packets into virtual tunnel interface
///
/// # Safety
///
/// This function dereferences pointer to firewall - user must ensure that this is
/// the pointer returned by `libfw_init`.
#[no_mangle]
pub unsafe extern "C" fn libfw_trigger_stale_connection_close(
    firewall: *mut LibfwFirewall,
    associated_ip: LibfwIpAddr,
    associated_data: *const u8,
    associated_data_len: usize,
    inject_packet_cb_data: *mut c_void,
    inject_packet_cb: LibfwInjectPacketCallback,
) -> LibfwError {
    if let Some(callback) = inject_packet_cb {
        if let LibfwIpVersion::LibfwIptypeIpv4 = associated_ip.ip_version {
            let assoc_data = slice::from_raw_parts(associated_data, associated_data_len);
            let conntrack = &(*firewall).conntracker;
            if let Err(err) = conntrack.reset_tcp_conns(assoc_data, |packet| {
                callback(inject_packet_cb_data, packet.as_ptr(), packet.len()).into()
            }) {
                return Err(err).into();
            }
            if let Err(err) = conntrack.reset_udp_conns(assoc_data, |packet| {
                callback(inject_packet_cb_data, packet.as_ptr(), packet.len()).into()
            }) {
                return Err(err).into();
            }
            LibfwError::LibfwSuccess
        } else {
            LibfwError::LibfwErrorNotImplemented
        }
    } else {
        LibfwError::LibfwErrorNullPointer
    }
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
/// # Safety
///
/// This function dereferences pointer to firewall - user must ensure that this is
/// the pointer returned by `libfw_init` - and also `packet` and `associated_data`
/// which must be allocated with valid lengts (`packet_len` and `associated_data_len`,
/// respectively).
#[no_mangle]
pub unsafe extern "C" fn libfw_process_inbound_packet(
    firewall: *mut LibfwFirewall,
    packet: *mut u8,
    packet_len: usize,
    associated_data: *mut u8,
    associated_data_len: usize,
) -> LibfwVerdict {
    let packet_buffer = unsafe { slice::from_raw_parts(packet, packet_len) };
    let assoc_data = unsafe { slice::from_raw_parts(associated_data, associated_data_len) };

    match unwrap_option_or_return!(packet_buffer.first(), LibfwVerdict::LibfwVerdictDrop) >> 4 {
        4 => {
            let ip = unwrap_option_or_return!(
                Ipv4Packet::try_from(packet_buffer),
                LibfwVerdict::LibfwVerdictDrop
            );
            let verdict = if let Some(chain) = &(*firewall).chain {
                chain.process_packet(
                    unsafe { &(*firewall).conntracker },
                    &ip,
                    assoc_data,
                    LibfwDirection::LibfwDirectionInbound,
                )
            } else {
                LibfwVerdict::LibfwVerdictAccept
            };

            unsafe { &(*firewall).conntracker }.handle_inbound_packet(&ip, assoc_data, verdict);

            verdict
        }
        6 if (*firewall).alow_ipv6 => {
            let ip = unwrap_option_or_return!(
                Ipv6Packet::try_from(packet_buffer),
                LibfwVerdict::LibfwVerdictDrop
            );
            let verdict = if let Some(chain) = unsafe { &(*firewall).chain } {
                chain.process_packet(
                    unsafe { &(*firewall).conntracker },
                    &ip,
                    assoc_data,
                    LibfwDirection::LibfwDirectionInbound,
                )
            } else {
                LibfwVerdict::LibfwVerdictAccept
            };

            (*firewall)
                .conntracker
                .handle_inbound_packet(&ip, assoc_data, verdict);

            verdict
        }
        version => {
            telio_log_warn!("Unexpected IP version {version} for outbound packet");
            LibfwVerdict::LibfwVerdictDrop
        }
    }
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
/// # Safety
///
/// This function dereferences pointer to firewall - user must ensure that this is
/// the pointer returned by `libfw_init` - and also `packet` and `associated_data`
/// which must be allocated with valid lengts (`packet_len` and `associated_data_len`,
/// respectively).
#[no_mangle]
pub unsafe extern "C" fn libfw_process_outbound_packet(
    firewall: *mut LibfwFirewall,
    packet: *const u8,
    packet_len: usize,
    associated_data: *const u8,
    associated_data_len: usize,
) -> LibfwVerdict {
    let packet_buffer = slice::from_raw_parts(packet, packet_len);
    let assoc_data = slice::from_raw_parts(associated_data, associated_data_len);

    match unwrap_option_or_return!(packet_buffer.first(), LibfwVerdict::LibfwVerdictDrop) >> 4 {
        4 => {
            let ip = unwrap_option_or_return!(
                Ipv4Packet::try_from(packet_buffer),
                LibfwVerdict::LibfwVerdictDrop
            );
            unsafe { &(*firewall).conntracker }.handle_outbound_packet(&ip, assoc_data);
            if let Some(chain) = &(*firewall).chain {
                chain.process_packet(
                    &(*firewall).conntracker,
                    &ip,
                    assoc_data,
                    LibfwDirection::LibfwDirectionOutbound,
                )
            } else {
                LibfwVerdict::LibfwVerdictAccept
            }
        }
        6 if unsafe { (*firewall).alow_ipv6 } => {
            let ip = unwrap_option_or_return!(
                Ipv6Packet::try_from(packet_buffer),
                LibfwVerdict::LibfwVerdictDrop
            );
            unsafe { &(*firewall).conntracker }.handle_outbound_packet(&ip, assoc_data);
            if let Some(chain) = &(*firewall).chain {
                chain.process_packet(
                    &(*firewall).conntracker,
                    &ip,
                    assoc_data,
                    LibfwDirection::LibfwDirectionOutbound,
                )
            } else {
                LibfwVerdict::LibfwVerdictAccept
            }
        }
        version => {
            telio_log_warn!("Unexpected IP version {version} for outbound packet");
            LibfwVerdict::LibfwVerdictDrop
        }
    }
}

///
/// Destructs firewall instance.
///
/// After this function returns it is guaranteed that no callbacks will
/// be called anymore.
///
/// @param fw - pointer returned by @ref libfw_init
///
/// # Safety
///
/// This function dereferences pointer to firewall - user must ensure that this is
/// the pointer returned by `libfw_init`.
#[no_mangle]
pub unsafe extern "C" fn libfw_deinit(firewall: *mut LibfwFirewall) {
    if !firewall.is_null() {
        unsafe {
            let _ = Box::from_raw(firewall);
        }
    }
}
