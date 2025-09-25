use core::slice;
use std::{ffi::c_void, ptr::null_mut};

use parking_lot::RwLock;
use pnet_packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};

use crate::{
    chain::{Chain, LibfwChain, LibfwVerdict},
    conntrack::{unwrap_option_or_return, Conntrack},
    error::LibfwError,
    log::{
        libfw_log_trace, libfw_log_warn, LibfwLogCallback, LibfwLogLevel, LOG_CALLBACK,
        MIN_LOG_LEVEL,
    },
};

mod chain;
mod conntrack;
mod error;
mod instant;
mod log;
mod lru_cache;
mod packet;

///
/// Type for firewall instance
///
pub struct LibfwFirewall {
    pub(crate) conntrack: Conntrack,
    pub(crate) chain: RwLock<Option<Chain>>,
    pub(crate) ffi_chain_copy: Option<LibfwChain>,
}

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
        data: *mut c_void,
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
pub extern "C" fn libfw_set_log_callback(min_log_level: LibfwLogLevel, log_cb: LibfwLogCallback) {
    *LOG_CALLBACK.write() = log_cb;
    *MIN_LOG_LEVEL.write() = min_log_level;
}

///
/// A function used to initialize libfirewall instance
///
/// @return pointer to initialized fw instance on success, NULL on failure
///
#[no_mangle]
pub extern "C" fn libfw_init() -> *mut LibfwFirewall {
    Box::leak(Box::new(LibfwFirewall {
        conntrack: Conntrack::new(),
        chain: RwLock::new(None),
        ffi_chain_copy: None,
    }))
}

///
/// Configures chain of rules for the firewall to follow
///
/// @param fw - pointer returned by @ref libfw_init
/// @param chain - chain of the firewall rules
///
#[no_mangle]
pub unsafe extern "C" fn libfw_configure_chain(
    fw: *mut LibfwFirewall,
    ffi_chain: *const LibfwChain,
) -> LibfwError {
    match ffi_chain.as_ref() {
        Some(ffi_chain) => match ffi_chain.try_into() {
            Ok(chain) => {
                unsafe {
                    (*fw).ffi_chain_copy = Some(ffi_chain.clone());
                    *(*fw).chain.write() = Some(chain);
                }
                LibfwError::LibfwSuccess
            }
            Err(err) => err,
        },
        None => LibfwError::LibfwErrorNullPointer,
    }
}

///
/// Retrieves currently configured chain of firewall rules
///
/// @param fw - pointer to initialized firewall
///
/// @returns  - currenlty configured chain, NULL if no chain is confugured
///
#[no_mangle]
pub unsafe extern "C" fn libfw_dump_chain(fw: *mut LibfwFirewall) -> *const LibfwChain {
    if let Some(chain) = unsafe { (*fw).ffi_chain_copy.as_ref() } {
        chain as *const LibfwChain
    } else {
        null_mut()
    }
}

///
/// A function which triggers stale connection closing
///
/// @param fw - pointer returned by @ref libfw_init
/// @param associated_data - identifier of peer. Should contain peer's public key
///                          for NordLynx and be Null for other protcols
/// @param associated_data_len - size of @param associated_data in bytes
/// @param inject_packet_cb_data - a pointer which will be passed in the
///                                inject_packet callback unmodified
/// @param inject_inbound_packet_cb - callback which will be used by libfw to inject
///                           packets into virtual tunnel interface
/// @param inject_outbound_packet_cb - callback which will be used by libfw to inject
///                          packets back towards VPN server. May be NULL if integrators
///                          accepts that libfirewall will only reject connections from
///                          inbound direction.
///
/// # Safety
///
/// This function dereferences pointer to firewall - user must ensure that this is
/// the pointer returned by `libfw_init`.
#[no_mangle]
pub unsafe extern "C" fn libfw_trigger_stale_connection_close(
    firewall: *mut LibfwFirewall,
    associated_data: *const u8,
    associated_data_len: usize,
    inject_packet_cb_data: *mut c_void,
    inject_inbound_packet_cb: LibfwInjectPacketCallback,
    _inject_outbound_packet_cb: LibfwInjectPacketCallback,
) -> LibfwError {
    libfw_log_trace!("Stale connection closing triggered");
    if let Some((fw, callback)) = firewall.as_mut().zip(inject_inbound_packet_cb) {
        let assoc_data = if associated_data.is_null() {
            None
        } else {
            Some(slice::from_raw_parts(associated_data, associated_data_len))
        };
        let conntrack = &fw.conntrack;
        let res_tcp = conntrack.reset_tcp_conns(assoc_data, |packet| {
            callback(
                inject_packet_cb_data,
                packet.as_ptr(),
                packet.len(),
                associated_data,
                associated_data_len,
            );
        });

        let res_udp = conntrack.reset_udp_conns(assoc_data, |packet| {
            callback(
                inject_packet_cb_data,
                packet.as_ptr(),
                packet.len(),
                associated_data,
                associated_data_len,
            );
        });

        if let Err(err) = res_tcp {
            libfw_log_warn!("Failed to reset TCP connections: {:?}", err);
            if let Err(err) = res_udp {
                libfw_log_warn!("Failed to reset UDP connections: {:?}", err);
            }
            err.into()
        } else if let Err(err) = res_udp {
            libfw_log_warn!("Failed to reset UDP connections: {:?}", err);
            err.into()
        } else {
            LibfwError::LibfwSuccess
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
/// @param inject_packet_cb_data - a pointer which will be passed in the
///                                inject_packet callback unmodified
/// @param inject_outbound_packet_cb - callback which will be used by libfw to inject
///                          packets back towards VPN server. May be NULL if integrators
///                          accepts that libfirewall will only reject connections from
///                          inbound direction.
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
    _inject_packet_cb_data: *mut c_void,
    _inject_outbound_packet_cb: LibfwInjectPacketCallback,
) -> LibfwVerdict {
    libfw_log_trace!("Processing inbound packet");
    if packet.is_null() {
        return LibfwVerdict::LibfwVerdictDrop;
    }

    let buffer = slice::from_raw_parts(packet, packet_len);
    let assoc_data = if associated_data.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(associated_data, associated_data_len))
    };

    let Some(fw) = firewall.as_mut() else {
        return LibfwVerdict::LibfwVerdictDrop;
    };

    match unwrap_option_or_return!(buffer.first(), LibfwVerdict::LibfwVerdictDrop) >> 4 {
        4 => {
            let conn_state = fw
                .conntrack
                .track_inbound_ip_packet::<Ipv4Packet>(assoc_data, buffer)
                .unwrap_or_else(|err| {
                    libfw_log_warn!("Conntrack failed to track an inbound packet {:?}", err);
                    conntrack::LibfwConnectionState::LibfwConnectionStateInvalid
                });
            if let Some(chain) = fw.chain.read().as_ref() {
                Ipv4Packet::new(buffer)
                    .map(|ip_packet| {
                        chain.process_packet(
                            conn_state,
                            &ip_packet,
                            assoc_data,
                            conntrack::LibfwDirection::LibfwDirectionInbound,
                        )
                    })
                    .unwrap_or(LibfwVerdict::LibfwVerdictDrop)
            } else {
                LibfwVerdict::LibfwVerdictAccept
            }
        }
        6 => {
            let conn_state = fw
                .conntrack
                .track_inbound_ip_packet::<Ipv6Packet>(assoc_data, buffer)
                .unwrap_or_else(|err| {
                    libfw_log_warn!("Conntrack failed to track an inbound packet {:?}", err);
                    conntrack::LibfwConnectionState::LibfwConnectionStateInvalid
                });
            if let Some(chain) = fw.chain.read().as_ref() {
                Ipv6Packet::new(buffer)
                    .map(|ip_packet| {
                        chain.process_packet(
                            conn_state,
                            &ip_packet,
                            assoc_data,
                            conntrack::LibfwDirection::LibfwDirectionInbound,
                        )
                    })
                    .unwrap_or(LibfwVerdict::LibfwVerdictDrop)
            } else {
                LibfwVerdict::LibfwVerdictAccept
            }
        }
        version => {
            libfw_log_warn!("Unexpected IP version {} for inbound packet", version);
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
/// @param inject_packet_cb_data - a pointer which will be passed in the
///                                inject_packet callback unmodified
/// @param inject_inbound_packet_cb - callback which will be used by libfw to inject
///                           packets into virtual tunnel interface
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
    _inject_packet_cb_data: *mut c_void,
    _inject_inbound_packet_cb: LibfwInjectPacketCallback,
) -> LibfwVerdict {
    libfw_log_trace!("Processing outbound packet");
    if packet.is_null() {
        return LibfwVerdict::LibfwVerdictDrop;
    }

    let buffer = slice::from_raw_parts(packet, packet_len);
    let assoc_data = if associated_data.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(associated_data, associated_data_len))
    };

    let Some(fw) = firewall.as_mut() else {
        return LibfwVerdict::LibfwVerdictDrop;
    };

    match unwrap_option_or_return!(buffer.first(), LibfwVerdict::LibfwVerdictDrop) >> 4 {
        4 => {
            let conn_state = fw
                .conntrack
                .track_outbound_ip_packet::<Ipv4Packet>(assoc_data, buffer)
                .unwrap_or_else(|err| {
                    libfw_log_warn!("Conntrack failed to track an outbound packet {:?}", err);
                    conntrack::LibfwConnectionState::LibfwConnectionStateInvalid
                });
            if let Some(chain) = fw.chain.read().as_ref() {
                Ipv4Packet::new(buffer)
                    .map(|ip_packet| {
                        chain.process_packet(
                            conn_state,
                            &ip_packet,
                            assoc_data,
                            conntrack::LibfwDirection::LibfwDirectionOutbound,
                        )
                    })
                    .unwrap_or(LibfwVerdict::LibfwVerdictDrop)
            } else {
                LibfwVerdict::LibfwVerdictAccept
            }
        }
        6 => {
            let conn_state = fw
                .conntrack
                .track_outbound_ip_packet::<Ipv6Packet>(assoc_data, buffer)
                .unwrap_or_else(|err| {
                    libfw_log_warn!("Conntrack failed to track an outbound packet {:?}", err);
                    conntrack::LibfwConnectionState::LibfwConnectionStateInvalid
                });
            if let Some(chain) = fw.chain.read().as_ref() {
                Ipv6Packet::new(buffer)
                    .map(|ip_packet| {
                        chain.process_packet(
                            conn_state,
                            &ip_packet,
                            assoc_data,
                            conntrack::LibfwDirection::LibfwDirectionOutbound,
                        )
                    })
                    .unwrap_or(LibfwVerdict::LibfwVerdictDrop)
            } else {
                LibfwVerdict::LibfwVerdictAccept
            }
        }
        version => {
            libfw_log_warn!("Unexpected IP version {} for outbound packet", version);
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
        drop(Box::from_raw(firewall));
    }
}
