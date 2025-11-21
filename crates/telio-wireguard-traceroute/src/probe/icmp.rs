use anyhow::{Context, Result};
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Packet;
use pnet_packet::icmpv6::Icmpv6Types;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::udp::UdpPacket;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{
    SocketAddr,
    SocketAddr::{V4, V6},
};

use std::time::Instant;
use tokio::net::UdpSocket as TokioUdpSocket;

use log::debug;

use super::Probe;
use super::Response;

/// Creates and configures a raw ICMP socket
///
/// # Returns
/// A configured Socket wrapped in an AsyncFd for async operations
///
/// # Errors
/// Returns io::Error if socket creation or configuration fails
pub async fn create_socket(src: &SocketAddr, dest: &SocketAddr) -> Result<TokioUdpSocket> {
    debug!("Attempting to create RAW socket for listening to ICMP: {src:?}, {dest:?}");

    let domain = match dest {
        V4(_) => Domain::IPV4,
        V6(_) => Domain::IPV6,
    };

    // Create raw ICMP socket (requires CAP_NET_RAW capability or root)
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::ICMPV4))
        .context("Failed to create raw socket")?;

    debug!("Socket handle for RAW ICMPv4 socket created");

    // Set socket to non-blocking mode for async operations
    socket
        .set_nonblocking(true)
        .context("Failed to set raw socket into non-blocking mode")?;

    debug!("Socket configured in non-blocking mode");

    socket
        .set_reuse_address(true)
        .context("Failed to set raw socket to reuse address")?;

    debug!("Socket configured to allow address reuse");

    // Bind to any address to receive all ICMP packets
    let addr: SockAddr = src.clone().into();
    socket.bind(&addr).context("Failed to bind raw socket")?;

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock;

        let mut opt_val: u32 = WinSock::RCVALL_ON.try_into()?;

        unsafe {
            let mut bytes_returned: u32 = 0;
            let res: i32 = WinSock::WSAIoctl(
                socket.as_raw_socket() as usize,
                WinSock::SIO_RCVALL,
                &mut opt_val as *mut u32 as *mut std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            );

            if res == WinSock::SOCKET_ERROR {
                let error = std::io::Error::last_os_error();
                return Err(error).context("WSAIoctl SIO_RCVALL failed");
            }
        }

        debug!("Windows-Specific: Enabled SIO_RCVALL");
    }

    // Convert to tokio socket based on raw fd
    let tokio_socket = tokio::net::UdpSocket::from_std(socket.into())
        .context("Failed to convert to tokio socket")?;

    Ok(tokio_socket)
}

/// Receives and processes ICMP messages from the socket
///
/// # Arguments
/// * `socket` - The AsyncFd-wrapped socket to read from
///
/// # Returns
/// A tuple containing the received data buffer and the number of bytes read
///
/// # Errors
/// Returns io::Error if receiving data fails
pub async fn receive_response(socket: &TokioUdpSocket, probe: &Probe) -> Result<Response> {
    let mut buffer = [0u8; 65536];

    loop {
        let (bytes_received, sender) = socket
            .recv_from(&mut buffer)
            .await
            .context("Failed to receive from RAW socket")?;
        let received: Vec<u8> = buffer[..bytes_received].to_vec();

        debug!("Received ICMP packet: {:?}", hex::encode(&received));

        // Check if the ICMP response is destined for us
        if !is_matching(&received, probe.src) {
            debug!("Non-matching ICMP packet. Ignoring.");
            continue;
        }

        return Ok(Response {
            received_at: Instant::now(),
            from: sender,
            payload: received,
        });
    }
}

/// Check if an ICMP error packet matches our expected source address
///
/// ICMP error messages contain a portion of the original packet that triggered
/// the error. This function extracts the embedded IP source and UDP source port
/// and compares them to the expected socket address.
///
/// # Arguments
/// * `icmp_packet` - Raw IP packet containing ICMP error message
/// * `expected_source` - Expected source socket address (IP + port) of original packet
///
/// # Returns
/// true if the embedded packet has matching source address and port
pub fn is_matching(icmp_packet: &[u8], expected_source: SocketAddr) -> bool {
    // Try IPv4
    if let Some(extracted_addr) = extract_source_from_icmp_ipv4(icmp_packet) {
        debug!("Extracted Addr {extracted_addr:?}, expected_addr: {expected_source:?}");
        return extracted_addr == expected_source;
    }

    // Try IPv6
    if let Some(extracted_addr) = extract_source_from_icmp_ipv6(icmp_packet) {
        debug!("Extracted Addr {extracted_addr:?}, expected_addr: {expected_source:?}");
        return extracted_addr == expected_source;
    }

    false
}

/// Extract source socket address from IPv4 ICMP error message
///
/// Returns the source SocketAddr from the embedded packet
fn extract_source_from_icmp_ipv4(packet: &[u8]) -> Option<SocketAddr> {
    // Parse outer IPv4 packet
    let ipv4 = Ipv4Packet::new(packet)?;

    // Verify it's ICMP
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        debug!(
            "IP next level proto not ICMP: {:?}",
            ipv4.get_next_level_protocol()
        );
        return None;
    }

    // Parse ICMP packet from IPv4 payload
    let icmp = IcmpPacket::new(ipv4.payload())?;

    // Verify icmp packet type
    match icmp.get_icmp_type() {
        IcmpTypes::DestinationUnreachable
        | IcmpTypes::TimeExceeded
        | IcmpTypes::Traceroute
        | IcmpTypes::ParameterProblem => {}
        _ => {
            debug!("Non-error ICMP type: {:?}", icmp.get_icmp_type());
            return None;
        }
    }

    // ICMP error payload structure (RFC 792):
    // [4 bytes: unused for Time Exceeded, specific for Dest Unreach]
    // [embedded IP packet...]
    let icmp_payload = icmp.payload();
    if icmp_payload.len() < 4 {
        debug!(
            "Too short payload len for ICMP error packet {:?}",
            icmp_payload.len()
        );
        return None;
    }

    // Skip the 4-byte header, get embedded IP packet
    let embedded_ip_packet = &icmp_payload[4..];

    // Parse the embedded IPv4 packet
    let embedded_ipv4 = Ipv4Packet::new(embedded_ip_packet)?;

    // Extract source IP from embedded packet
    let source_ip = embedded_ipv4.get_source();

    // Verify embedded packet is UDP
    if embedded_ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        debug!(
            "ICMP inner-packet is not UDP: {:?}",
            embedded_ipv4.get_next_level_protocol()
        );
        return None;
    }

    // Parse embedded UDP header
    let embedded_udp = UdpPacket::new(embedded_ipv4.payload())?;

    // Extract source port from embedded UDP
    let source_port = embedded_udp.get_source();

    // Construct SocketAddr
    Some(SocketAddr::new(source_ip.into(), source_port))
}

/// Extract source socket address from IPv6 ICMP error message
///
/// Returns the source SocketAddr from the embedded packet
fn extract_source_from_icmp_ipv6(packet: &[u8]) -> Option<SocketAddr> {
    // Parse outer IPv6 packet
    let ipv6 = Ipv6Packet::new(packet)?;

    // Verify it's ICMPv6
    if ipv6.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        debug!(
            "IP next header proto not ICMPv6: {:?}",
            ipv6.get_next_header()
        );
        return None;
    }

    // Parse ICMPv6 packet from IPv6 payload
    let icmpv6 = Icmpv6Packet::new(ipv6.payload())?;

    // Verify icmp packet type
    match icmpv6.get_icmpv6_type() {
        Icmpv6Types::DestinationUnreachable
        | Icmpv6Types::TimeExceeded
        | Icmpv6Types::PacketTooBig
        | Icmpv6Types::ParameterProblem => {}
        _ => {
            debug!("Non-error ICMPv6 type: {:?}", icmpv6.get_icmpv6_type());
            return None;
        }
    }

    // ICMPv6 error payload structure:
    // [4 bytes: unused/specific data]
    // [embedded IPv6 packet...]
    let icmpv6_payload = icmpv6.payload();
    if icmpv6_payload.len() < 4 {
        debug!(
            "Too short payload len for ICMPv6 error packet {:?}",
            icmpv6_payload.len()
        );
        return None;
    }

    // Skip the 4-byte header
    let embedded_ip_packet = &icmpv6_payload[4..];

    // Parse the embedded IPv6 packet
    let embedded_ipv6 = Ipv6Packet::new(embedded_ip_packet)?;

    // Extract source IP from embedded packet
    let source_ip = embedded_ipv6.get_source();

    // Verify embedded packet is UDP
    if embedded_ipv6.get_next_header() != IpNextHeaderProtocols::Udp {
        debug!(
            "ICMPv6 inner-packet is not UDP: {:?}",
            embedded_ipv6.get_next_header()
        );
        return None;
    }

    // Parse embedded UDP header
    let embedded_udp = UdpPacket::new(embedded_ipv6.payload())?;

    // Extract source port from embedded UDP
    let source_port = embedded_udp.get_source();

    // Construct SocketAddr
    Some(SocketAddr::new(source_ip.into(), source_port))
}
