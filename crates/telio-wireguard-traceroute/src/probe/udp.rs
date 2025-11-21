use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::UdpSocket;

use log::debug;

use super::{Probe, Response};

/// Send a WireGuard handshake probe packet with specified TTL
///
/// # Arguments
/// * `packet` - The handshake packet to send
/// * `dest` - Destination address
/// * `ttl` - Time-to-live value for the packet
/// * `source_port` - Optional source port to bind to
/// * `wait_duration` - How long to wait for a response
///
/// # Returns
/// ProbeResult indicating timeout or response with RTT
pub async fn send_probe(dest: &SocketAddr, packet: &[u8], socket: &UdpSocket) -> Result<Probe> {
    // Send packet
    debug!("Sending UDP packet {:?} to {dest:?}", hex::encode(packet));
    socket
        .send_to(packet, dest)
        .await
        .context("Failed to send packet")?;

    Ok(Probe {
        sent_at: Instant::now(),
        payload: packet.to_vec(),
        src: socket.local_addr()?,
        dest: dest.clone(),
        ttl: socket.ttl()? as u8,
    })
}

pub async fn receive_response(socket: &UdpSocket) -> Result<Response> {
    loop {
        // Receive
        let mut buf = [0u8; 65536]; // size is probably overkill
        let len = socket.recv(&mut buf).await?;
        let received = buf[..len].to_vec();

        debug!(
            "Received UDP packet {:?} from {:?}",
            hex::encode(received.as_slice()),
            socket.peer_addr()
        );

        if buf[0] != 0x02 {
            debug!("Recieved packet is not handshake response. Ignoring");
            continue;
        }

        return Ok(Response {
            received_at: Instant::now(),
            from: socket.peer_addr()?,
            payload: received,
        })
    }
}

/// Create a UDP socket with specified TTL and optional source port
pub async fn create_socket(
    source_port: Option<u16>,
    destination: &SocketAddr,
    ttl: u8,
) -> Result<UdpSocket> {
    debug!("Attempting to create UDP socket: {source_port:?}, {destination:?}, {ttl:?}");

    // Bind to source port
    let bind_addr = match source_port {
        Some(p) => format!("0.0.0.0:{}", p),
        None => "0.0.0.0:0".to_string(),
    };

    // Create and bind socket
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .context("Failed to bind UDP socket")?;

    debug!("Socket bound to {bind_addr:?}");

    // Set TTL
    socket.set_ttl(ttl as u32).context("Failed to set TTL")?;

    debug!("TTL Set to {ttl:?}");

    // Windows-specific: Disable ICMP error notifications
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock;

        unsafe {
            let mut bytes_returned: u32 = 0;
            let mut disable: u32 = 0;

            let result = WinSock::WSAIoctl(
                socket.as_raw_socket() as usize,
                WinSock::SIO_UDP_CONNRESET,
                &mut disable as *mut u32 as *mut std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned as *mut u32,
                std::ptr::null_mut(),
                None,
            );

            if result != 0 {
                eprintln!(
                    "Warning: Failed to disable ICMP errors: {}",
                    std::io::Error::last_os_error()
                );
                // Continue anyway
            }

            debug!("Windows-Specific: Disabled SIO_UDP_CONNRESET");

            disable = 0;
            let result = WinSock::WSAIoctl(
                socket.as_raw_socket() as usize,
                WinSock::SIO_UDP_NETRESET,
                &mut disable as *mut u32 as *mut std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned as *mut u32,
                std::ptr::null_mut(),
                None,
            );

            if result != 0 {
                eprintln!(
                    "Warning: Failed to disable ICMP errors: {}",
                    std::io::Error::last_os_error()
                );
                // Continue anyway
            }

            debug!("Windows-Specific: Disabled SIO_UDP_NETRESET");
        }
    }

    socket.connect(destination).await?;

    debug!("Socket connected to {destination:?}");

    Ok(socket)
}
