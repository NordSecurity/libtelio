use boringtun::noise::{Tunn, TunnResult};
use pnet_packet::ipv4::{checksum, MutableIpv4Packet};
use pnet_packet::udp::MutableUdpPacket;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::{net::SocketAddr, sync::Arc};
use telio_sockets::SocketPool;
use telio_task::io::chan::Rx;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};
use telio_wg::{DynamicWg, WireGuard};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::multicast_peer::MulticasterIp;

#[cfg(feature = "test-util")]
const MULTICAST_TRANSPORT_PORT: u16 = 0;
#[cfg(not(feature = "test-util"))]
const MULTICAST_TRANSPORT_PORT: u16 = 13569;
const MAX_PACKET: usize = 2048;
const IPV4_HEADER: usize = 20; // bytes
const UDP_DEST_OFFSET: usize = 2;

/// Multicaster task that resends locally generated
/// multicast traffic to other peers
pub struct Multicaster {
    wg_if: Arc<DynamicWg>,
    transport_socket: Arc<UdpSocket>,
    local_socket: Arc<UdpSocket>,
    wg_sock: Arc<SocketAddr>,
    tun_rx: Option<Rx<Vec<u8>>>,
    tun_to_transport_task: Option<JoinHandle<()>>,
    transport_to_local_task: Option<JoinHandle<()>>,
    peer: Arc<Tunn>,
    nat_map: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    multicaster_ip: Arc<MulticasterIp>,
}

impl Multicaster {
    pub async fn new(
        local_socket: Arc<UdpSocket>,
        wg: Arc<DynamicWg>,
        wg_sock: Arc<SocketAddr>,
        socket_pool: Arc<SocketPool>,
        tun_rx: Rx<Vec<u8>>,
        peer: Arc<Tunn>,
        multicaster_ip: Arc<MulticasterIp>,
    ) -> Result<Self, String> {
        let transport_socket = socket_pool
            .new_internal_udp(
                SocketAddr::from(([0, 0, 0, 0], MULTICAST_TRANSPORT_PORT)),
                None,
            )
            .await
            .map_err(|e| {
                telio_log_error!("Failed to bind multicast socket: {:?}", e);
                format!("Failed to bind multicast socket: {:?}", e)
            })?;

        let nat_map: Arc<RwLock<HashMap<u16, SocketAddr>>> = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            wg_if: wg,
            transport_socket: Arc::new(transport_socket),
            local_socket,
            wg_sock,
            tun_rx: Some(tun_rx),
            tun_to_transport_task: None,
            transport_to_local_task: None,
            peer: peer.clone(),
            nat_map: nat_map.clone(),
            multicaster_ip,
        })
    }

    pub async fn start_multicaster(&mut self) {
        let Some(tun_rx) = self.tun_rx.take() else {
            telio_log_warn!("multicast can be started once for now");
            return;
        };

        self.tun_to_transport_task = Some(tokio::spawn(Multicaster::tun_to_transport(
            tun_rx,
            self.wg_if.clone(),
            self.transport_socket.clone(),
            self.nat_map.clone(),
            self.multicaster_ip.clone(),
        )));
        self.transport_to_local_task = Some(tokio::spawn(Self::transport_to_local(
            self.transport_socket.clone(),
            self.local_socket.clone(),
            self.wg_sock.clone(),
            self.peer.clone(),
            self.nat_map.clone(),
            self.multicaster_ip.clone(),
        )));
    }

    pub async fn stop(&mut self) {
        if let Some(handle) = &self.transport_to_local_task {
            handle.abort();
        }
        if let Some(handle) = &self.tun_to_transport_task {
            handle.abort();
        }
    }

    pub async fn tun_to_transport(
        mut tun_rx: Rx<Vec<u8>>,
        wg: Arc<DynamicWg>,
        transport_sock: Arc<UdpSocket>,
        nat_map: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        multicaster_ip: Arc<MulticasterIp>,
    ) {
        loop {
            let mut packet = match tun_rx.recv().await {
                Some(packet) => packet,
                None => {
                    telio_log_error!("failed to receive multicast packet from tun channel");
                    return;
                }
            };

            telio_log_debug!("rx from tun");

            // Extracting UDP destination port from the packet
            let key = u16::from_be_bytes([
                *(packet.get(IPV4_HEADER + UDP_DEST_OFFSET).unwrap_or(&0)),
                *(packet.get(IPV4_HEADER + UDP_DEST_OFFSET + 1).unwrap_or(&0)),
            ]);

            let dest_sock = if let Some(mut ip_packet) = MutableIpv4Packet::new(&mut packet) {
                let dest_sock = if ip_packet.get_destination() == multicaster_ip.ipv4 {
                    let (dest_ip, dest_port) =
                        if let Some(sock_addr) = nat_map.read().await.get(&key) {
                            if let IpAddr::V4(addr) = sock_addr.ip() {
                                (addr, sock_addr.port())
                            } else {
                                (Ipv4Addr::new(0, 0, 0, 0), 0)
                            }
                        } else {
                            ((Ipv4Addr::new(0, 0, 0, 0)), 0)
                        };
                    ip_packet.set_destination(dest_ip);
                    ip_packet.set_checksum(0);
                    ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
                    telio_log_debug!("Unicast -> ip {:?}", ip_packet.get_destination());
                    Some((dest_ip, dest_port))
                } else {
                    None
                };
                dest_sock
            } else {
                None
            };

            if let Some(sock) = dest_sock {
                // Is a unicast response
                if let Some(mut udp_packet) = packet
                    .get_mut(IPV4_HEADER..)
                    .and_then(MutableUdpPacket::new)
                {
                    udp_packet.set_destination(sock.1);
                    telio_log_debug!("Unicast -> port {:?}", udp_packet.get_destination());
                    // Ignoring L4 checksum as it is already encapsulated in L3/L4 header
                    udp_packet.set_checksum(0x0000);
                }
                let res = transport_sock
                    .send_to(
                        &packet,
                        SocketAddr::new(std::net::IpAddr::V4(sock.0), MULTICAST_TRANSPORT_PORT),
                    )
                    .await;
                if let Err(e) = res {
                    telio_log_error!(
                        "Failed to forward multicast packet to {:?}, error: {}",
                        sock.0,
                        e
                    );
                }
            } else {
                // Is a multicast packet
                let peers = wg.as_ref().get_interface().await.map(|interface| {
                    interface
                        .peers
                        .values()
                        .filter_map(|peer| {
                            if peer.is_connected()
                                && !peer.is_multicast_peer()
                                && !peer.is_stun_peer()
                            {
                                peer.allowed_ips.get(0).map(|allowed_ip| allowed_ip.ip())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<IpAddr>>()
                });
                let tun_sock = transport_sock.clone();
                let _ = peers.map(|peer_vec| async move {
                    for addr in peer_vec {
                        let res = tun_sock
                            .send_to(&packet, SocketAddr::new(addr, MULTICAST_TRANSPORT_PORT))
                            .await;
                        if let Err(e) = res {
                            telio_log_error!(
                                "Failed to forward multicast packet to {:?}, error: {}",
                                addr,
                                e
                            );
                        }
                    }
                });
            }
        }
    }

    pub async fn transport_to_local(
        transport_sock: Arc<UdpSocket>,
        local_sock: Arc<UdpSocket>,
        wg_sock: Arc<SocketAddr>,
        peer: Arc<Tunn>,
        nat_map: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        vpeer: Arc<MulticasterIp>,
    ) {
        let mut receiving_buffer = vec![0u8; MAX_PACKET];
        let mut sending_buffer = vec![0u8; MAX_PACKET];
        loop {
            let res = transport_sock.recv(&mut receiving_buffer).await;
            let bytes_read = match res {
                Err(e) => {
                    telio_log_error!("failed to receive on multicast transport socket: {}", e);
                    0
                }
                Ok(bytes) => bytes,
            };

            let ip_addrs = if let Some(mut ip_packet) = receiving_buffer
                .get_mut(..bytes_read)
                .and_then(MutableIpv4Packet::new)
            {
                let sender_ip = ip_packet.get_source();
                let dest = {
                    // Set source of packet to vpeer
                    ip_packet.set_source(vpeer.ipv4);
                    ip_packet.set_checksum(0);
                    ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
                    std::net::IpAddr::V4(ip_packet.get_destination())
                };
                Some((std::net::IpAddr::V4(sender_ip), dest))
            } else {
                None
            };

            if let (Some(mut udp_packet), Some((ip_src, ip_dst))) = (
                MutableUdpPacket::new(receiving_buffer.get_mut(IPV4_HEADER..).unwrap_or(&mut [])),
                ip_addrs,
            ) {
                {
                    let natted_port =
                        Multicaster::map_to_port(&ip_src, &ip_dst, udp_packet.get_destination());
                    if !nat_map.write().await.contains_key(&natted_port) {
                        nat_map.write().await.insert(
                            natted_port,
                            SocketAddr::new(ip_src, udp_packet.get_source()),
                        );
                    }
                    udp_packet.set_source(natted_port);
                }
                // Setting it as null to ignore L4 checksum as it is internal transportation
                udp_packet.set_checksum(0x0000);
            }
            match peer.encapsulate(
                receiving_buffer.get(..(bytes_read)).unwrap_or(&[]),
                &mut sending_buffer,
            ) {
                TunnResult::WriteToNetwork(buff) => {
                    let res = local_sock.send_to(buff, *wg_sock).await;
                    if let Err(e) = res {
                        telio_log_error!("failed to receive on multicast transport socket: {e}");
                    }
                }
                _ => telio_log_warn!("failed to send upstream"),
            }
        }
    }

    // TODO: Change this to a better mapper
    fn map_to_port(src_ip: &IpAddr, ip: &IpAddr, port: u16) -> u16 {
        // Create a hasher instance
        let mut hasher = DefaultHasher::new();
        // Combine IP address and port into a single string and hash it
        let combined = format!("Src {} {}:{}", src_ip, ip, port);
        combined.hash(&mut hasher);
        // Obtain the hash value and map it to a number less than 65535
        let hash_value = hasher.finish();
        (hash_value % 65535) as u16
    }
}
