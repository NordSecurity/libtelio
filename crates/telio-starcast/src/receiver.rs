use boringtun::noise::{Tunn, TunnResult};
use ipnetwork::{IpNetwork, IpNetworkError, Ipv4Network};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use telio_crypto::{PublicKey, SecretKey};
use telio_task::io::chan::Tx;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};
use telio_wg::uapi::Peer;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret};

use crate::multicast_peer::MulticasterIp;
const MAX_PACKET: usize = 2048;

pub struct Receiver {
    secret_key: SecretKey,
    tun_socket: Arc<UdpSocket>,
    vpeer_wg_port: u16,
    telio_wg_endpoint: Arc<SocketAddr>,
    peer: Arc<Tunn>,
    task: Option<JoinHandle<()>>,
    tun_out: Tx<Vec<u8>>,
    multicaster_ip: Arc<MulticasterIp>,
}

impl Receiver {
    pub async fn new(
        socket: Arc<UdpSocket>,
        telio_wg_socket: Arc<SocketAddr>,
        chan: Tx<Vec<u8>>,
        multicast_secret_key: SecretKey,
        peer: Arc<Tunn>,
        multicaster_ip: Arc<MulticasterIp>,
    ) -> Result<Self, String> {
        let vpeer_wg_port = socket
            .local_addr()
            .map_err(|e| {
                telio_log_error!("Failed to get socket port: {:?}", e);
                format!("Failed to get socket port: {:?}", e)
            })?
            .port();

        Ok(Self {
            secret_key: multicast_secret_key,
            tun_socket: socket,
            vpeer_wg_port,
            telio_wg_endpoint: telio_wg_socket.clone(),
            peer: peer.clone(),
            task: None,
            tun_out: chan,
            multicaster_ip,
        })
    }

    pub async fn start_receiver(&mut self) {
        self.task = Some(tokio::spawn(Receiver::local_forwarder(
            self.peer.clone(),
            self.tun_socket.clone(),
            *self.telio_wg_endpoint,
            self.tun_out.clone(),
        )));
    }

    pub async fn stop(&mut self) {
        if let Some(handle) = &self.task {
            handle.abort();
        }
    }

    pub fn get_peer(&self) -> Result<Peer, IpNetworkError> {
        Ok(Peer {
            public_key: self.public_key(),
            endpoint: Some(([127, 0, 0, 1], self.vpeer_wg_port).into()),
            // Include all local non-routable ipv4 multicast addresses and single ipv6 address for just MDNS for now
            allowed_ips: vec![
                IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(224, 0, 0, 0), 4)?),
                IpNetwork::V4(Ipv4Network::new(self.multicaster_ip.ipv4, 32)?),
                IpAddr::V6(self.multicaster_ip.ipv6).into(),
            ],
            ..Default::default()
        })
    }

    fn public_key(&self) -> PublicKey {
        let static_secret = &StaticSecret::from(self.secret_key.into_bytes());
        telio_log_debug!(
            "Multicast vpeer - public_key: {:?}",
            PublicKeyDalek::from(static_secret)
        );
        PublicKey(PublicKeyDalek::from(static_secret).to_bytes())
    }

    async fn local_forwarder(
        peer: Arc<Tunn>,
        tun_sock: Arc<UdpSocket>,
        telio_wg_endpoint: SocketAddr,
        tun_out: Tx<Vec<u8>>,
    ) {
        let mut receiving_buffer = vec![0u8; MAX_PACKET];
        let mut sending_buffer = vec![0u8; MAX_PACKET];
        loop {
            let bytes_read_from_tun = match tun_sock.recv(&mut receiving_buffer).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    telio_log_error!("[Multicast] Failed to read bytes: {:?}", e);
                    continue;
                }
            };

            loop {
                match peer.update_timers(&mut sending_buffer) {
                    TunnResult::WriteToNetwork(packet) => {
                        if let Err(e) = tun_sock.send_to(packet, telio_wg_endpoint).await {
                            telio_log_warn!(
                                "[Multicast] Failed to send timer update packet : {:?}",
                                e
                            )
                        };
                    }
                    TunnResult::Err(e) => {
                        telio_log_error!("[Multicast] Failed to update Tunn timers : {:?}", e);
                        break;
                    }
                    _ => break,
                };
            }

            let peer = peer.clone();
            let socket = tun_sock.clone();
            let receiving_buffer = receiving_buffer.clone();
            let mut sending_buffer = sending_buffer.clone();
            let Ok(sender) = tun_out.clone().reserve_owned().await else {
                telio_log_warn!("failed to reserve tun send!");
                return;
            };

            let _ = tokio::spawn(async move {
                match peer.decapsulate(
                    None,
                    receiving_buffer.get(..bytes_read_from_tun).unwrap_or(&[]),
                    &mut sending_buffer,
                ) {
                    // Handshake packets
                    TunnResult::WriteToNetwork(packet) => {
                        if let Err(e) = socket.send_to(packet, telio_wg_endpoint).await {
                            telio_log_warn!(
                                "[Multicast] Failed to send handshake packet  : {:?}",
                                e
                            );
                            return;
                        };
                        let mut temporary_buffer = [0u8; MAX_PACKET];

                        while let TunnResult::WriteToNetwork(empty) =
                            peer.decapsulate(None, &[], &mut temporary_buffer)
                        {
                            if let Err(e) = socket.send_to(empty, telio_wg_endpoint).await {
                                telio_log_warn!(
                                    "[Multicast] Failed to send handshake packet  : {:?}",
                                    e
                                );
                                return;
                            };
                        }
                    }
                    // Multicast packets
                    TunnResult::WriteToTunnelV4(packet, _)
                    | TunnResult::WriteToTunnelV6(packet, _) => {
                        let bytes = packet.to_vec();
                        let _ = sender.send(bytes);
                    }
                    TunnResult::Err(wireguard_error) => {
                        telio_log_warn!("Decapsulate error {:?}", wireguard_error)
                    }
                    TunnResult::Done => (),
                }
            })
            .await;
        }
    }
}
