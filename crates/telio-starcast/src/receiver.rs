use boringtun::noise::{Tunn, TunnResult};
use ipnetwork::{IpNetwork, Ipv4Network};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use telio_crypto::{PublicKey, SecretKey};
use telio_task::io::Chan;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_info, telio_log_warn};
use telio_wg::uapi::Peer;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret};
const IPV4_HEADER: usize = 20; // bytes
const IPV6_HEADER: usize = 40; // bytes
const MAX_PACKET: usize = 2048;
const UDP_HEADER: usize = 8;

pub struct Receiver {
    secret_key: SecretKey,
    tun_socket: Arc<UdpSocket>,
    vpeer_wg_port: u16,
    telio_wg_endpoint: SocketAddr,
    peer: Arc<Tunn>,
    task: Option<JoinHandle<()>>,
    chan: Arc<Chan<Vec<u8>>>,

    /// packet checksum -> packet sender (to avoid packet loop)
    ddos_map: HashMap<u32, PublicKey>,
}

impl Receiver {
    pub async fn new(
        telio_wg_port: u16,
        public_key: &PublicKey,
        chan: Chan<Vec<u8>>,
    ) -> Result<Self, String> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| {
                telio_log_error!("Failed to bind multicast socket: {:?}", e);
                format!("Failed to bind multicast socket: {:?}", e)
            })?;

        let vpeer_wg_port = socket
            .local_addr()
            .map_err(|e| {
                telio_log_error!("Failed to get socket port: {:?}", e);
                format!("Failed to get socket port: {:?}", e)
            })?
            .port();

        let multicast_secret_key = SecretKey::gen();

        let telio_public_key: PublicKeyDalek = PublicKeyDalek::from(public_key.0);

        Ok(Self {
            secret_key: multicast_secret_key,
            tun_socket: Arc::new(socket),
            vpeer_wg_port,
            telio_wg_endpoint: ([127, 0, 0, 1], telio_wg_port).into(),
            peer: Arc::<Tunn>::from(Tunn::new(
                StaticSecret::from(multicast_secret_key.into_bytes()),
                telio_public_key,
                None,
                None,
                0,
                None,
            )?),
            task: None,
            chan: Arc::new(chan),
            ddos_map: Default::default(),
        })
    }

    pub async fn start_receiver(&mut self) {
        self.task = Some(tokio::spawn(Receiver::local_forwarder(
            self.peer.clone(),
            self.tun_socket.clone(),
            self.telio_wg_endpoint,
            self.chan.clone(),
        )));
    }

    pub async fn stop(&mut self) {
        if let Some(handle) = &self.task {
            handle.abort();
        }
    }

    pub fn get_peer(&self) -> Peer {
        Peer {
            public_key: self.public_key(),
            endpoint: Some(([127, 0, 0, 1], self.vpeer_wg_port).into()),
            // Include all local non-routable ipv4 multicast addresses and single ipv6 address for just MDNS for now
            allowed_ips: vec![
                IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(224, 0, 0, 0), 24).unwrap()),
                IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)).into(),
            ],
            ..Default::default()
        }
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
        chan: Arc<Chan<Vec<u8>>>,
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
            let mut receiving_buffer = receiving_buffer.clone();
            let mut sending_buffer = sending_buffer.clone();
            let mut send_chan = chan.clone();
            tokio::spawn(async move {
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
                        telio_log_info!("got packet to vpeer: {:?}", packet);
                        let bytes = packet.to_vec();
                        let res = send_chan.tx.send(bytes).await;
                        if let Err(e) = res {
                            telio_log_error!("failed to send packet to multicaster: {}", e);
                        }
                    }
                    _ => {}
                }
            });
        }
    }
}
