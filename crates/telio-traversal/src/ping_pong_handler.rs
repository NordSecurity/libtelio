use crate::endpoint_providers::Error;
use rand::rngs::StdRng;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use telio_crypto::{
    encryption::{decrypt_request, decrypt_response, encrypt_request, encrypt_response},
    PublicKey, SecretKey,
};
use telio_model::features::EndpointProvider;
use telio_proto::{
    CodecError, PacketRelayed, PacketTypeRelayed, PingerMsg, Session, Timestamp, WGPort,
};
use telio_task::io::chan;
use telio_utils::{telio_log_debug, telio_log_warn};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::endpoint_providers::PongEvent;

/// PingPongHandler will send and receive encrypted Pinger and Ponger messages.
///
/// When Pinger is received it will be validated against configured set of allowed
/// keys. When Ponger message is received it will validate against the set of live
/// sessions.
pub struct PingPongHandler {
    secret_key: SecretKey,
    known_keys: HashSet<PublicKey>,
    known_sessions: HashMap<Session, PublicKey>,
    rng: Mutex<StdRng>,
}

impl PingPongHandler {
    /// Create new instance with our secret key to be used during encryption.
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            known_keys: Default::default(),
            known_sessions: Default::default(),
            rng: Mutex::new(rand::make_rng()),
        }
    }

    /// Configure list of allowed sessions together with maching public keys of peer.
    pub fn configure(&mut self, known_sessions: HashMap<Session, PublicKey>) {
        self.known_keys = known_sessions.values().copied().collect();
        self.known_sessions = known_sessions;
    }

    /// Send a encrypted Pinger message via `udp_socket` to `addr`.
    pub async fn send_ping(
        &mut self,
        addr: SocketAddr,
        wg_port: WGPort,
        udp_socket: &UdpSocket,
        session_id: Session,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        telio_log_debug!("Sending ping to {:?}", addr);
        let ping = PingerMsg::ping(wg_port, session_id, ts);
        let mut rng = self.rng.lock().await;

        let encrypt_transform = |b: &[u8]| {
            encrypt_request(b, &mut *rng, &self.secret_key, public_key)
                .map_err(|e| CodecError::EncryptionFailed(e.to_string()))
        };

        let buf = ping.encode_and_encrypt(encrypt_transform)?;
        udp_socket.send_to(&buf, addr).await?;

        Ok(())
    }

    /// Handle incomming message of type Pinger or Ponger.
    ///
    /// Other message types are discarded.
    pub async fn handle_rx_packet(
        &self,
        encrypted_buf: &[u8],
        addr: &SocketAddr,
        wg_port: WGPort,
        udp_socket: &UdpSocket,
        pong_publisher: &Option<chan::Tx<PongEvent>>,
        endpoint_provider: EndpointProvider,
    ) -> Result<(), Error> {
        let decrypt_transform = |packet_type, buf: &[u8]| {
            match packet_type {
                PacketTypeRelayed::Pinger => {
                    decrypt_request(buf, &self.secret_key, |k| self.known_keys.contains(k))
                        .map_err(|e| CodecError::DecryptionFailed(e.to_string()))
                        .map(|(buf, pk)| (buf, Some(pk)))
                }
                // keep inner proto encrypted for now, later on we will decrypt it when we will have access to session to public key mapping
                PacketTypeRelayed::Ponger => Ok((buf.to_vec(), None)),
                _ => Err(CodecError::InvalidType),
            }
        };
        match PacketRelayed::decode_and_decrypt(encrypted_buf, decrypt_transform)? {
            (PacketRelayed::Pinger(packet), Some(remote_pk)) => {
                // Respond with pong
                telio_log_debug!(
                    "Received ping from {:?} ({}), responding from {endpoint_provider:?} ({:?})",
                    addr,
                    packet.get_session(),
                    udp_socket.local_addr()
                );
                let pong = packet
                    .pong(wg_port, &addr.ip(), endpoint_provider)
                    .ok_or(Error::FailedToBuildPongPacket)?;
                let mut rng = self.rng.lock().await;
                let encrypt_transform = |b: &[u8]| {
                    encrypt_response(b, &mut *rng, &self.secret_key, &remote_pk)
                        .map_err(|e| CodecError::EncryptionFailed(e.to_string()))
                };
                let buf = pong.encode_and_encrypt(encrypt_transform)?;
                udp_socket.send_to(&buf, addr).await?;
            }
            (PacketRelayed::Ponger(packet), _) => {
                if let Some(pong_publisher) = pong_publisher.as_ref() {
                    if let Some(remote_pk) = self.known_sessions.get(&packet.get_session()) {
                        let decrypt_transform = |b: &[u8]| {
                            decrypt_response(b, &self.secret_key, remote_pk)
                                .map_err(|e| CodecError::DecryptionFailed(e.to_string()))
                        };
                        let msg = packet.decrypt(decrypt_transform)?;
                        telio_log_debug!("Received pong from {:?}, notifying", addr);
                        let ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_micros() as Timestamp;
                        pong_publisher
                            .send(PongEvent {
                                addr: *addr,
                                rtt: Duration::from_millis(ts - msg.get_start_timestamp()),
                                msg,
                            })
                            .await?;
                    } else {
                        telio_log_warn!(
                            "Received pong for unknown session: {}",
                            packet.get_session()
                        );
                    }
                } else {
                    telio_log_warn!(
                        "Received pong from {:?}, No one subscribed for notifications",
                        addr
                    );
                }
            }
            p => {
                telio_log_warn!("Received unknown packet on local endpoint provider {:?}", p);
            }
        }

        Ok(())
    }
}
