use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use telio_model::features::FeaturePostQuantumVPN;
use telio_task::io::chan;
use telio_utils::telio_log_debug;

// This constant is based on section 6.1 of the wireguard whitepaper
// It is the amount of time that has to happen since the last handshake before a connection is abandoned
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

struct Peer {
    pubkey: telio_crypto::PublicKey,
    wg_secret: telio_crypto::SecretKey,
    addr: SocketAddr,
    /// This is a key rotation task guard, its `Drop` implementation aborts the task
    _rotation_task: super::conn::ConnKeyRotation,
    keys: Option<super::Keys>,
    last_handshake_ts: Option<Instant>,
}

use std::fmt;

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("pubkey", &self.pubkey)
            .field("last_handshake_ts", &self.last_handshake_ts)
            .finish()
    }
}

pub struct Entity {
    features: FeaturePostQuantumVPN,
    sockets: Arc<telio_sockets::SocketPool>,
    chan: chan::Tx<super::Event>,
    peer: Mutex<Option<Peer>>,
}

impl crate::PostQuantum for Entity {
    fn keys(&self) -> Option<crate::Keys> {
        self.peer.lock().as_ref().and_then(|p| p.keys.clone())
    }

    fn is_rotating_keys(&self) -> bool {
        self.peer.lock().is_some()
    }
}

impl Entity {
    pub fn new(
        features: FeaturePostQuantumVPN,
        sockets: Arc<telio_sockets::SocketPool>,
        chan: chan::Tx<super::Event>,
    ) -> Self {
        Self {
            features,
            sockets,
            chan,
            peer: Mutex::new(None),
        }
    }

    pub fn on_event(&self, event: super::Event) {
        if let Some(peer) = self.peer.lock().as_mut() {
            telio_log_debug!("pq event: {:?} for {:?}", event, peer.pubkey);
            match event {
                super::Event::Handshake(addr, keys) => {
                    if peer.addr == addr {
                        peer.keys = Some(keys);
                        peer.last_handshake_ts = Some(Instant::now());

                        telio_log_debug!(
                            "pq handshake event, set ts to {:?} for {:?}",
                            peer.last_handshake_ts,
                            peer.pubkey
                        );
                    }
                }
                super::Event::Rekey(super::Keys {
                    wg_secret,
                    pq_shared,
                }) => {
                    if let Some(keys) = &mut peer.keys {
                        // Check if we are still talking to the same exit node
                        if keys.wg_secret == wg_secret {
                            // and only then update the preshared key,
                            // otherwise we're connecting to different node already
                            keys.pq_shared = pq_shared;
                            peer.last_handshake_ts = Some(Instant::now());
                            telio_log_debug!(
                                "pq rekey event, set ts to {:?} for {:?}",
                                peer.last_handshake_ts,
                                peer.pubkey
                            );
                        } else {
                            telio_log_debug!(
                                "PQ secret key does not match, ignoring shared secret rotation"
                            );
                        }
                    }
                }
                _ => (),
            }
        }
    }

    pub fn peer_pubkey(&self) -> Option<telio_crypto::PublicKey> {
        self.peer.lock().as_ref().map(|p| p.pubkey)
    }

    // There is some temporary event filtering around disconnected events for postquantum
    // That filtering depends heavily on the peer being removed before emitting Disconnected
    // here
    pub async fn stop(&self) {
        let peer = self.peer.lock().take();
        if let Some(peer) = peer {
            #[allow(mpsc_blocking_send)]
            let _ = self
                .chan
                .send(super::Event::Disconnected(peer.pubkey))
                .await;
        }
    }

    pub async fn start(
        &self,
        addr: SocketAddr,
        wg_secret: telio_crypto::SecretKey,
        peer: telio_crypto::PublicKey,
    ) {
        self.stop().await;
        telio_log_debug!("start {:?}", peer);
        self.start_impl(addr, wg_secret, peer).await;
    }

    // Postquantum has a quirk that can cause VPN connections to fail due to the client having a preshared key when the server doesn't.
    // This can happen if there was a handshake established with a preshared key, then the connection is broken for more than 180s
    // (the time after which wireguard will abandon an inactive connection), and then the client tries to do a new handshake with the same
    // preshared key as before. Since the server abandoned the connection, it no longer knows about that preshared key and will therefore
    // ignore the handshake, preventing a connection from being made.
    //
    // To solve this we can restart the postquantum entity if the time since the last handshake exceeds 180s, which is what this function does.
    // The postquantum peer stores a timestamp of the last handshake, which is used in this function to check whether we should restart.
    pub async fn maybe_restart(&self) {
        let peer = {
            let mut peer = self.peer.lock();
            telio_log_debug!("Maybe restart PQ. Peer: {:?}", peer);
            let should_restart = peer
                .as_ref()
                .and_then(|peer| peer.last_handshake_ts)
                .is_some_and(|ts| ts.elapsed() > REJECT_AFTER_TIME);
            if should_restart {
                peer.take()
            } else {
                None
            }
        };
        if let Some(peer) = peer {
            telio_log_debug!("Restarting postquantum entity");
            self.start_impl(peer.addr, peer.wg_secret, peer.pubkey)
                .await;
        }
    }

    async fn start_impl(
        &self,
        addr: SocketAddr,
        wg_secret: telio_crypto::SecretKey,
        peer: telio_crypto::PublicKey,
    ) {
        *self.peer.lock() = Some(Peer {
            pubkey: peer,
            wg_secret: wg_secret.clone(),
            addr,
            _rotation_task: super::conn::ConnKeyRotation::run(
                self.chan.clone(),
                self.sockets.clone(),
                addr,
                wg_secret,
                peer,
                &self.features,
            ),
            keys: None,
            last_handshake_ts: None,
        });

        #[allow(mpsc_blocking_send)]
        let _ = self.chan.send(super::Event::Connecting(peer)).await;
    }
}
