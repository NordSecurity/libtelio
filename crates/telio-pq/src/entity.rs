use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;

use telio_model::features::FeaturePostQuantumVPN;
use telio_task::io::chan;
use telio_utils::telio_log_debug;

struct Peer {
    pubkey: telio_crypto::PublicKey,
    wg_secret: telio_crypto::SecretKey,
    addr: SocketAddr,
    /// This is a key rotation task guard, its `Drop` implementation aborts the task
    _rotation_task: super::conn::ConnKeyRotation,
    keys: Option<super::Keys>,
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
            match event {
                super::Event::Handshake(addr, keys) => {
                    if peer.addr == addr {
                        peer.keys = Some(keys);
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
        self.start_impl(addr, wg_secret, peer).await;
    }

    pub async fn restart(&self) {
        let peer = self.peer.lock().take();
        if let Some(peer) = peer {
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
        });

        #[allow(mpsc_blocking_send)]
        let _ = self.chan.send(super::Event::Connecting(peer)).await;
    }
}
