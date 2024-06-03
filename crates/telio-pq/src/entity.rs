use std::net::SocketAddr;
use std::sync::Arc;

use telio_model::features::FeaturePostQuantumVPN;
use telio_task::io::chan;
use telio_utils::{telio_log_debug, telio_log_generic};

struct Peer {
    addr: SocketAddr,
    /// This is a key rotation task guard, its `Drop` implementation aborts the task
    _rotation_task: super::conn::ConnKeyRotation,
    keys: Option<super::Keys>,
}

pub struct Entity {
    features: FeaturePostQuantumVPN,
    sockets: Arc<telio_sockets::SocketPool>,
    chan: chan::Tx<super::Event>,
    peer: Option<Peer>,
}

impl crate::PostQuantum for Entity {
    fn keys(&self) -> Option<crate::Keys> {
        self.peer.as_ref().and_then(|p| p.keys)
    }

    fn is_rotating_keys(&self) -> bool {
        self.peer.is_some()
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
            peer: None,
        }
    }

    pub fn on_event(&mut self, event: super::Event) {
        let Some(peer) = &mut self.peer else {
            return;
        };

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
        }
    }

    pub fn stop(&mut self) {
        self.peer = None;
    }

    pub fn start(
        &mut self,
        addr: SocketAddr,
        wg_secret: telio_crypto::SecretKey,
        peer: telio_crypto::PublicKey,
    ) {
        self.peer = Some(Peer {
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
    }
}
