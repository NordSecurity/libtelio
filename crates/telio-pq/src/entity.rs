use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use tokio::task::JoinHandle;

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
    /// Override for the default PQ upgrader IP.
    pq_upgrader_ip: Option<Ipv4Addr>,
    /// This is a key rotation task guard, its `Drop` implementation aborts the task
    _rotation_task: super::conn::ConnKeyRotation,
    keys: Option<super::Keys>,
    last_key_fetch_ts: Option<SystemTime>,
    /// First WireGuard handshake completed after `last_key_fetch_ts`.
    /// Tracked only with `rekey_attached_to_wg_handshake`.
    first_wg_handshake_ts: Option<SystemTime>,
}

impl Peer {
    fn on_key_exchange(&mut self) {
        self.last_key_fetch_ts = Some(SystemTime::now());
        self.first_wg_handshake_ts = None;
    }

    fn on_wg_handshake_age(&mut self, age: Duration) {
        if self.first_wg_handshake_ts.is_some() {
            return;
        }
        let (Some(key_exchange), Some(handshake)) =
            (self.last_key_fetch_ts, SystemTime::now().checked_sub(age))
        else {
            return;
        };
        if handshake >= key_exchange {
            self.first_wg_handshake_ts = Some(handshake);
        }
    }

    /// Start of the session that must get a PQ rekey within `REJECT_AFTER_TIME`.
    ///
    /// With kernel WireGuard a PSK change does not force a handshake, so the session
    /// keyed with the last fetched PSK starts only at the next WireGuard handshake.
    fn session_start_ts(&self) -> Option<SystemTime> {
        self.first_wg_handshake_ts.or(self.last_key_fetch_ts)
    }
}

pub struct Entity {
    features: FeaturePostQuantumVPN,
    sockets: Arc<telio_sockets::SocketPool>,
    chan: chan::Tx<super::Event>,
    peer: Arc<Mutex<Option<Peer>>>,
    rekey_event: Arc<tokio::sync::Notify>,
    /// Starts PQ rekeys after WireGuard handshakes, with `rekey_attached_to_wg_handshake`
    rekey_trigger_task: Option<JoinHandle<()>>,
}

impl Drop for Entity {
    fn drop(&mut self) {
        if let Some(task) = &self.rekey_trigger_task {
            task.abort();
        }
    }
}

impl crate::PostQuantum for Entity {
    fn keys(&self) -> Option<crate::Keys> {
        self.peer.lock().as_ref().and_then(|p| p.keys.clone())
    }

    fn is_rotating_keys(&self) -> bool {
        self.peer.lock().is_some()
    }
}

async fn filter(
    pq_peer: Arc<Mutex<Option<Peer>>>,
    mut last_handshake_ages: tokio::sync::watch::Receiver<
        HashMap<telio_model::PublicKey, Option<Duration>>,
    >,
    threshold: Duration,
    rekey_notify: Arc<tokio::sync::Notify>,
) {
    let mut last_below = true;

    loop {
        if last_handshake_ages.changed().await.is_err() {
            telio_log_debug!("WireGuard handshake times channel closed, stopping PQ rekey trigger");
            break;
        }
        let ages: HashMap<_, _> = last_handshake_ages.borrow().clone();
        let pq_pubkey = pq_peer.lock().as_ref().map(|p| p.pubkey);

        for (pk, age) in ages {
            if Some(pk) == pq_pubkey {
                if let Some(age) = age {
                    if let Some(peer) = pq_peer.lock().as_mut().filter(|p| p.pubkey == pk) {
                        peer.on_wg_handshake_age(age);
                    }
                    if age > threshold {
                        if last_below {
                            rekey_notify.notify_waiters();
                        }
                        last_below = false
                    }
                    if age <= threshold && !last_below {
                        last_below = true;
                    }
                }
            }
        }
    }
}

impl Entity {
    pub fn new(
        features: FeaturePostQuantumVPN,
        sockets: Arc<telio_sockets::SocketPool>,
        chan: chan::Tx<super::Event>,
        last_handshake_ages: tokio::sync::watch::Receiver<
            HashMap<telio_model::PublicKey, Option<Duration>>,
        >,
    ) -> Self {
        let peer = Arc::new(Mutex::new(None));
        let rekey_event = Arc::new(tokio::sync::Notify::new());
        let rekey_trigger_task = features.rekey_attached_to_wg_handshake.then(|| {
            tokio::spawn(filter(
                peer.clone(),
                last_handshake_ages,
                Duration::from_secs(features.rekey_interval_s.into()),
                rekey_event.clone(),
            ))
        });
        Self {
            features,
            sockets,
            chan,
            peer,
            rekey_event,
            rekey_trigger_task,
        }
    }

    pub fn on_event(&self, event: super::Event) {
        if let Some(peer) = self.peer.lock().as_mut() {
            match event {
                super::Event::KeyFetch(addr, keys) => {
                    if peer.addr == addr {
                        peer.keys = Some(keys);
                        peer.on_key_exchange();
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
                            // Keys are also fetched during rekey
                            peer.on_key_exchange();
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
        pq_upgrader_ip: Option<Ipv4Addr>,
    ) {
        self.stop().await;
        self.start_impl(addr, wg_secret, peer, pq_upgrader_ip).await;
    }

    /// Restart the key-rotation task without clearing the existing keys.
    ///
    /// This is the preferred action on a network change.
    /// The old `ConnKeyRotation` task is dropped and a new one is started immediately
    /// so it can open a fresh socket on the current network interface.  The existing
    /// `keys` and `last_key_fetch_ts` are preserved, so WireGuard continues to use the
    /// current preshared key while the new task performs its first rekey - avoiding a
    /// visible VPN disconnection.
    ///
    /// Does nothing if no PQ peer is currently active
    pub fn restart_rotation(&self) {
        let mut peer = self.peer.lock();
        if let Some(p) = peer.as_mut() {
            telio_log_debug!("Restarting PQ rotation task after network change");
            p._rotation_task = super::conn::ConnKeyRotation::run(
                self.chan.clone(),
                self.sockets.clone(),
                p.addr,
                p.wg_secret.clone(),
                p.pubkey,
                &self.features,
                p.pq_upgrader_ip,
                self.rekey_event.clone(),
            );
        }
    }

    // Postquantum has a quirk that can cause VPN connections to fail due to the client having a preshared key when the server doesn't.
    // This can happen if there was a handshake established with a preshared key, then the connection is broken for more than 180s
    // (the time after which wireguard will abandon an inactive connection), and then the client tries to do a new handshake with the same
    // preshared key as before. Since the server abandoned the connection, it no longer knows about that preshared key and will therefore
    // ignore the handshake, preventing a connection from being made.
    //
    // To solve this we can restart the postquantum entity if the time since the last handshake exceeds 180s, which is what this function does.
    // The postquantum peer stores a timestamp of the last handshake, which is used in this function to check whether we should restart.
    // We store the timestamp of the last handshake as a SystemTime instead of an Instant because Instant does not guarantee
    // whether time spent while the system is asleep is counted or not.
    // Since we use SystemTime, it is possible that changes to the system clock by the user may affect our measurements.
    // Because of this, we must also restart when ts.elapsed() returns an error, which happens when the elapsed() call
    // would return a negative value. The error returned contains the absolute value of the time difference.
    // We ignore values smaller than 5 seconds (chosen arbitrarily) because SystemTime does not guarantee monotonicity,
    // so it is possible that ts.elapsed() returns a small negative value when called shortly after ts was saved.
    // With `rekey_attached_to_wg_handshake` the timeout runs from the first WireGuard handshake after the last
    // key exchange (RFC LLT-0120 session termination), see `Peer::session_start_ts`.
    pub async fn maybe_restart(&self) {
        let peer = {
            let mut peer = self.peer.lock();
            let should_restart = peer
                .as_ref()
                .and_then(Peer::session_start_ts)
                .is_some_and(|ts| match ts.elapsed() {
                    Ok(dur) => dur > REJECT_AFTER_TIME,
                    Err(err) => err.duration() > Duration::from_secs(5),
                });

            if should_restart {
                peer.take()
            } else {
                None
            }
        };
        if let Some(peer) = peer {
            telio_log_debug!("Restarting postquantum entity");
            self.start_impl(peer.addr, peer.wg_secret, peer.pubkey, peer.pq_upgrader_ip)
                .await;
        }
    }

    async fn start_impl(
        &self,
        addr: SocketAddr,
        wg_secret: telio_crypto::SecretKey,
        peer: telio_crypto::PublicKey,
        pq_upgrader_ip: Option<Ipv4Addr>,
    ) {
        *self.peer.lock() = Some(Peer {
            pubkey: peer,
            wg_secret: wg_secret.clone(),
            addr,
            pq_upgrader_ip,
            _rotation_task: super::conn::ConnKeyRotation::run(
                self.chan.clone(),
                self.sockets.clone(),
                addr,
                wg_secret,
                peer,
                &self.features,
                pq_upgrader_ip,
                self.rekey_event.clone(),
            ),
            keys: None,
            last_key_fetch_ts: None,
            first_wg_handshake_ts: None,
        });

        #[allow(mpsc_blocking_send)]
        let _ = self.chan.send(super::Event::Connecting(peer)).await;
    }
}
