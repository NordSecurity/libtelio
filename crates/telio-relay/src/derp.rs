//! This Task is used for communicating with Derp.
//!
//! It manages connections to Derp servers, acting as a mid point between Multiplexer module
//! and actual server.
//!
//! Task is started with `DerpRelay::start_with()` and configured with `configure(config)`, where
//! config contains sorted list of servers, the module will try to connect to them one at a time
//! until first connection is made. For other configuration values, see `Config` description

pub mod http;
pub mod proto;

use async_trait::async_trait;
use futures::{future::select_all, Future};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use telio_crypto::{PublicKey, SecretKey};
use telio_model::config::{DerpAnalyticsEvent, RelayConnectionChangeReason};
use telio_model::{
    config::{RelayState, Server},
    features::FeatureDerp,
};
#[mockall_double::double]
use telio_nurse::aggregator::ConnectivityDataAggregator;
use telio_proto::{
    Codec, DerpPollRequestMsg, PacketControl, PacketRelayed, PacketTypeRelayed, PeersStatesMap,
    Session,
};
use telio_sockets::SocketPool;
use telio_task::io::{wait_for_tx, Chan};
use telio_task::{io::mc_chan::Tx, task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    telio_err_with_log, telio_log_debug, telio_log_error, telio_log_info, telio_log_trace,
    telio_log_warn,
};
use tokio::sync::mpsc::OwnedPermit;
use tokio::{task::JoinHandle, time::sleep};

use crypto_box::aead::{
    generic_array::{typenum::Unsigned, GenericArray},
    AeadCore, Error, Payload,
};
use telio_crypto::chachabox::ChaChaBox;

use rand::rngs::StdRng;
use smart_default::SmartDefault;

use self::{http::connect_http_and_start, http::DerpConnection};

pub use self::proto::Error as DerpError;

/// Helper container structure for specific server ordering
#[derive(Clone, Debug, Default)]
pub struct SortedServers {
    servers: Vec<Server>,
    current_server_num: usize,
}

impl SortedServers {
    /// Create SortedServers with default server sorting - by their weight
    pub fn new(mut servers: Vec<Server>) -> Self {
        servers.sort_by(|a, b| a.weight.cmp(&b.weight));
        Self {
            servers,
            current_server_num: 0,
        }
    }

    fn get_next(&mut self) -> Option<Server> {
        if self.current_server_num < self.servers.len() {
            let result = self.servers.get(self.current_server_num).cloned();
            self.current_server_num += 1;
            result
        } else {
            None
        }
    }

    fn contains(&self, server: &Server) -> bool {
        self.servers.contains(server)
    }

    fn reset_server_index(&mut self) {
        self.current_server_num = 0;
    }
}

impl PartialEq for SortedServers {
    fn eq(&self, other: &Self) -> bool {
        self.servers == other.servers
    }
}

/// Derp task exposed to other crates
pub struct DerpRelay {
    task: Task<State>,
}

struct State {
    /// Channel, that communicates with upper multiplexer module
    channel: Option<Chan<(PublicKey, PacketRelayed)>>,
    /// Derp configuration
    config: Option<Config>,
    /// Connection object
    conn: Option<DerpConnection>,
    /// Event Tx
    event: Tx<Box<Server>>,
    /// Connected server
    server: Option<Server>,
    /// Used on cryptography Nonce
    rng: StdRng,
    /// Used to get external sockets
    socket_pool: Arc<SocketPool>,
    /// Used to match derp poll request with response
    derp_poll_session: Session,
    /// Cache the result of derp polling
    remote_peers_states: PeersStatesMap,
    /// Connectivity data aggregator
    aggregator: Option<Arc<ConnectivityDataAggregator>>,

    last_disconnection_reason: RelayConnectionChangeReason,

    connecting: Option<JoinHandle<(Server, DerpConnection)>>,
}

/// Keepalive values that help keeping Derp connection in conntrack alive,
/// so server can send traffic after being silent for a while
/// *derp_keepalive* is also used as an interval for retrieving remote peer states.
/// PollKeepalive is a feature that is meant to replace TCP keepalives with
/// application level keepalives (DerpPollRequest).
/// More info on PollKeepalive can be found in RFC-LLT-0070
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerpKeepaliveConfig {
    tcp_keepalive: u32,
    derp_keepalive: u32,
    poll_keepalive: bool,
}

impl From<&Option<FeatureDerp>> for DerpKeepaliveConfig {
    fn from(derp: &Option<FeatureDerp>) -> Self {
        let mut tcp_keepalive = proto::DERP_TCP_KEEPALIVE_INTERVAL;
        let mut derp_keepalive = proto::DERP_KEEPALIVE_INTERVAL;
        let mut poll_keepalive = false;
        if let Some(derp) = derp {
            if let Some(tcp_ka) = derp.tcp_keepalive {
                tcp_keepalive = tcp_ka;
            }
            if let Some(derp_ka) = derp.derp_keepalive {
                derp_keepalive = derp_ka;
            }
            poll_keepalive = derp.poll_keepalive.unwrap_or_default();
        }

        DerpKeepaliveConfig {
            tcp_keepalive,
            derp_keepalive,
            poll_keepalive,
        }
    }
}

const DEFAULT_SERVER_KEEPALIVE_CONFIG: DerpKeepaliveConfig = DerpKeepaliveConfig {
    tcp_keepalive: proto::DERP_TCP_KEEPALIVE_INTERVAL,
    derp_keepalive: proto::DERP_KEEPALIVE_INTERVAL,
    poll_keepalive: false,
};

/// Derp configuration
#[derive(Debug, Clone, PartialEq, SmartDefault)]
pub struct Config {
    /// Secret key of local node which is used for encryption/decryption of messages to other nodes
    pub secret_key: SecretKey,
    /// List of potential Derp servers
    pub servers: SortedServers,
    /// Remote peer list that we accept traffic from
    pub meshnet_peers: HashSet<PublicKey>,
    /// Timeout used for connecting to derp server
    #[default(proto::TCP_CONNECT_TIMEOUT)]
    pub timeout: Duration,
    /// Keepalive values for derp connection
    #[default(DEFAULT_SERVER_KEEPALIVE_CONFIG)]
    pub server_keepalives: DerpKeepaliveConfig,
    /// Enable mechanism for turning off keepalive to offline peers
    pub enable_polling: bool,
    /// Use Mozilla's root certificates instead of OS ones [default false]
    pub use_built_in_root_certificates: bool,
}

impl State {
    async fn disconnect(&mut self) {
        // Stop attempts to connect
        if let Some(c) = self.connecting.take() {
            c.abort();
            let _ = c.await;
        }
        // Stop current connection
        if let Some(c) = self.conn.take() {
            c.stop();
        }
        // kill server
        if let Some(mut server) = self.server.take() {
            telio_log_debug!("({}) Disconnected from DERP server!", Self::NAME);
            server.conn_state = RelayState::Disconnected;
            let _ = self.event.send(Box::new(server));
        }
        self.server = None;
    }

    fn start_connecting(&self, mut config: Config) -> JoinHandle<(Server, DerpConnection)> {
        let event = self.event.clone();
        let socket_pool = self.socket_pool.clone();

        let aggregator = self.aggregator.clone();
        let mut last_disconnection_reason = self.last_disconnection_reason;

        let connection = async move {
            let mut sleep_time = 1f64;
            loop {
                let mut server = match config.servers.get_next() {
                    Some(server) => {
                        telio_log_debug!(
                            "({}) Trying to connect to DERP server: {}",
                            Self::NAME,
                            &server.get_address()
                        );
                        server
                    }
                    None => {
                        telio_log_info!(
                            "({}) Server list exhausted sleeping for: {}",
                            Self::NAME,
                            sleep_time
                        );
                        config.servers.reset_server_index();
                        sleep(Duration::from_secs_f64(sleep_time)).await;
                        sleep_time = (sleep_time * 2f64).min(60f64);
                        continue;
                    }
                };

                server.conn_state = RelayState::Connecting;
                let _ = event.send(Box::new(server.clone()));
                if let Some(aggregator) = aggregator.as_ref() {
                    aggregator
                        .change_relay_state(DerpAnalyticsEvent::new(
                            &server,
                            last_disconnection_reason,
                        ))
                        .await;
                }

                // Try to establish connection
                match Box::pin(connect_http_and_start(
                    socket_pool.clone(),
                    &server.get_address(),
                    SocketAddr::new(IpAddr::V4(server.ipv4), server.relay_port),
                    config.clone(),
                ))
                .await
                {
                    Ok(conn) => {
                        telio_log_info!("({}) Connected to {}", Self::NAME, server.get_address());
                        server.conn_state = RelayState::Connected;
                        if let Some(aggregator) = aggregator.as_ref() {
                            aggregator
                                .change_relay_state(DerpAnalyticsEvent::new(
                                    &server,
                                    RelayConnectionChangeReason::ConfigurationChange,
                                ))
                                .await;
                        }
                        break (server, conn);
                    }
                    Err(err) => {
                        if config.servers.current_server_num == config.servers.servers.len() {
                            telio_log_warn!(
                                "({}) Failed to connect to any of {} servers: {}",
                                Self::NAME,
                                config.servers.servers.len(),
                                err
                            );
                        }
                        last_disconnection_reason = err.into();
                        continue;
                    }
                }
            }
        };
        tokio::spawn(connection)
    }
}

impl DerpRelay {
    /// Relay's constructor
    pub fn start_with(
        channel: Chan<(PublicKey, PacketRelayed)>,
        socket_pool: Arc<SocketPool>,
        event: Tx<Box<Server>>,
        aggregator: Option<Arc<ConnectivityDataAggregator>>,
    ) -> Self {
        // generate random number used to encrypt control messages
        let rng: StdRng = rand::make_rng();

        Self {
            task: Task::start(State {
                channel: Some(channel),
                config: None,
                conn: None,
                event,
                server: None,
                rng,
                socket_pool,
                derp_poll_session: 0,
                remote_peers_states: HashMap::new(),
                connecting: None,
                last_disconnection_reason: RelayConnectionChangeReason::ConfigurationChange,
                aggregator,
            }),
        }
    }

    /// Change DERP config
    pub async fn configure(&self, config: Option<Config>) {
        let _ = task_exec!(&self.task, async move |s| {
            if s.config == config {
                // Nothing todo here
                return Ok(());
            }

            s.config = config;

            // Prepare new config
            if let Some(config) = s.config.as_mut() {
                // TODO: This logic should most likely linked with wg_stun_controll
                // Restart connection
                match s.server.as_ref() {
                    Some(server) => {
                        // Current server not found in new config or server no config
                        if !config.servers.contains(server) {
                            telio_log_info!("Currently active server is no longer available in config - reconnecting.");
                            s.disconnect().await;
                        }
                    }
                    None => {
                        // Disconnect and start from the top of the list
                        telio_log_info!("No active relay server. Reconnecting.");
                        s.disconnect().await;
                    }
                }
            }

            Ok(())
        })
        .await;
    }

    /// Get current Derp configuration
    pub async fn get_config(&self) -> Option<Config> {
        task_exec!(&self.task, async move |s| Ok(s.config.as_ref().cloned()))
            .await
            .ok()
            .flatten()
    }

    /// Get current connection state (connected/disconnected)
    pub async fn get_conn_state(&self) -> bool {
        task_exec!(&self.task, async move |s| Ok(s.conn.is_some()))
            .await
            .ok()
            .unwrap_or(false)
    }

    /// Get server we are currently connected to.
    /// Returns None if we are not connected
    pub async fn get_connected_server(&self) -> Option<Server> {
        task_exec!(&self.task, async move |s| Ok(s.server.clone()))
            .await
            .ok()
            .unwrap_or(None)
    }

    /// Get newest information about remote peer states
    pub async fn get_remote_peer_states(&self) -> PeersStatesMap {
        task_exec!(&self.task, async move |s| Ok(s.remote_peers_states.clone()))
            .await
            .ok()
            .unwrap_or_default()
    }

    /// Try reconnect
    pub async fn reconnect(&self) {
        let _ = task_exec!(&self.task, async move |s| {
            telio_log_info!("Explicit relay reconnect requested");
            s.disconnect().await;
            Ok(())
        })
        .await;
    }

    /// Stop relay
    pub async fn stop(self) {
        let _ = self.task.stop().await;
    }

    // Routines related with encryption exclusively of control
    // messages over Derp server e.g. pinger

    // Putting all nonce information in one place
    const NONCE_SIZE: usize = <ChaChaBox as AeadCore>::NonceSize::USIZE;
    const NONCE_BEGIN_POS: usize = 1;
    const NONCE_END_POS: usize = DerpRelay::NONCE_SIZE + 1;

    /// Used to encrypt control messages to send through
    /// a Derp connection
    ///
    /// public key         -> foreign public key
    /// secret key         -> node private key
    /// encrypted_message  -> received encrypted message
    /// associated_data    -> 0x05 + some information
    ///
    /// return message  including: type (0x05) + Nonce + payload
    /// Or Error
    fn encrypt_if_needed(
        secret_key: SecretKey,
        public_key: PublicKey,
        rng: &mut StdRng,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // In case is a data package already encrypted by wireguard skip

        if PacketTypeRelayed::from(if let Some(d) = data.first() {
            *d
        } else {
            telio_log_error!("Invalid buffer");
            return Err(crypto_box::aead::Error);
        }) == PacketTypeRelayed::Data
        {
            return Ok(data.to_vec());
        }

        // new Box and convert telio-key to crypto_box format
        let secret_box = ChaChaBox::new(&public_key, &secret_key);
        let nonce = ChaChaBox::generate_nonce(rng);
        // Encrypt the message using the box
        match secret_box.encrypt(
            &nonce,
            Payload {
                msg: data,
                // for now AAD is empty
                aad: "".as_ref(),
            },
        ) {
            Ok(mut cipher_text) => {
                // include encrypt message type
                let mut message = vec![PacketTypeRelayed::Encrypted as u8];
                // include nonce
                message.append(&mut nonce.as_slice().to_vec());
                // include ciphered payload
                message.append(&mut cipher_text);
                // return  message type (0x05) + Nonce ( next 24 bytes) + encrypted payload
                Ok(message)
            }
            Err(error) => telio_err_with_log!(error),
        }
    }

    /// Associated function used to decrypt control messages
    /// received by a foreign node
    ///
    /// public_key : foreign public key
    /// secret_key : node private key
    /// data       : received encrypted message
    ///
    /// return the plain text
    fn decrypt_if_needed(
        secret_key: SecretKey,
        public_key: PublicKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Data packages are treated by Wireguard encryption System
        // In this case any encryption operation is skipped for those.
        match PacketTypeRelayed::from(if let Some(d) = data.first() {
            *d
        } else {
            telio_log_error!("Invalid buffer");
            return Err(crypto_box::aead::Error);
        }) {
            PacketTypeRelayed::Data => {
                telio_log_trace!(
                    "Encryption not necessary : {:?} ...",
                    &data.chunks(8).next().unwrap_or_default()
                );
                Ok(data.to_vec())
            }
            PacketTypeRelayed::Encrypted => {
                // Extract nonce always with exactly 24 bytes from byte 1 to 24
                let nonce = GenericArray::from_slice(
                    data.get(DerpRelay::NONCE_BEGIN_POS..DerpRelay::NONCE_END_POS)
                        .ok_or(crypto_box::aead::Error)?,
                );
                telio_log_trace!(
                    "Rx encrypted data: {:?} ...",
                    &data.chunks(8).next().unwrap_or_default()
                );

                // extract payload to be decrypted from byte 25 till end of data
                // what is data + ADD which always come appended to the end
                let cipher_text = data
                    .get(DerpRelay::NONCE_END_POS..data.len())
                    .ok_or(crypto_box::aead::Error)?;

                let secret_box = ChaChaBox::new(&public_key, &secret_key);

                match secret_box.decrypt(
                    nonce,
                    Payload {
                        msg: cipher_text,
                        // for now AAD is empty
                        aad: "".as_ref(),
                    },
                ) {
                    Ok(plain_text) => {
                        telio_log_trace!(
                            "Data after decryption: {:?}",
                            &plain_text.chunks(8).next().unwrap_or_default()
                        );
                        Ok(plain_text)
                    }
                    Err(error) => telio_err_with_log!(error),
                }
            }
            _ => {
                telio_log_error!("Malformed / Not encrypted package");
                Err(crypto_box::aead::Error)
            }
        }
    }
}

impl State {
    /// handle traffic for |LocalNode -> Derp -> RemoteNode|
    async fn handle_outcoming_payload_relayed(
        permit: OwnedPermit<(PublicKey, Vec<u8>)>,
        pk: PublicKey,
        msg: PacketRelayed,
        config: &Config,
        rng: &mut StdRng,
    ) {
        // TODO add custom task's log format macro
        telio_log_trace!(
            "({}) Tx --> DERP, pubkey: {:?}, packet type: {:?}",
            Self::NAME,
            pk,
            msg.packet_type()
        );
        match msg.encode() {
            Ok(buf) => match DerpRelay::encrypt_if_needed(config.secret_key.clone(), pk, rng, &buf)
            {
                Ok(cipher_text) => {
                    let _ = permit.send((pk, cipher_text));
                }
                Err(error) => {
                    telio_log_debug!("({}) Encryption failed: {}", Self::NAME, error);
                }
            },
            Err(e) => {
                telio_log_debug!("({}) Failed to encode packet: {}", Self::NAME, e);
            }
        }
    }

    /// handle traffic for |LocalNode -> Derp|
    async fn handle_outcoming_payload_direct(permit: OwnedPermit<Vec<u8>>, msg: PacketControl) {
        telio_log_trace!(
            "({}) Tx --> DERP, packet type: {:?}",
            Self::NAME,
            msg.packet_type()
        );
        match msg.encode() {
            Ok(buf) => {
                let _ = permit.send(buf.to_vec());
            }
            Err(e) => {
                telio_log_debug!("({}) Failed to encode packet: {}", Self::NAME, e);
            }
        }
    }

    /// handle traffic for |RemoteNode -> Derp -> LocalNode|
    async fn handle_incoming_payload_relayed(
        permit: OwnedPermit<(PublicKey, PacketRelayed)>,
        pk: PublicKey,
        buf: Vec<u8>,
        config: &Config,
    ) {
        if config.meshnet_peers.contains(&pk) {
            match DerpRelay::decrypt_if_needed(config.secret_key.clone(), pk, &buf) {
                Ok(plain_text) => match PacketRelayed::decode(&plain_text) {
                    Ok(msg) => {
                        telio_log_trace!(
                            "({}) DERP --> Rx, pubkey: {:?}, len: {}, packet type: {:?}",
                            Self::NAME,
                            pk,
                            buf.len(),
                            msg.packet_type()
                        );
                        permit.send((pk, msg));
                    }
                    Err(e) => {
                        telio_log_debug!(
                            "({}) DERP --> Rx, failed to parse packet: ({})",
                            Self::NAME,
                            e
                        );
                    }
                },
                Err(error) => {
                    telio_log_debug!("Decryption failed: {}", error);
                }
            }
        } else {
            telio_log_debug!(
                "({}) DERP --> Rx, received a packet with unknown pubkey: {}",
                Self::NAME,
                pk
            );
        }
    }

    /// handle traffic for |Derp -> LocalNode|
    async fn handle_incoming_payload_direct(
        expected_session: Session,
        buf: Vec<u8>,
    ) -> Option<HashMap<PublicKey, bool>> {
        match PacketControl::decode(buf.as_slice()) {
            Ok(msg) => match msg {
                PacketControl::DerpPollResponse(derp_poll_response) => {
                    if derp_poll_response.get_session() != expected_session {
                        telio_log_debug!(
                            "Invalid session for incoming derp poll response: {}, expected: {}",
                            derp_poll_response.get_session(),
                            expected_session
                        );
                        return None;
                    }
                    Some(derp_poll_response.get_peers_statuses())
                }
                _ => {
                    telio_log_debug!(
                        "({}) DERP --> Rx, unexpected packet type: {:?}",
                        Self::NAME,
                        msg.packet_type()
                    );
                    None
                }
            },
            Err(e) => {
                telio_log_debug!(
                    "({}) DERP --> Rx, failed to decode derp poll response packet: ({}), bytes: {:?}",
                    Self::NAME,
                    e,
                    buf
                );
                None
            }
        }
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "DerpRelay";

    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
    {
        // Only react to updates without config
        let config = match self.config.as_ref() {
            Some(c) => c,
            None => {
                telio_log_info!("Disconnecting from DERP server due to empty config");
                self.disconnect().await;
                return (update.await)(self).await;
            }
        };

        match &mut self.conn {
            Some(c) => {
                let (upper_read, chan_tx) = match self.channel.as_mut() {
                    Some(chan) => (chan.rx.recv(), &chan.tx),
                    None => {
                        // Similar case to config, but the log is already printed
                        return (update.await)(self).await;
                    }
                };

                if let Some(connecting) = self.connecting.take() {
                    connecting.abort();
                }

                let derp_relayed_read = c.comms_relayed.rx.recv();
                let derp_direct_read = c.comms_direct.rx.recv();
                let conn_join = select_all([&mut c.join_sender, &mut c.join_receiver]);
                let poll_timer_tick = c.poll_timer.tick();

                tokio::select! {
                    // Connection returned, reconnect
                    (err, _, _) = conn_join => {
                        telio_log_info!("Disconnecting from DERP server, due to transmission tasks error");

                        self.last_disconnection_reason = match err {
                            Ok(Ok(())) => {
                                let reason = RelayConnectionChangeReason::ConfigurationChange;
                                telio_log_debug!("DERP transmission task error -> {reason:?}");
                                reason
                            },
                            Ok(Err(err)) => {
                                telio_log_debug!("DERP transmission task error: {:?}", err);
                                err.into()
                            },
                            Err(join_err) => {
                                let reason = RelayConnectionChangeReason::ClientError;
                                telio_log_debug!("DERP transmission task join error: {:?} -> {reason:?}", join_err);
                                reason
                            },
                        };
                        self.disconnect().await;
                    },
                    // Received payload from upper relay, forward it to DERP stream
                    res = wait_for_tx(&c.comms_relayed.tx, upper_read) => match res {
                        Some((permit, Some((pk, msg)))) => {
                            Self::handle_outcoming_payload_relayed(permit, pk, msg, config, &mut self.rng).await;
                        },
                        Some((_, None)) => {
                            telio_log_debug!("Disconnecting from DERP server due to closed rx channel");
                            self.channel = None;
                            self.last_disconnection_reason = RelayConnectionChangeReason::ClientError;
                            self.disconnect().await;
                        }
                        // If forwarding fails, disconnect
                        None => {
                            telio_log_info!("Disconnecting from DERP server");
                            self.last_disconnection_reason = RelayConnectionChangeReason::ClientError;
                            self.disconnect().await;
                        }
                    },
                    // On tick send derp poll request to derp stream
                    Some((permit, _)) = wait_for_tx(&c.comms_direct.tx, poll_timer_tick) => {
                        if config.enable_polling || config.server_keepalives.poll_keepalive {
                            self.derp_poll_session = self.derp_poll_session.wrapping_add(1);
                            telio_log_debug!("Sending DerpPollRequest with session {}", self.derp_poll_session);
                            Self::handle_outcoming_payload_direct(permit, PacketControl::DerpPollRequest(DerpPollRequestMsg::new(
                                self.derp_poll_session, &config.meshnet_peers
                            ))).await;
                        }
                    }
                    // Received payload from DERP stream, forward it to upper relay
                    Some((permit, Some((pk, buf)))) = wait_for_tx(chan_tx, derp_relayed_read) => {
                        Self::handle_incoming_payload_relayed(permit, pk, buf, config).await;
                    },
                    Some((_, Some(buf))) = wait_for_tx(chan_tx, derp_direct_read) => {
                        self.remote_peers_states = Self::handle_incoming_payload_direct(self.derp_poll_session, buf).await.unwrap_or_default();
                        telio_log_debug!("Remote peers statuses: {:?}", self.remote_peers_states);
                    }

                    update = update => return update(self).await,

                    else => (),
                }

                Ok(())
            }
            None => {
                if self.channel.is_none() {
                    return (update.await)(self).await;
                }

                let connecting = if let Some(connecting) = &mut self.connecting {
                    connecting
                } else {
                    let connection = self.start_connecting(config.clone());
                    self.connecting.insert(connection)
                };

                tokio::pin!(connecting);

                tokio::select! {
                    res = connecting => {
                        match res {
                            Ok((server, conn)) => {
                                self.server = Some(server.clone());
                                self.conn = Some(conn);
                                if let Err(err) = self.event.send(Box::new(server.clone())) {
                                    telio_log_warn!("({}) sending new server info failed {}", Self::NAME, err)
                                }
                            }
                            Err(err) => {
                                self.last_disconnection_reason = RelayConnectionChangeReason::ClientError;
                                telio_log_warn!("({}) connecting task failed {}", Self::NAME, err)
                            }
                        }
                    }
                    update = update => update(self).await?,
                }
                Ok(())
            }
        }
    }

    async fn stop(mut self) {
        // Abort the connection tasks
        telio_log_info!("Stopping relay");
        self.disconnect().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use telio_nurse::aggregator::MockConnectivityDataAggregator;
    use telio_proto::DataMsg;
    use telio_sockets::NativeProtector;
    use telio_task::io::McChan;
    use telio_test::await_timeout;
    use tokio::time::timeout;

    struct DerpTestConfig {
        pub payload: PacketRelayed,
        pub private_key: SecretKey,
    }
    impl DerpTestConfig {
        pub fn new() -> Self {
            Self {
                payload: PacketRelayed::Data(DataMsg::new(b"seniuuukastavepinginu!")),
                private_key: "mLB63f78Mx9QEEIi8z+hoKk4v/X0P98M3FcFJZ8o6gA="
                    .parse::<SecretKey>()
                    .unwrap(),
            }
        }
    }

    #[test]
    fn test_server_hostname() {
        let server = Server {
            hostname: "example.com".to_string(),
            relay_port: 1111,
            use_plain_text: false,
            ..Default::default()
        };
        assert_eq!("https://example.com:1111", server.get_address());

        let server = Server {
            hostname: "example.com".to_string(),
            relay_port: 1111,
            use_plain_text: true,
            ..Default::default()
        };
        assert_eq!("http://example.com:1111", server.get_address());
    }

    #[test]
    fn test_server_selection() {
        let first = Server {
            weight: 11,
            ..Default::default()
        };

        let second = Server {
            relay_port: 8765,
            weight: 22,
            ..Default::default()
        };

        let third = Server {
            weight: 33,
            ..Default::default()
        };

        let test_conf = DerpTestConfig::new();

        let mut config = Config {
            secret_key: test_conf.private_key,
            servers: SortedServers::new(vec![third.clone(), first.clone(), second.clone()]),
            ..Default::default()
        };

        // Compare only wights, because of the 'weight' field
        assert_eq!(first.weight, config.servers.get_next().unwrap().weight);
        assert_eq!(second.weight, config.servers.get_next().unwrap().weight);
        assert_eq!(third.weight, config.servers.get_next().unwrap().weight);
        assert_eq!(None, config.servers.get_next());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "derp cannot connect to real host"]
    async fn test_derp_fallback() {
        let test_conf = DerpTestConfig::new();

        let config = Config {
            secret_key: test_conf.private_key,
            servers: SortedServers::new(vec![
                // Should NOT work
                Server {
                    hostname: "ab1234.notnordvpn.com".into(),
                    relay_port: 9999,
                    weight: 5,
                    ..Default::default()
                },
                // Should work
                Server {
                    hostname: "de1047.nordvpn.com".into(),
                    relay_port: 8765,
                    weight: 7,
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        let McChan {
            rx: mut devent_rx,
            tx: devent_tx,
        } = McChan::default();

        let (_derp_outter_ch, derp_inner_ch) = Chan::pipe();

        let mocked_aggregator = MockConnectivityDataAggregator::default();

        let test_derp = DerpRelay::start_with(
            derp_inner_ch,
            Arc::new(SocketPool::new(
                NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    false,
                )
                .unwrap(),
            )),
            devent_tx,
            Some(Arc::new(mocked_aggregator)),
        );
        test_derp.configure(Some(config)).await;

        let derp_event = timeout(Duration::from_secs(1), devent_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(RelayState::Connected, derp_event.conn_state);
        await_timeout!(test_derp.stop());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "does not stop on assertion"]
    async fn test_retries_exhausted() {
        let test_conf = DerpTestConfig::new();

        let config = Config {
            secret_key: test_conf.private_key,
            servers: SortedServers::new(vec![
                // Should NOT work
                Server {
                    hostname: "ab1234.nordvpn.com".into(),
                    relay_port: 8765,
                    weight: 1,
                    ..Default::default()
                },
                // Should NOT work
                Server {
                    hostname: "ab1235.nordvpn.com".into(),
                    relay_port: 8765,
                    weight: 2,
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        let McChan {
            rx: mut devent_rx,
            tx: devent_tx,
        } = McChan::default();

        let (_derp_outter_ch, derp_inner_ch) = Chan::pipe();

        let mocked_aggregator = MockConnectivityDataAggregator::default();

        let test_derp = DerpRelay::start_with(
            derp_inner_ch,
            Arc::new(SocketPool::new(
                NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    false,
                )
                .unwrap(),
            )),
            devent_tx,
            Some(Arc::new(mocked_aggregator)),
        );
        test_derp.configure(Some(config)).await;

        let derp_event = timeout(Duration::from_secs(1), devent_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(RelayState::Connecting, derp_event.conn_state);
        await_timeout!(test_derp.stop());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "derp cannot connect to real host"]
    async fn test_derp_read_write() {
        let test_conf = DerpTestConfig::new();

        let McChan {
            rx: mut devent_rx,
            tx: devent_tx,
        } = McChan::default();

        let config = Config {
            secret_key: test_conf.private_key.clone(),
            servers: SortedServers::new(vec![Server {
                hostname: "de1047.nordvpn.com".into(),
                relay_port: 8765,
                ..Default::default()
            }]),
            ..Default::default()
        };

        let (mut derp_outer_ch, derp_inner_ch) = Chan::pipe();

        let mocked_aggregator = MockConnectivityDataAggregator::default();

        let test_derp = DerpRelay::start_with(
            derp_inner_ch,
            Arc::new(SocketPool::new(
                NativeProtector::new(
                    #[cfg(target_os = "macos")]
                    false,
                )
                .unwrap(),
            )),
            devent_tx,
            Some(Arc::new(mocked_aggregator)),
        );
        test_derp.configure(Some(config)).await;

        let derp_event = await_timeout!(devent_rx.recv()).unwrap();
        assert_eq!(RelayState::Connected, derp_event.conn_state);

        await_timeout!(derp_outer_ch
            .tx
            .send((test_conf.private_key.public(), test_conf.payload.clone())))
        .unwrap();

        assert_eq!(
            await_timeout!(derp_outer_ch.rx.recv()).unwrap(),
            ((test_conf.private_key.public(), test_conf.payload.clone()))
        );

        await_timeout!(test_derp.stop());
    }
}
