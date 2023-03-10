pub mod http;
pub mod proto;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::io::RawSocket;

use async_trait::async_trait;
use futures::FutureExt;
use futures::{future::select_all, Future};
use generic_array::typenum::Unsigned;
use serde::{Deserialize, Serialize};
use telio_crypto::{PublicKey, SecretKey};
use telio_proto::{Codec, Packet, PacketType};
use telio_sockets::SocketPool;
use telio_task::io::{wait_for_tx, Chan};
use telio_task::{io::mc_chan::Tx, task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    telio_err_with_log, telio_log_debug, telio_log_error, telio_log_info, telio_log_trace,
    telio_log_warn,
};
use tokio::time::sleep;

use crypto_box::{
    aead::{Aead, AeadCore, Error, Nonce, Payload},
    ChaChaBox,
};

use core::result::Result;
use generic_array::GenericArray;
use rand::{rngs::StdRng, SeedableRng};

use self::{http::connect_http_and_start, http::DerpConnection, http::Protect};

pub use self::{proto::Error as DerpError, proto::FrameChannel};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayState {
    Disconnected,
    Connecting,
    Connected,
}

impl Default for RelayState {
    fn default() -> RelayState {
        RelayState::Disconnected
    }
}

pub struct Event {
    pub server: Option<Server>,
}

pub struct DerpRelay {
    task: Task<State>,
}

struct State {
    /// Channel, that communicates with upper multiplexer module
    channel: Chan<(PublicKey, Packet)>,
    /// Derp configuration
    config: Config,
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub secret_key: SecretKey,
    pub servers: Vec<Server>,
    pub allowed_pk: HashSet<PublicKey>,
    pub timeout: Duration,
    pub ca_pem_path: Option<PathBuf>,
    pub mesh_ip: IpAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Server {
    pub region_code: String,
    pub name: String,
    pub hostname: String,
    pub ipv4: Ipv4Addr,
    pub relay_port: u16,
    pub stun_port: u16,
    #[serde(default)]
    pub stun_plaintext_port: u16,
    pub public_key: PublicKey,
    pub weight: u32,

    #[serde(default)]
    pub conn_state: RelayState,

    #[serde(default)]
    pub use_plain_text: bool,

    #[serde(default)]
    pub used: bool,
}

impl PartialEq for Server {
    // Ignore fields used by DerpRelay itself only
    fn eq(&self, other: &Self) -> bool {
        self.region_code == other.region_code
            && self.name == other.name
            && self.hostname == other.hostname
            && self.ipv4 == other.ipv4
            && self.relay_port == other.relay_port
            && self.stun_port == other.stun_port
            && self.stun_plaintext_port == other.stun_plaintext_port
            && self.public_key == other.public_key
            && self.use_plain_text == other.use_plain_text
        // Do not compare weights, priority for connection persistence
        // && self.weight == other.weight
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout: proto::TCP_CONNECT_TIMEOUT,
            secret_key: Default::default(),
            allowed_pk: Default::default(),
            servers: Default::default(),
            ca_pem_path: None,
            mesh_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl State {
    async fn disconnect(&mut self) {
        // Stop current connection
        if let Some(c) = &self.conn {
            c.stop();
        }

        // This will start new connect cycle
        self.conn = None;
        if let Some(mut server) = self.server.clone() {
            server.conn_state = RelayState::Disconnected;
            let _ = self.event.send(Box::new(server));
        }
        self.server = None;
        telio_log_debug!("({}) Disconnected from DERP server!", Self::NAME);
    }
}

impl Config {
    pub fn reset(&mut self) {
        // Sort server list by weights
        self.servers.sort_by(|a, b| a.weight.cmp(&b.weight));

        // Reset used indicator
        for mut server in &mut self.servers {
            server.used = false;
        }
    }

    pub fn get_server(&mut self) -> Option<Server> {
        // Get first unused server address
        for mut server in &mut self.servers {
            if !server.used {
                server.used = true;
                return Some(server.clone());
            }
        }

        None
    }
}

impl Server {
    pub fn get_address(&self) -> String {
        if self.use_plain_text {
            format!("http://{}:{}", self.hostname, self.relay_port)
        } else {
            format!("https://{}:{}", self.hostname, self.relay_port)
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            region_code: "".to_string(),
            name: "".to_string(),
            hostname: "".to_string(),
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
            relay_port: 0,
            stun_port: 0,
            stun_plaintext_port: 0,
            public_key: PublicKey::default(),
            use_plain_text: false,
            weight: 0,
            used: false,
            conn_state: RelayState::Disconnected,
        }
    }
}

impl DerpRelay {
    /// Relay's constructor
    pub fn start_with(
        channel: Chan<(PublicKey, Packet)>,
        socket_pool: Arc<SocketPool>,
        config: Config,
        event: Tx<Box<Server>>,
    ) -> Self {
        let mut config = config;
        config.reset();

        // generate random number used to encrypt control messages
        let rng = StdRng::from_entropy();

        Self {
            task: Task::start(State {
                channel,
                config,
                conn: None,
                event,
                server: None,
                rng,
                socket_pool,
            }),
        }
    }

    /// Change DERP config
    pub async fn set_config(&self, config: Config) {
        let _ = task_exec!(&self.task, async move |s| {
            if s.config == config {
                // Nothing todo here
                return Ok(());
            }

            s.config = config;

            // Prepare new config
            s.config.reset();

            // Restart connection
            match s.server.as_ref() {
                Some(server) => {
                    // Current server not found in new config
                    if !s.config.servers.contains(server) {
                        s.disconnect().await;
                    }
                }
                None => {
                    // Disconnect and start from the top of the list
                    s.disconnect().await;
                }
            }

            Ok(())
        })
        .await;
    }

    pub async fn get_config(&self) -> Config {
        task_exec!(&self.task, async move |s| Ok(s.config.clone()))
            .await
            .unwrap_or_default()
    }

    /// Get current connection state (connected/diconnected)
    pub async fn get_conn_state(&self) -> bool {
        task_exec!(&self.task, async move |s| Ok(s.conn.is_some()))
            .await
            .ok()
            .unwrap_or(false)
    }

    pub async fn get_connected_server(&self) -> Option<Server> {
        task_exec!(&self.task, async move |s| Ok(s.server.clone()))
            .await
            .ok()
            .unwrap_or(None)
    }

    /// Try reconnect
    pub async fn reconnect(&self) {
        let _ = task_exec!(&self.task, async move |s| {
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

        if PacketType::from(data[0]) == PacketType::Data {
            return Ok(data.to_vec());
        }

        // new Box and convert telio-key to crypto_box format
        let secret_box = ChaChaBox::new(&public_key.into(), &secret_key.into());
        let nonce = crypto_box::generate_nonce(rng);
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
                let mut message = vec![PacketType::Encrypted as u8];
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
        match PacketType::from(data[0]) {
            PacketType::Data => {
                telio_log_trace!(
                    "Encryption not necessary : {:?} ...",
                    &data.chunks(8).next().unwrap_or_default()
                );
                Ok(data.to_vec())
            }
            PacketType::Encrypted => {
                // Extract nonce always with exactly 24 bytes from byte 1 to 24
                let nonce: Nonce<ChaChaBox> = GenericArray::clone_from_slice(
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

                let secret_box = ChaChaBox::new(&public_key.into(), &secret_key.into());

                match secret_box.decrypt(
                    &nonce,
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

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "DerpRelay";

    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
    {
        match &mut self.conn {
            Some(c) => {
                let upper_read = self.channel.rx.recv();
                let derp_read = c.comms.rx.recv();
                let conn_join = select_all([&mut c.join_sender, &mut c.join_receiver]);

                tokio::select! {
                    // Connection returned, reconnect
                    (_, _, _) = conn_join => {
                        self.disconnect().await;
                        Ok(())
                    },
                    // Received payload from upper relay, forward it to DERP stream
                    res = wait_for_tx(&c.comms.tx, upper_read) => match res {
                        Some((permit, Some((pk, msg)))) => {
                            // TODO add custom task's log format macro
                            telio_log_trace!("({}) Tx --> DERP, pubkey: {:?}, packet type: {:?}", Self::NAME, pk, msg.packet_type());
                            match msg.encode() {
                                Ok(buf) => {
                                    match DerpRelay::encrypt_if_needed(self.config.secret_key, pk, &mut self.rng, &buf) {
                                        Ok(cipher_text) => {
                                            let _ = permit.send((pk, cipher_text));
                                        },
                                        Err(error) => {
                                            telio_log_debug!("({}) Encryption failed: {}", Self::NAME, error);
                                        }
                                    }
                                }
                                Err(e) => {
                                    telio_log_debug!("({}) Failed to encode packet: {}", Self::NAME, e);
                                }
                            }
                            Ok(())
                        }
                        Some((_, None)) => {
                            telio_log_debug!("({}) Tx --> Derp closed", Self::NAME);
                            self.disconnect().await;
                            Ok(())
                        }
                        // If forwarding fails, disconnect
                        None => {
                            self.disconnect().await;
                            Ok(())
                        }
                    },
                    // Received payload from DERP stream, forward it to upper relay
                    Some((permit, Some((pk, buf)))) = wait_for_tx(&self.channel.tx, derp_read) => {
                        if self.config.allowed_pk.contains(&pk) {
                            match DerpRelay::decrypt_if_needed(self.config.secret_key,pk, &buf){
                                Ok(plain_text)=>{
                                    match Packet::decode(&plain_text) {
                                        Ok(msg) => {
                                            telio_log_trace!("({}) DERP --> Rx, pubkey: {:?}, len: {}, packet type: {:?}", Self::NAME, pk, buf.len(), msg.packet_type());
                                            permit.send((pk, msg));
                                        },
                                        Err(e) => {
                                            telio_log_debug!("({}) DERP --> Rx, failed to parse packet: ({})", Self::NAME, e);
                                        }
                                    }
                                },
                                Err(error) =>{
                                    telio_log_debug!("Decryption failed: {}", error);
                                }
                            }
                        } else {
                            telio_log_debug!("({}) DERP --> Rx, received a packet with unknown pubkey: {}", Self::NAME, pk);
                        }

                        Ok(())
                    },
                    update = update => update(self).await,

                    else => Ok(()),
                }
            }
            None => {
                let connection = async {
                    let mut sleep_time = 1f64;
                    loop {
                        let mut server = match self.config.get_server() {
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
                                self.config.reset();
                                sleep(Duration::from_secs_f64(sleep_time)).await;
                                sleep_time = (sleep_time * 2f64).min(60f64);
                                continue;
                            }
                        };

                        server.conn_state = RelayState::Connecting;
                        let _ = self.event.send(Box::new(server.clone()));

                        // Try to establish connection
                        match connect_http_and_start(
                            self.socket_pool.clone(),
                            &server.get_address(),
                            SocketAddr::new(IpAddr::V4(server.ipv4), server.relay_port),
                            self.config.clone(),
                        )
                        .await
                        {
                            Ok(conn) => {
                                telio_log_info!(
                                    "({}) Connected to {}",
                                    Self::NAME,
                                    server.get_address()
                                );
                                server.conn_state = RelayState::Connected;
                                self.server = Some(server);
                                break conn;
                            }
                            Err(err) => {
                                telio_log_warn!("({}) Failed to connect: {}", Self::NAME, err);
                                continue;
                            }
                        }
                    }
                };

                tokio::select! {
                    conn = connection => {
                        self.conn = Some(conn);
                        if let Some(server) = self.server.clone() {
                            let _ = self.event.send(Box::new(server));
                        }
                    }
                    update = update => update(self).await?,
                }
                self.config.reset();
                Ok(())
            }
        }
    }

    async fn stop(mut self) {
        // Abort the connection tasks
        self.disconnect().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use telio_crypto::PublicKey;
    use telio_proto::DataMsg;
    use telio_task::io::McChan;
    use telio_test::await_timeout;
    use tokio::time::timeout;

    struct DerpTestConfig {
        pub payload: Packet,
        pub private_key: SecretKey,
    }
    impl DerpTestConfig {
        pub fn new() -> Self {
            Self {
                payload: Packet::Data(DataMsg::new(b"seniuuukastavepinginu!")),
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
            servers: vec![third.clone(), first.clone(), second.clone()],
            ..Default::default()
        };

        config.reset();

        // Compare only wights, because of the 'weight' field
        assert_eq!(first.weight, config.get_server().unwrap().weight);
        assert_eq!(second.weight, config.get_server().unwrap().weight);
        assert_eq!(third.weight, config.get_server().unwrap().weight);
        assert_eq!(None, config.get_server());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "derp cannot connect to real host"]
    async fn test_derp_fallback() {
        let test_conf = DerpTestConfig::new();

        let mut config = Config {
            secret_key: test_conf.private_key,
            servers: vec![
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
            ],
            ..Default::default()
        };

        config.reset();

        let McChan {
            rx: mut devent_rx,
            tx: devent_tx,
        } = McChan::default();

        let (_derp_outter_ch, derp_inner_ch) = Chan::pipe();

        let test_derp = DerpRelay::start_with(
            derp_inner_ch,
            Arc::new(SocketPool::default()),
            config,
            devent_tx,
        );

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

        let mut config = Config {
            secret_key: test_conf.private_key,
            servers: vec![
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
            ],
            ..Default::default()
        };

        config.reset();

        let McChan {
            rx: mut devent_rx,
            tx: devent_tx,
        } = McChan::default();

        let (_derp_outter_ch, derp_inner_ch) = Chan::pipe();

        let test_derp = DerpRelay::start_with(
            derp_inner_ch,
            Arc::new(SocketPool::default()),
            config,
            devent_tx,
        );

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

        let mut config = Config {
            secret_key: test_conf.private_key,
            servers: vec![Server {
                hostname: "de1047.nordvpn.com".into(),
                relay_port: 8765,
                ..Default::default()
            }],
            ..Default::default()
        };

        config.reset();

        let (mut derp_outter_ch, derp_inner_ch) = Chan::pipe();

        let test_derp = DerpRelay::start_with(
            derp_inner_ch,
            Arc::new(SocketPool::default()),
            config,
            devent_tx,
        );

        let derp_event = await_timeout!(devent_rx.recv()).unwrap();
        assert_eq!(RelayState::Connected, derp_event.conn_state);

        await_timeout!(derp_outter_ch
            .tx
            .send((test_conf.private_key.public(), test_conf.payload.clone())))
        .unwrap();

        assert_eq!(
            await_timeout!(derp_outter_ch.rx.recv()).unwrap(),
            ((test_conf.private_key.public(), test_conf.payload.clone()))
        );

        await_timeout!(test_derp.stop());
    }
}
