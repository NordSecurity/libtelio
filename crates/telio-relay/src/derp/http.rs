use super::proto::{
    exchange_keys, read_server_info, start_read, start_write, Error, PairAddr, TCP_KEEPALIVE_COUNT,
    TCP_KEEPALIVE_IDLE, TCP_KEEPALIVE_INTERVAL, TCP_USER_TIMEOUT,
};
use httparse::Status;
use std::{
    convert::TryFrom,
    fs::File,
    io::{BufReader, Cursor, Error as IoError, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use telio_sockets::{SocketBufSizes, SocketPool, TcpParams};
use telio_task::io::Chan;

use crate::{Config, DerpKeepaliveConfig};

use telio_crypto::{PublicKey, SecretKey};
use tokio::time::{interval_at, Interval, MissedTickBehavior};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    task::JoinHandle,
    time,
    time::timeout,
};
use tokio_rustls::{
    rustls::{
        client::{ServerCertVerified, ServerCertVerifier, ServerName},
        Certificate, ClientConfig, Error as TLSError, OwnedTrustAnchor, RootCertStore,
        ALL_CIPHER_SUITES,
    },
    TlsConnector,
};
use url::{Host, Url};
use webpki_roots::TLS_SERVER_ROOTS;

pub(crate) struct NoVerifier;

const SOCK_BUF_SZ: usize = 212992;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub type Protect = Arc<dyn Fn(i32) + Send + Sync + 'static>;

/// Max TCP packet size is 65535
const MAX_TCP_PACKET_SIZE: usize = u16::MAX as usize;

pub struct DerpConnection {
    pub comms_relayed: Chan<(PublicKey, Vec<u8>)>,
    pub comms_direct: Chan<Vec<u8>>,
    pub join_sender: JoinHandle<Result<(), IoError>>,
    pub join_receiver: JoinHandle<Result<(), IoError>>,

    /// For polling derp about remote peers states
    pub poll_timer: Interval,
}

impl DerpConnection {
    pub fn stop(&self) {
        self.join_sender.abort();
        self.join_receiver.abort();
    }
}

/// Function determines wether to use plain TCP socket or TCP over TLS socket, initiates the connection to
/// the server. TLS connection is default. In order to ignore tls, set url scheme to `http://`.
/// The function returns sender and receiver for communicating with other DERP peers and thread handles
/// Note that this function spawns 2 tasks
pub async fn connect_http_and_start(
    socket_pool: Arc<SocketPool>,
    addr: &str,
    ip: SocketAddr,
    derp_config: Config,
) -> Result<DerpConnection, Error> {
    let u = Url::parse(addr)?;
    let hostname = match u.host() {
        None => {
            return Err(Box::new(IoError::new(
                ErrorKind::Other,
                "addr host is empty",
            )))
        }
        Some(hostname) => match hostname {
            Host::Domain(hostname) => String::from(hostname),
            Host::Ipv4(hostname) => hostname.to_string(),
            Host::Ipv6(hostname) => hostname.to_string(),
        },
    };

    let port = match u.port() {
        None => match u.scheme() {
            "http" => 80,
            _ => 443,
        },
        Some(port) => port,
    };
    let hostport = format!("{}:{}", hostname, port);

    let socket = socket_pool.new_external_tcp_v4(Some(TcpParams {
        keepalive_enable: Some(true),
        keepalive_cnt: Some(TCP_KEEPALIVE_COUNT),
        keepalive_idle: Some(TCP_KEEPALIVE_IDLE),
        keepalive_intvl: Some(TCP_KEEPALIVE_INTERVAL),
        nodelay_enable: Some(true),
        user_timeout: Some(TCP_USER_TIMEOUT),
        buf_size: SocketBufSizes {
            tx_buf_size: Some(SOCK_BUF_SZ),
            rx_buf_size: Some(SOCK_BUF_SZ),
        },
    }))?;

    let stream = timeout(derp_config.timeout, socket.connect(ip)).await??;

    let addr = PairAddr {
        local: stream.local_addr()?,
        remote: stream.peer_addr()?,
    };

    match u.scheme() {
        "http" => {
            Box::pin(connect_and_start(
                stream,
                addr,
                derp_config.secret_key,
                derp_config.server_keepalives,
                &hostport,
            ))
            .await
        }
        _ => {
            let trust_anchors = TLS_SERVER_ROOTS.iter().map(|trust_anchor| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    trust_anchor.subject,
                    trust_anchor.spki,
                    trust_anchor.name_constraints,
                )
            });

            let mut root_store = RootCertStore::empty();
            root_store.add_trust_anchors(trust_anchors);

            if let Some(path) = &derp_config.ca_pem_path {
                let root_cert_file = File::open(path)?;
                let mut root_cert_file = BufReader::new(root_cert_file);
                let der_certs = rustls_pemfile::certs(&mut root_cert_file).unwrap_or_default();
                root_store.add_parsable_certificates(&der_certs);
            }

            let mut config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            if derp_config.ca_pem_path.is_some() {
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoVerifier));
            }

            let server_name =
                ServerName::try_from(hostname.as_str()).map_err(|_| "Invalid Server Name")?;
            let config = TlsConnector::from(Arc::new(config));

            connect_and_start(
                config.connect(server_name, stream).await?,
                addr,
                derp_config.secret_key,
                derp_config.server_keepalives,
                &hostport,
            )
            .await
        }
    }
}

async fn connect_and_start<RW: AsyncRead + AsyncWrite + Send + 'static>(
    stream: RW,
    addr: PairAddr,
    secret_key: SecretKey,
    server_keepalives: DerpKeepaliveConfig,
    host: &str,
) -> Result<DerpConnection, Error> {
    let (mut reader, mut writer) = split(stream);

    let leftovers = Box::pin(connect_http(
        &mut reader,
        &mut writer,
        &server_keepalives,
        host,
    ))
    .await?;

    let mut reader = Cursor::new(leftovers).chain(reader);

    exchange_keys(&mut reader, &mut writer, secret_key).await?;

    read_server_info(&mut reader).await?;

    // Split channels for communication side and for connection side. One channel for
    // connections relayed through derp and another for communication with derp directly
    let (comm_side_relayed, conn_side_relayed) = Chan::pipe();
    let (comm_side_direct, conn_side_direct) = Chan::pipe();

    let sender_relayed = conn_side_relayed.tx;
    let receiver_relayed = conn_side_relayed.rx;
    let sender_direct = conn_side_direct.tx;
    let receiver_direct = conn_side_direct.rx;

    Ok(DerpConnection {
        comms_relayed: comm_side_relayed,
        comms_direct: comm_side_direct,
        join_sender: tokio::spawn(async move {
            start_read(reader, sender_relayed, sender_direct, addr)
                .await
                .map_err(|err| IoError::new(ErrorKind::Other, err.to_string()))
        }),
        join_receiver: tokio::spawn(async move {
            start_write(writer, receiver_relayed, receiver_direct, addr)
                .await
                .map_err(|err| IoError::new(ErrorKind::Other, err.to_string()))
        }),
        poll_timer: {
            let poll_interval = Duration::from_secs(server_keepalives.derp_keepalive as u64);
            let mut timer = interval_at(tokio::time::Instant::now() + poll_interval, poll_interval);
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            timer
        },
    })
}

/// Sends the initial HTTP packet and parses the response in order to initiate the
/// connection
async fn connect_http<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    server_keepalives: &DerpKeepaliveConfig,
    host: &str,
) -> Result<Vec<u8>, Error> {
    writer
        .write_all(
            format!(
                "GET /derp HTTP/1.1\r\n\
                Host: {host}\r\n\
                Connection: Upgrade\r\n\
                Upgrade: DERP\r\n\
                User-Agent: telio/{} {}\r\n\
                Keep-Alive: tcp={}, derp={}\r\n\r\n",
                telio_utils::version_tag(),
                std::env::consts::OS,
                server_keepalives.tcp_keepalive,
                server_keepalives.derp_keepalive,
            )
            .as_bytes(),
        )
        .await?;

    let mut data = [0_u8; MAX_TCP_PACKET_SIZE];
    let data_len = reader.read(&mut data).await?;

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut res = httparse::Response::new(&mut headers);
    let res_len = match res.parse(&data)? {
        Status::Partial => {
            return Err(Box::new(IoError::new(
                ErrorKind::Other,
                "HTTP Response not full",
            )))
        }
        Status::Complete(len) => len,
    };
    Ok(data
        .get(res_len..data_len)
        .ok_or_else(|| {
            Box::new(IoError::new(
                ErrorKind::Other,
                "Out of bounds index for data buffer",
            ))
        })?
        .to_vec())
}
