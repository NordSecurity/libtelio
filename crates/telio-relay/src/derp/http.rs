use super::proto::{
    exchange_keys, read_server_info, start_read, start_write, Error, PairAddr, TCP_KEEPALIVE_COUNT,
    TCP_KEEPALIVE_IDLE, TCP_KEEPALIVE_INTERVAL, TCP_USER_TIMEOUT,
};
use httparse::Status;
use std::{
    fs::File,
    io::{BufReader, Cursor, Error as IoError, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use telio_sockets::{SocketBufSizes, SocketPool, TcpParams};
use telio_task::io::Chan;

use crate::Config;

use telio_crypto::{PublicKey, SecretKey};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    task::JoinHandle,
    time,
    time::timeout,
};
use tokio_rustls::{
    rustls::{
        Certificate, ClientConfig, RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError,
    },
    TlsConnector,
};
use url::{Host, Url};
use webpki::DNSNameRef;
use webpki_roots::TLS_SERVER_ROOTS;

pub(crate) struct NoVerifier;

const SOCK_BUF_SZ: usize = 212992;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        _presented_certs: &[Certificate],
        _dns_name: DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub type Protect = Arc<dyn Fn(i32) + Send + Sync + 'static>;

/// Max TCP packet size is 65535
const MAX_TCP_PACKET_SIZE: usize = u16::MAX as usize;

pub struct DerpConnection {
    pub comms: Chan<(PublicKey, Vec<u8>)>,
    pub join_sender: JoinHandle<Result<(), IoError>>,
    pub join_receiver: JoinHandle<Result<(), IoError>>,
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

    let socket = socket_pool.new_external_tcp_v4(
        Some(TcpParams {
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
        }),
        #[cfg(target_os = "macos")]
        false,
    )?;

    let stream = timeout(derp_config.timeout, socket.connect(ip)).await??;

    let addr = PairAddr {
        local: stream.local_addr()?,
        remote: stream.peer_addr()?,
    };

    match u.scheme() {
        "http" => connect_and_start(stream, addr, derp_config.secret_key, &hostport).await,
        _ => {
            let mut config = ClientConfig::new();
            config
                .root_store
                .add_server_trust_anchors(&TLS_SERVER_ROOTS);

            if let Some(path) = derp_config.ca_pem_path {
                let root_cert_file = File::open(path)?;
                let mut root_cert_file = BufReader::new(root_cert_file);
                config.root_store.add_pem_file(&mut root_cert_file);
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoVerifier));
            }

            let dnsname = DNSNameRef::try_from_ascii_str(&hostname)?;
            let config = TlsConnector::from(Arc::new(config));

            connect_and_start(
                config.connect(dnsname, stream).await?,
                addr,
                derp_config.secret_key,
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
    host: &str,
) -> Result<DerpConnection, Error> {
    let (mut reader, mut writer) = split(stream);

    let leftovers = connect_http(&mut reader, &mut writer, host).await?;

    let mut reader = Cursor::new(leftovers).chain(reader);

    exchange_keys(&mut reader, &mut writer, secret_key).await?;

    read_server_info(&mut reader).await?;

    // Splitted channel for communication side and for connection side
    let (comm_side, conn_side) = Chan::pipe();

    let tx = conn_side.tx;
    let rx = conn_side.rx;

    Ok(DerpConnection {
        comms: comm_side,
        join_sender: tokio::spawn(async move {
            start_read(reader, tx, addr)
                .await
                .map_err(|err| IoError::new(ErrorKind::Other, err.to_string()))
        }),
        join_receiver: tokio::spawn(async move {
            start_write(writer, rx, addr)
                .await
                .map_err(|err| IoError::new(ErrorKind::Other, err.to_string()))
        }),
    })
}

/// Sends the initial HTTP packet and parses the response in order to initiate the
/// connection
async fn connect_http<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    host: &str,
) -> Result<Vec<u8>, Error> {
    writer
        .write_all(
            format!(
                "GET /derp HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n",
                host
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
    Ok(data[res_len..data_len].to_vec())
}
