//! Connection to Derp creation and management

use super::proto::{
    exchange_keys, read_server_info, start_read, start_write, Error, PairAddr, TCP_KEEPALIVE_COUNT,
    TCP_KEEPALIVE_IDLE, TCP_KEEPALIVE_INTERVAL, TCP_USER_TIMEOUT,
};
use httparse::Status;
use std::{
    convert::TryFrom,
    io::{Cursor, Error as IoError, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use telio_sockets::{SocketBufSizes, SocketPool, TcpParams};
use telio_task::io::Chan;
use telio_utils::interval_at;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{Config, DerpKeepaliveConfig};

use telio_crypto::{PublicKey, SecretKey};
use tokio::time::Interval;
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    rustls::{client::ServerName, ClientConfig, OwnedTrustAnchor, RootCertStore},
    TlsConnector,
};
use url::{Host, Url};

const SOCK_BUF_SZ: usize = 212992;

/// Max TCP packet size is 65535
const MAX_TCP_PACKET_SIZE: usize = u16::MAX as usize;

/// Class used to manage connection and it's receive/send threads
pub struct DerpConnection {
    /// Communication channel for Node <-> Node communication
    pub comms_relayed: Chan<(PublicKey, Vec<u8>)>,
    /// Communication channel for Node <-> Derp communication
    pub comms_direct: Chan<Vec<u8>>,
    /// Handle for managing sender thread
    pub join_sender: JoinHandle<Result<(), Error>>,
    /// Handle for managing receiver thread
    pub join_receiver: JoinHandle<Result<(), Error>>,

    /// For polling derp about remote peers states
    pub poll_timer: Interval,
}

impl DerpConnection {
    /// Function used to stop sending/receiving derp traffic
    pub fn stop(&self) {
        self.join_sender.abort();
        self.join_receiver.abort();
    }
}

/// Function determines whether to use plain TCP socket or TCP over TLS socket, initiates the connection to
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
        None => return Err(IoError::new(ErrorKind::Other, "addr host is empty").into()),
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
            let config = if derp_config.use_built_in_root_certificates {
                let trust_anchors = TLS_SERVER_ROOTS.iter().map(|trust_anchor| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        trust_anchor.subject,
                        trust_anchor.spki,
                        trust_anchor.name_constraints,
                    )
                });
                let mut root_store = RootCertStore::empty();
                root_store.add_trust_anchors(trust_anchors);

                let config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                TlsConnector::from(Arc::new(config))
            } else {
                TlsConnector::from(Arc::new(rustls_platform_verifier::tls_config()))
            };

            let server_name =
                ServerName::try_from(hostname.as_str()).map_err(|_| Error::InvalidServerName)?;

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
            start_read(reader, sender_relayed, sender_direct, addr).await
        }),
        join_receiver: tokio::spawn(async move {
            start_write(writer, receiver_relayed, receiver_direct, addr).await
        }),
        poll_timer: {
            let poll_interval = Duration::from_secs(server_keepalives.derp_keepalive as u64);
            interval_at(tokio::time::Instant::now() + poll_interval, poll_interval)
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
                Upgrade: WebSocket\r\n\
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
            return Err(IoError::new(ErrorKind::Other, "HTTP Response not full").into())
        }
        Status::Complete(len) => len,
    };
    Ok(data
        .get(res_len..data_len)
        .ok_or_else(|| IoError::new(ErrorKind::Other, "Out of bounds index for data buffer"))?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::HeaderValue;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn http_derp_connection_initiation() {
        const RESPONSE_BODY: &str = "test body";
        const HOST: &str = "hostname";

        async fn hello(request: Request<hyper::Body>) -> hyper::Result<Response<hyper::Body>> {
            assert_eq!(
                request.headers().get(hyper::header::HOST),
                Some(&HeaderValue::from_static(HOST))
            );
            assert_eq!(
                request.headers().get(hyper::header::CONNECTION),
                Some(&HeaderValue::from_static("Upgrade"))
            );
            assert_eq!(
                request.headers().get(hyper::header::UPGRADE),
                Some(&HeaderValue::from_static("WebSocket"))
            );
            assert_eq!(
                request.headers().get("keep-alive"),
                Some(&HeaderValue::from_static("tcp=1, derp=2"))
            );
            Ok(Response::builder()
                .body(hyper::Body::from(RESPONSE_BODY))
                .unwrap())
        }
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();

        let connect_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::task::spawn(async move {
                    http1::Builder::new()
                        .serve_connection(stream, service_fn(hello))
                        .await
                        .unwrap();
                });
            }
        });

        let mut stream = TcpStream::connect(connect_addr).await.unwrap();
        let (mut r, mut w) = stream.split();

        let derp_config = DerpKeepaliveConfig {
            tcp_keepalive: 1,
            derp_keepalive: 2,
        };
        assert_eq!(
            RESPONSE_BODY.as_bytes(),
            connect_http(&mut r, &mut w, &derp_config, HOST)
                .await
                .unwrap()
                .as_slice()
        );
    }
}
