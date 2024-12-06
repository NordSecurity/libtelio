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
use telio_utils::{interval_at, telio_log_debug};
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
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
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

    // First try to use derp v2, with poll keepalives it the feature is enabled
    if derp_config.server_keepalives.poll_keepalive.is_some() {
        telio_log_debug!("Trying to connect to derp V2");
        let socket = socket_pool.new_external_tcp_v4(Some(build_tcp_parameters(false)))?;
        let stream = timeout(derp_config.timeout, socket.connect(ip)).await??;
        let addr = PairAddr {
            local: stream.local_addr()?,
            remote: stream.peer_addr()?,
        };

        let connection = match u.scheme() {
            "http" => {
                Box::pin(connect_and_start(
                    stream,
                    addr,
                    derp_config.secret_key,
                    derp_config.server_keepalives.clone(),
                    &hostport,
                    true,
                ))
                .await
            }
            _ => {
                let config = if derp_config.use_built_in_root_certificates {
                    let root_store: RootCertStore = TLS_SERVER_ROOTS.iter().cloned().collect();

                    let config = ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    TlsConnector::from(Arc::new(config))
                } else {
                    TlsConnector::from(Arc::new(rustls_platform_verifier::tls_config()))
                };

                let server_name =
                    ServerName::try_from(hostname.clone()).map_err(|_| Error::InvalidServerName)?;

                connect_and_start(
                    config.connect(server_name, stream).await?,
                    addr,
                    derp_config.secret_key,
                    derp_config.server_keepalives.clone(),
                    &hostport,
                    true,
                )
                .await
            }
        };

        if connection.is_ok() {
            // We managed to successfully connect to derp v2
            telio_log_debug!("Successfully connected to derp v2");
            return connection;
        }
    }

    // If we didn't want or didn't manage to connect to depr v2, we will try derp v1
    telio_log_debug!("Trying to connect to derp v1");
    let socket = socket_pool.new_external_tcp_v4(Some(build_tcp_parameters(true)))?;
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
                false,
            ))
            .await
        }
        _ => {
            let config = if derp_config.use_built_in_root_certificates {
                let root_store: RootCertStore = TLS_SERVER_ROOTS.iter().cloned().collect();

                let config = ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                TlsConnector::from(Arc::new(config))
            } else {
                TlsConnector::from(Arc::new(rustls_platform_verifier::tls_config()))
            };

            let server_name =
                ServerName::try_from(hostname).map_err(|_| Error::InvalidServerName)?;

            connect_and_start(
                config.connect(server_name, stream).await?,
                addr,
                derp_config.secret_key,
                derp_config.server_keepalives,
                &hostport,
                false,
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
    derp_v2: bool,
) -> Result<DerpConnection, Error> {
    let (mut reader, mut writer) = split(stream);

    let leftovers = Box::pin(connect_http(
        &mut reader,
        &mut writer,
        &server_keepalives,
        host,
        derp_v2,
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

    // TODO: When we switch to batched Poll Keepalives, we have to move this into the session keeper
    // The logic is here for now for testing purposes
    let poll_interval = match (derp_v2, server_keepalives.poll_keepalive) {
        // We connected to derp V2, so we will use poll keepalives
        (true, Some(poll_keepalive)) => Duration::from_secs(poll_keepalive as u64),
        // We connected to derp V1, so we will use the old derp_keepalive config
        (false, _) => Duration::from_secs(server_keepalives.derp_keepalive as u64),
        // Any other situation is an error
        _ => return Err(Error::InternalError),
    };
    telio_log_debug!("Derp poll interval {:?}", poll_interval);

    Ok(DerpConnection {
        comms_relayed: comm_side_relayed,
        comms_direct: comm_side_direct,
        join_sender: tokio::spawn(async move {
            start_read(reader, sender_relayed, sender_direct, addr).await
        }),
        join_receiver: tokio::spawn(async move {
            start_write(writer, receiver_relayed, receiver_direct, addr).await
        }),
        poll_timer: { interval_at(tokio::time::Instant::now() + poll_interval, poll_interval) },
    })
}

/// Sends the initial HTTP packet and parses the response in order to initiate the
/// connection
async fn connect_http<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    server_keepalives: &DerpKeepaliveConfig,
    host: &str,
    derp_v2: bool,
) -> Result<Vec<u8>, Error> {
    let request = match (derp_v2, server_keepalives.poll_keepalive) {
        // We try to connect to derp V2
        (true, Some(poll_keepalive)) => format!(
            "GET /derpv2 HTTP/1.1\r\n\
                Host: {host}\r\n\
                Connection: Upgrade\r\n\
                Upgrade: WebSocket\r\n\
                User-Agent: telio/{} {}\r\n\
                Poll-Keepalive: {}\r\n\r\n",
            telio_utils::version_tag(),
            std::env::consts::OS,
            poll_keepalive,
        ),
        // We try to connect to derp V1
        (false, _) => format!(
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
        ),
        _ => return Err(Error::InternalError),
    };
    telio_log_debug!("DERP connect request: {}", &request);

    writer.write_all(request.as_bytes()).await?;

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

fn build_tcp_parameters(use_tcp_keepalives: bool) -> TcpParams {
    if use_tcp_keepalives {
        TcpParams {
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
        }
    } else {
        TcpParams {
            nodelay_enable: Some(true),
            user_timeout: Some(TCP_USER_TIMEOUT),
            buf_size: SocketBufSizes {
                tx_buf_size: Some(SOCK_BUF_SZ),
                rx_buf_size: Some(SOCK_BUF_SZ),
            },
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::HeaderValue;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Body, Request, Response};
    use tokio::net::{TcpListener, TcpStream};

    const RESPONSE_BODY: &str = "test body";
    const HOST: &str = "hostname";

    fn default_asserts(request: &Request<Body>) -> () {
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
    }

    async fn derpv1_handler(request: Request<Body>) -> hyper::Result<Response<Body>> {
        default_asserts(&request);
        match request.uri().path() {
            "/derp" => {
                assert_eq!(
                    request.headers().get("Keep-alive"),
                    Some(&HeaderValue::from_static("tcp=1, derp=2"))
                );
                assert_eq!(request.headers().get("Poll-keepalive"), None);
                Ok(Response::builder().body(Body::from(RESPONSE_BODY)).unwrap())
            }
            _ => Ok(Response::builder()
                .status(404)
                .body(Body::from("Not found"))
                .unwrap()),
        }
    }

    async fn derpv2_handler(request: Request<Body>) -> hyper::Result<Response<Body>> {
        default_asserts(&request);
        match request.uri().path() {
            "/derp" => {
                assert_eq!(
                    request.headers().get("Keep-alive"),
                    Some(&HeaderValue::from_static("tcp=1, derp=2"))
                );
                assert_eq!(request.headers().get("Poll-keepalive"), None);
                Ok(Response::builder().body(Body::from(RESPONSE_BODY)).unwrap())
            }
            "/derpv2" => {
                assert_eq!(request.headers().get("Keep-alive"), None);
                assert_eq!(
                    request.headers().get("Poll-keepalive"),
                    Some(&HeaderValue::from_static("3"))
                );
                Ok(Response::builder().body(Body::from(RESPONSE_BODY)).unwrap())
            }
            _ => Ok(Response::builder()
                .status(404)
                .body(Body::from("Not found"))
                .unwrap()),
        }
    }

    #[tokio::test]
    async fn test_v1_derp_connection() {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();
        let connect_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::task::spawn(async move {
                    http1::Builder::new()
                        .serve_connection(stream, service_fn(derpv1_handler))
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
            poll_keepalive: Some(3),
        };
        assert_eq!(
            "Not found".as_bytes(),
            connect_http(&mut r, &mut w, &derp_config, HOST, true)
                .await
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            RESPONSE_BODY.as_bytes(),
            connect_http(&mut r, &mut w, &derp_config, HOST, false)
                .await
                .unwrap()
                .as_slice()
        );
    }

    #[tokio::test]
    async fn test_v2_derp_connection() {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();
        let connect_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::task::spawn(async move {
                    http1::Builder::new()
                        .serve_connection(stream, service_fn(derpv2_handler))
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
            poll_keepalive: Some(3),
        };
        assert_eq!(
            RESPONSE_BODY.as_bytes(),
            connect_http(&mut r, &mut w, &derp_config, HOST, true)
                .await
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            RESPONSE_BODY.as_bytes(),
            connect_http(&mut r, &mut w, &derp_config, HOST, false)
                .await
                .unwrap()
                .as_slice()
        );
    }
}
