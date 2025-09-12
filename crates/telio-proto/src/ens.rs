use std::{
    net::{IpAddr, ToSocketAddrs},
    str::FromStr,
    sync::Arc,
};

use base64::prelude::{Engine, BASE64_STANDARD};
use blake3::{derive_key, keyed_hash};
use grpc::ConnectionError;
use http::Uri;
use hyper_util::rt::TokioIo;
#[cfg(feature = "enable_ens")]
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use telio_crypto::{SecretKey, SharedSecret};
use telio_model::PublicKey;
use telio_sockets::SocketPool;
use telio_task::io::{
    chan::{Rx, Tx},
    Chan,
};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_info, telio_log_warn};
use tokio::{select, sync::watch, task::JoinHandle};
use tokio_rustls::TlsConnector;
use tonic::{
    metadata::AsciiMetadataValue,
    transport::{Channel, Endpoint},
    Request, Status,
};
use tower::service_fn;
use uuid::Uuid;

use crate::ens::grpc::{ChallengeRequest, ConnectionErrorRequest};

#[allow(missing_docs)]
pub(crate) mod grpc {
    use telio_model::mesh::VpnConnectionError;
    tonic::include_proto!("ens");

    impl From<ConnectionError> for VpnConnectionError {
        fn from(connection_error: ConnectionError) -> Self {
            match connection_error.code {
                code if code == Error::ConnectionLimitReached as i32 => {
                    Self::ConnectionLimitReached
                }
                code if code == Error::ServerMaintenance as i32 => Self::ServerMaintenance,
                code if code == Error::Unauthenticated as i32 => Self::Unauthenticated,
                code if code == Error::Superseded as i32 => Self::Superseded,
                _code => Self::Unknown,
            }
        }
    }
}

const CONTEXT: &str = "ens-auth";
const ENS_PORT: u16 = 993;
const AUTHENTICATION_KEY: &str = "authentication";

/// ENS errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed VPN uri
    #[error("Failed to parse the vpn server uri: {0}")]
    MalformedVpnUri(#[from] http::Error),
    /// Inner grpc/tonic error
    #[error("ENS transport error: {0}")]
    TransportError(#[from] tonic::transport::Error),
    /// GRPC status error
    #[error("GRPC status error: {0}")]
    StatusError(#[from] tonic::Status),
}

/// ErrorNotificationService manages tasks started and stopped to consume the ENS grpc error streams
pub struct ErrorNotificationService {
    quit: Option<(watch::Sender<bool>, JoinHandle<()>)>,
    tx: Tx<(ConnectionError, PublicKey)>,
    socket_pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
}

impl Drop for ErrorNotificationService {
    fn drop(&mut self) {
        let _ = self.stop_old_monitor(); // Can't wait on the handle in the Drop
    }
}

impl ErrorNotificationService {
    /// Create new instance with buffer_size used for the error notifications channel
    pub fn new(
        buffer_size: usize,
        socket_pool: Arc<SocketPool>,
        allow_only_mlkem: bool,
    ) -> (Self, Rx<(ConnectionError, PublicKey)>) {
        let Chan { rx, tx }: Chan<(ConnectionError, PublicKey)> = Chan::new(buffer_size);
        (
            Self {
                quit: None,
                tx,
                socket_pool,
                allow_only_mlkem,
            },
            rx,
        )
    }

    /// Start new task that will monitor ENS instance running on the `vpn_ip`:993
    pub async fn start_monitor(
        &mut self,
        vpn_ip: IpAddr,
        vpn_public_key: PublicKey,
        local_private_key: SecretKey,
    ) -> Result<(), Error> {
        self.start_monitor_on_port(vpn_ip, ENS_PORT, vpn_public_key, local_private_key)
            .await
    }

    async fn start_monitor_on_port(
        &mut self,
        vpn_ip: IpAddr,
        ens_port: u16,
        vpn_public_key: PublicKey,
        local_private_key: SecretKey,
    ) -> Result<(), Error> {
        telio_log_info!("Will start ENS monitoring on {vpn_ip}:{ens_port} ({vpn_public_key:?})");
        self.stop().await;

        let (quit_tx, quit_rx): (watch::Sender<bool>, watch::Receiver<bool>) =
            watch::channel(false);

        // Needs to be http and not https, otherwise grpc will add another layer of https
        // on top of our own custom one
        let vpn_uri = format!("http://{vpn_ip}:{ens_port}");

        let pool = self.socket_pool.clone();
        let tx = self.tx.clone();
        let allow_only_mlkem = self.allow_only_mlkem;

        let join_handle = tokio::spawn(async move {
            // This future is too big for keeping it on the stack
            if let Err(e) = Box::pin(task(
                vpn_uri.clone(),
                vpn_public_key,
                local_private_key,
                pool.clone(),
                tx,
                quit_rx,
                allow_only_mlkem,
            ))
            .await
            {
                telio_log_warn!("ENS task for {vpn_uri} ({vpn_public_key:?}) failed: {e}");
            }
        });

        self.quit = Some((quit_tx, join_handle));
        Ok(())
    }

    /// Stop ENS
    pub async fn stop(&mut self) {
        if let Some(join_handle) = self.stop_old_monitor() {
            telio_log_debug!("Will wait for the old ENS task to end");
            join_handle.abort(); // Since the task might be in the grpc connection establishment, it might not be able
                                 // to receive and react to te quit signal. Which is why we need to cancel it here, so
                                 // that we are not stuck for a long time in the await.
            if let Err(e) = join_handle.await {
                if !e.is_cancelled() {
                    telio_log_warn!("Previous ENS task failed to stop: {e}");
                }
            }
        }
    }

    fn stop_old_monitor(&mut self) -> Option<JoinHandle<()>> {
        if let Some((quit_channel, join_handle)) = self.quit.take() {
            telio_log_debug!("Previous ENS task will be stopped");
            if let Err(e) = quit_channel.send(true) {
                telio_log_warn!("Failed to send stop request to previous ENS monitor: {e}");
            } else {
                return Some(join_handle);
            }
        }
        None
    }
}

async fn task(
    vpn_uri: String,
    vpn_public_key: PublicKey,
    local_private_key: SecretKey,
    pool: Arc<SocketPool>,
    tx: Tx<(ConnectionError, PublicKey)>,
    mut quit_rx: watch::Receiver<bool>,
    allow_only_mlkem: bool,
) -> anyhow::Result<()> {
    'outer: loop {
        let pool = pool.clone();
        let external_channel =
            Box::pin(create_external_channel(&vpn_uri, pool, allow_only_mlkem)).await?;

        let authenticated_challenge = get_login_challenge(
            external_channel.clone(),
            vpn_public_key,
            local_private_key.clone(),
        )
        .await?;

        let mut client = grpc::ens_client::EnsClient::with_interceptor(
            external_channel,
            authentication_interceptor(authenticated_challenge),
        );

        let connection = client
            .connection_errors(ConnectionErrorRequest::default())
            .await?;
        let mut stream = connection.into_inner();
        loop {
            select! {
                _ = quit_rx.wait_for(|b| *b) => {
                    telio_log_info!("ENS monitor for '{vpn_uri}' ends");
                    break 'outer;
                }
                error_notification = stream.message() => {
                    telio_log_warn!("Received error notification for '{vpn_uri}': {error_notification:?}");
                    match error_notification {
                        Ok(Some(error_notification)) => {
                            if let Err(e) = tx.try_send((error_notification, vpn_public_key)) {
                                telio_log_warn!("Failed to publish newly received error notification: {e}");
                            }
                        }
                        Ok(None) => {
                            telio_log_debug!("'{vpn_uri}' closed the grpc stream");
                            break 'outer;
                        }
                        Err(e) => {
                            telio_log_error!("GRPC error: {e}");
                            // TODO(LLT-6489): we shouldn't reconnect immediately, instead we should have a backoff strategy
                            break;
                        }
                    }
                }
            };
        }
    }
    telio_log_debug!("ENS monitor for '{vpn_uri}' terminates");
    Ok(())
}

async fn get_login_challenge(
    external_channel: Channel,
    vpn_public_key: PublicKey,
    local_private_key: SecretKey,
) -> anyhow::Result<AsciiMetadataValue> {
    let mut login_client = grpc::login_client::LoginClient::new(external_channel);

    let challenge_response = login_client
        .get_challenge(ChallengeRequest::default())
        .await?;
    let challenge = &challenge_response.get_ref().challenge;
    let challenge = Uuid::from_str(challenge)?;
    let shared_secret = local_private_key.ecdh(&vpn_public_key);

    let mut authentication = vec![];
    authentication.extend_from_slice(&local_private_key.public());
    authentication.extend_from_slice(&challenge.into_bytes());
    let authentication_tag = authentication_tag(shared_secret, &authentication);
    authentication.extend_from_slice(&authentication_tag);
    let authentication = BASE64_STANDARD.encode(&authentication);

    Ok(AsciiMetadataValue::try_from(authentication)?)
}

fn authentication_interceptor(
    authentication_value: AsciiMetadataValue,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> {
    move |mut req: Request<()>| {
        req.metadata_mut()
            .insert(AUTHENTICATION_KEY, authentication_value.clone());
        Ok(req)
    }
}

async fn create_external_channel(
    vpn_uri: &str,
    pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
) -> anyhow::Result<Channel> {
    let socket_factory = move |uri: Uri| {
        let pool = pool.clone();
        async move {
            let host = match uri.host() {
                Some(host) => host,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "missing host in vpn uri",
                    ))
                }
            };
            let port = match uri.port_u16() {
                Some(port) => port,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "missing port in vpn uri",
                    ))
                }
            };

            let socket = pool.new_external_tcp_v4(None)?;
            let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            if let Some(resolved) = ((host, port).to_socket_addrs()?).next() {
                let tcp_stream = socket.connect(resolved).await?;
                let tls_connector = make_tls_connector(allow_only_mlkem)?;
                let tls_stream = tls_connector.connect(domain, tcp_stream).await?;
                return Ok::<_, std::io::Error>(TokioIo::new(tls_stream));
            }

            Err(std::io::Error::other(format!(
                "None of the IPs resolved from {host} accepted ENS over TLS"
            )))
        }
    };

    Ok(Endpoint::try_from(vpn_uri.to_owned())?
        .connect_with_connector(service_fn(socket_factory))
        .await?)
}

#[cfg(not(feature = "enable_ens"))]
fn make_tls_connector(_allow_only_mlkem: bool) -> std::io::Result<TlsConnector> {
    telio_log_warn!("An attempt was made to enable ENS when it is disabled at compile time");
    Err(std::io::Error::other("ENS is disabled"))
}

#[cfg(feature = "enable_ens")]
fn make_tls_connector(allow_only_mlkem: bool) -> std::io::Result<TlsConnector> {
    #[derive(Debug)]
    struct AcceptAnyCertVerifier;

    impl ServerCertVerifier for AcceptAnyCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
                SignatureScheme::ML_DSA_44,
                SignatureScheme::ML_DSA_65,
                SignatureScheme::ML_DSA_87,
            ]
        }
    }

    let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();

    if allow_only_mlkem {
        provider.kx_groups =
            vec![tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    }

    let mut tls_config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::other(format!("{e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(TlsConnector::from(Arc::new(tls_config)))
}

fn authentication_tag(secret: SharedSecret, message: &[u8]) -> [u8; 32] {
    let key = derive_key(CONTEXT, &secret);
    *keyed_hash(&key, message).as_bytes()
}

#[cfg(test)]
mod tests {

    use std::{
        collections::HashSet,
        net::Ipv4Addr,
        sync::{atomic::AtomicUsize, LazyLock, Mutex},
        time::Duration,
    };

    use grpc::{
        ens_server::{self, EnsServer},
        login_server::{self, LoginServer},
        Challenge, ConnectionError,
    };
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use telio_crypto::SecretKey;
    use telio_sockets::NativeProtector;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::{service::Interceptor, transport::Server};

    use super::*;

    const SUBJECT_ALT_NAMES: LazyLock<Vec<String>> =
        LazyLock::new(|| vec!["localhost".to_string(), "127.0.0.1".to_string()]);

    struct GrpcStub {
        errors: Vec<ConnectionError>,
        challenges: Mutex<HashSet<Uuid>>,
        vpn_server_private_key: SecretKey,
    }

    impl GrpcStub {
        fn new(errors: &[ConnectionError], vpn_server_private_key: SecretKey) -> Self {
            Self {
                errors: errors.to_vec(),
                challenges: Mutex::new(HashSet::default()),
                vpn_server_private_key,
            }
        }
    }

    #[tonic::async_trait]
    impl ens_server::Ens for Arc<GrpcStub> {
        type ConnectionErrorsStream = ReceiverStream<Result<ConnectionError, tonic::Status>>;
        async fn connection_errors(
            &self,
            _request: tonic::Request<ConnectionErrorRequest>,
        ) -> std::result::Result<tonic::Response<Self::ConnectionErrorsStream>, tonic::Status>
        {
            let (tx, rx) = mpsc::channel(1);
            let errors = self.errors.clone();
            tokio::spawn(async move {
                for error in errors {
                    tx.send(Ok(error)).await.unwrap();
                }
            });

            Ok(tonic::Response::new(ReceiverStream::new(rx)))
        }
    }

    #[tonic::async_trait]
    impl login_server::Login for Arc<GrpcStub> {
        async fn get_challenge(
            &self,
            _request: tonic::Request<ChallengeRequest>,
        ) -> std::result::Result<tonic::Response<Challenge>, tonic::Status> {
            let challenge = Uuid::new_v4();
            self.challenges.lock().unwrap().insert(challenge);
            Ok(tonic::Response::new(Challenge {
                challenge: challenge.to_string(),
            }))
        }
    }

    #[derive(Clone)]
    struct CheckAuthenticationInterceptor(Arc<GrpcStub>);

    impl Interceptor for CheckAuthenticationInterceptor {
        fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
            match req.metadata().get(AUTHENTICATION_KEY) {
                Some(t) => {
                    let decoded = BASE64_STANDARD.decode(&t).unwrap();
                    let (client_public_key, challenge_uuid, received_authentication_code) = (
                        PublicKey::new(decoded[..32].try_into().unwrap()),
                        Uuid::from_slice(&decoded[32..48]).unwrap(),
                        &decoded[48..],
                    );

                    if let Some(_) = self.0.challenges.lock().unwrap().take(&challenge_uuid) {
                        let secret = self.0.vpn_server_private_key.ecdh(&client_public_key);
                        if received_authentication_code
                            == authentication_tag(secret, &decoded[..48])
                        {
                            Ok(req)
                        } else {
                            Err(Status::unauthenticated("Challenge not authenticated"))
                        }
                    } else {
                        Err(Status::unauthenticated("Unknown auth token"))
                    }
                }
                _ => Err(Status::unauthenticated("No valid auth token")),
            }
        }
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_ens() {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();

        let server_private_key = SecretKey::gen();
        let server_public_key = server_private_key.public();
        let client_private_key = SecretKey::gen();

        let errors_to_emit = vec![
            (
                ConnectionError {
                    code: grpc::Error::Unknown as i32,
                    additional_info: None,
                },
                server_public_key,
            ),
            (
                ConnectionError {
                    code: grpc::Error::ConnectionLimitReached as i32,
                    additional_info: Some("additional info".to_owned()),
                },
                server_public_key,
            ),
        ];
        let grpc_stub = Arc::new(GrpcStub::new(
            &errors_to_emit
                .iter()
                .map(|(c, _)| c.clone())
                .collect::<Vec<_>>(),
            server_private_key,
        ));
        let ens_srv = EnsServer::with_interceptor(
            grpc_stub.clone(),
            CheckAuthenticationInterceptor(grpc_stub.clone()),
        );
        let login_srv = LoginServer::new(grpc_stub.clone());

        let (port_tx, port_rx) = oneshot::channel();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let actual_addr = listener.local_addr().unwrap();
            port_tx.send(actual_addr.port()).unwrap();

            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(SUBJECT_ALT_NAMES.clone()).unwrap();

            let cert_pem = cert.pem();
            let key_pem = signing_key.serialize_pem();

            use tonic::transport::ServerTlsConfig;

            let tonic_tls_config = ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(cert_pem, key_pem));

            Server::builder()
                .tls_config(tonic_tls_config)
                .unwrap()
                .add_service(ens_srv)
                .add_service(login_srv)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let socket_pool = make_socket_pool();
        let allow_only_mlkem = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(10, socket_pool, allow_only_mlkem);

        let port = port_rx.await.unwrap();
        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            server_public_key,
            client_private_key.clone(),
        )
        .await
        .unwrap();
        let _collected_errors = collect_errors(2, &mut rx).await;
        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            server_public_key,
            client_private_key,
        )
        .await
        .unwrap();

        let collected_errors = collect_errors(2, &mut rx).await;

        assert_eq!(errors_to_emit, collected_errors);

        ens.stop().await;
    }

    async fn collect_errors(
        n: usize,
        rx: &mut Rx<(ConnectionError, PublicKey)>,
    ) -> Vec<(ConnectionError, PublicKey)> {
        let mut ret = vec![];
        for _ in 0..n {
            ret.push(rx.recv().await.unwrap());
        }
        ret
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_ens_fails_without_x25519mlkem768_support() {
        let server_private_key = SecretKey::gen();
        let server_public_key = server_private_key.public();
        let client_private_key = SecretKey::gen();

        let (port_tx, port_rx) = oneshot::channel();
        let expected_errors = Arc::new(AtomicUsize::new(0));

        let expected_errors_clone = expected_errors.clone();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let actual_addr = listener.local_addr().unwrap();
            port_tx.send(actual_addr.port()).unwrap();

            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(SUBJECT_ALT_NAMES.clone()).unwrap();

            let _cert_pem = cert.pem();
            let _key_pem = signing_key.serialize_pem();

            // Create a TLS server that explicitly does NOT support X25519MLKEM768
            // by using a provider that only supports traditional key exchange algorithms
            let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
            provider.kx_groups = vec![
                tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
                tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
                tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519,
            ];

            let server_config =
                tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                            cert.der().to_vec(),
                        )],
                        tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(
                            signing_key.serialize_der(),
                        )
                        .unwrap(),
                    )
                    .unwrap();

            let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = tls_acceptor.clone();
                let expected_errors = expected_errors_clone.clone();
                tokio::spawn(async move {
                    let err = acceptor.accept(stream).await.unwrap_err();
                    let rustls_err = err
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<rustls::Error>()
                        .unwrap();
                    assert_eq!(
                        *rustls_err,
                        rustls::Error::PeerIncompatible(
                            rustls::PeerIncompatible::NoKxGroupsInCommon
                        )
                    );
                    // Making sure that we reach this point, tokio::spawn can 'swallow' panics
                    expected_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        });

        let socket_pool = make_socket_pool();
        let allow_only_mlkem = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(10, socket_pool, allow_only_mlkem);

        let port = port_rx.await.unwrap();
        let result = ens
            .start_monitor_on_port(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                server_public_key,
                client_private_key,
            )
            .await;

        assert!(result.is_ok());

        // Wait a bit for the background task to attempt TLS handshake and fail
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Try to receive from the error channel - this should timeout
        // because the connection should fail during TLS handshake before any errors are sent
        let timeout_result = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;

        // We expect a timeout because the connection should fail during TLS handshake
        // and never reach the point where it can send error notifications
        assert!(timeout_result.is_err());

        ens.stop().await;

        assert_eq!(expected_errors.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    fn make_socket_pool() -> Arc<SocketPool> {
        Arc::new(SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ))
    }
}
