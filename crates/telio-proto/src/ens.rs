use std::{
    net::{IpAddr, ToSocketAddrs},
    str::FromStr,
    sync::Arc,
};

use base64::prelude::{Engine, BASE64_STANDARD};
use blake3::{derive_key, keyed_hash};
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
use telio_utils::{
    exponential_backoff::{self, Backoff},
    telio_log_debug, telio_log_error, telio_log_info, telio_log_warn,
};
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

pub(crate) mod grpc {
    pub use llt_proto::ens::{
        ens_client, login_client, ChallengeRequest, ConnectionError, ConnectionErrorRequest, Error,
    };
}

const CONTEXT: &str = "ens-auth";
const ENS_PORT: u16 = 993;
const AUTHENTICATION_KEY: &str = "authentication";
const DEFAULT_ROOT_CERTIFICATE: &[u8] = include_bytes!("../data/default_root_certificate.der");

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
    /// Exponential backoff creation error
    #[error("Exponential backoff creation failed {0}")]
    ExponentialBackoff(#[from] exponential_backoff::Error),
}

/// ErrorNotificationService manages tasks started and stopped to consume the ENS grpc error streams
pub struct ErrorNotificationService {
    quit: Option<(watch::Sender<bool>, JoinHandle<()>)>,
    tx: Tx<(grpc::ConnectionError, PublicKey)>,
    socket_pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
    // DER encoded root certificate to be use for verification of TLS
    root_certificate: Vec<u8>,
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
        root_certificate_override: Option<Vec<u8>>,
    ) -> (Self, Rx<(grpc::ConnectionError, PublicKey)>) {
        let Chan { rx, tx }: Chan<(grpc::ConnectionError, PublicKey)> = Chan::new(buffer_size);
        if let Some(cert) = &root_certificate_override {
            telio_log_info!(
                "Will use root certificate override: {:?}",
                BASE64_STANDARD.encode(cert)
            );
        }

        (
            Self {
                quit: None,
                tx,
                socket_pool,
                allow_only_mlkem,
                root_certificate: root_certificate_override
                    .unwrap_or_else(|| DEFAULT_ROOT_CERTIFICATE.to_vec()),
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
        backoff: impl Backoff,
    ) -> Result<(), Error> {
        self.start_monitor_on_port(vpn_ip, ENS_PORT, vpn_public_key, local_private_key, backoff)
            .await
    }

    async fn start_monitor_on_port(
        &mut self,
        vpn_ip: IpAddr,
        ens_port: u16,
        vpn_public_key: PublicKey,
        local_private_key: SecretKey,
        backoff: impl Backoff,
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
        let root_certificate = self.root_certificate.clone();

        let join_handle = tokio::spawn(async move {
            // This future is too big for keeping it on the stack
            if let Err(e) = Box::pin(task(
                &vpn_uri,
                vpn_public_key,
                local_private_key,
                pool.clone(),
                tx,
                quit_rx,
                allow_only_mlkem,
                backoff,
                root_certificate,
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

#[allow(clippy::too_many_arguments)]
async fn task(
    vpn_uri: &str,
    vpn_public_key: PublicKey,
    local_private_key: SecretKey,
    pool: Arc<SocketPool>,
    tx: Tx<(grpc::ConnectionError, PublicKey)>,
    mut quit_rx: watch::Receiver<bool>,
    allow_only_mlkem: bool,
    mut backoff: impl Backoff,
    root_certificate: Vec<u8>,
) -> anyhow::Result<()> {
    'outer: loop {
        macro_rules! restart {
            ($backoff: expr) => {
                tokio::time::sleep(backoff.get_backoff()).await;
                backoff.next_backoff();
                continue 'outer;
            };
        }
        /// If the Err is returned but ENS shouldn't quit yet, the outer loop will be restarted
        /// and the task will reconnect. If we should quit, the task will terminate. In case of Ok
        /// case, the macro will evaluete to the inner value of Ok.
        macro_rules! handle_error {
            ($value: expr, $backoff: expr) => {
                match $value {
                    Ok(v) => v,
                    Err(e) => {
                        telio_log_warn!("ENS task transient failure: {e}");
                        if *quit_rx.borrow() == true {
                            break 'outer;
                        }
                        restart!($backoff);
                    }
                }
            };
        }

        let pool = pool.clone();
        let external_channel = handle_error!(
            Box::pin(create_external_channel(
                vpn_uri,
                pool,
                allow_only_mlkem,
                root_certificate.clone()
            ))
            .await,
            backoff
        );

        let authenticated_challenge = handle_error!(
            get_login_challenge(
                external_channel.clone(),
                vpn_public_key,
                local_private_key.clone(),
            )
            .await,
            backoff
        );

        let mut client = grpc::ens_client::EnsClient::with_interceptor(
            external_channel,
            authentication_interceptor(authenticated_challenge),
        );

        let connection = handle_error!(
            client
                .connection_errors(ConnectionErrorRequest::default())
                .await,
            backoff
        );
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
                            backoff.reset();
                            if let Err(e) = tx.try_send((error_notification, vpn_public_key)) {
                                telio_log_warn!("Failed to publish newly received error notification: {e}");
                            }
                        }
                        Ok(None) => {
                            telio_log_debug!("'{vpn_uri}' closed the grpc stream");
                            break 'outer;
                        }
                        Err(e) => {
                            // After the first error, the stream will never return any new value, which means
                            // we need to reconnect. For details, see: https://github.com/hyperium/tonic/blob/c9cc210cb7c6f3f937786a3134c682761a26c65c/tonic/src/codec/decode.rs#L392-L394
                            telio_log_error!("GRPC error: {e}");
                            break;
                        }
                    }
                }
            };
        }
        restart!(&mut backoff);
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
    root_certificate: Vec<u8>,
) -> anyhow::Result<Channel> {
    let socket_factory = move |uri: Uri| {
        let pool = pool.clone();
        let root_certificate = root_certificate.clone();
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
                let tls_connector = make_tls_connector(allow_only_mlkem, &root_certificate)?;
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
fn make_tls_connector(
    _allow_only_mlkem: bool,
    _root_certificate: &[u8],
) -> std::io::Result<TlsConnector> {
    telio_log_warn!("An attempt was made to enable ENS when it is disabled at compile time");
    Err(std::io::Error::other("ENS is disabled"))
}

#[cfg(feature = "enable_ens")]
fn make_tls_connector(
    allow_only_mlkem: bool,
    root_certificate: &[u8],
) -> std::io::Result<TlsConnector> {
    use rustls::RootCertStore;

    #[derive(Debug)]
    struct TrustedRootCertVerifier(RootCertStore);

    impl TrustedRootCertVerifier {
        fn new(root_certificate: &[u8]) -> std::io::Result<Self> {
            let mut root_store = RootCertStore::empty();
            let (added, ignored) = root_store
                .add_parsable_certificates([CertificateDer::from_slice(root_certificate)]);
            if ignored > 0 {
                telio_log_warn!("Added {added} certs to trusted store, ignored: {ignored}");
                Err(std::io::Error::other(
                    "Failed to add root cert to the root certificate store",
                ))
            } else {
                telio_log_debug!("Added {added} certs to trusted store, ignored: {ignored}");
                Ok(Self(root_store))
            }
        }
    }

    impl ServerCertVerifier for TrustedRootCertVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            use rustls::{
                client::verify_server_cert_signed_by_trust_anchor,
                pki_types::SignatureVerificationAlgorithm, server::ParsedCertificate,
            };
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(end_entity).into();
            telio_log_info!(
                "Remote gRPC server ({server_name:?}) sha256 fingerprint: {}",
                hex::encode(hash)
            );

            let end_entity: ParsedCertificate = end_entity.try_into()?;

            use webpki::aws_lc_rs::*;
            let schemas: Vec<&dyn SignatureVerificationAlgorithm> = vec![
                ECDSA_P256_SHA256,
                ECDSA_P384_SHA384,
                ECDSA_P521_SHA512,
                ED25519,
                RSA_PKCS1_2048_8192_SHA256,
                RSA_PKCS1_2048_8192_SHA384,
                RSA_PKCS1_2048_8192_SHA512,
                RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            ];

            let verification = verify_server_cert_signed_by_trust_anchor(
                &end_entity,
                &self.0,
                intermediates,
                now,
                &schemas,
            );

            telio_log_info!("Remote gRPC TLS certificate verification result: {verification:?}");
            match verification {
                Ok(()) => Ok(ServerCertVerified::assertion()),
                Err(e) => Err(e),
            }
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
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
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
        .with_custom_certificate_verifier(Arc::new(TrustedRootCertVerifier::new(root_certificate)?))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(TlsConnector::from(Arc::new(tls_config)))
}

fn authentication_tag(secret: SharedSecret, message: &[u8]) -> [u8; 32] {
    let key = derive_key(CONTEXT, &secret);
    *keyed_hash(&key, message).as_bytes()
}

/// Install the default crypto provider for rustls
///
/// In case there are two providers present (ring and aws-lc-rs) rustls requires the user
/// to explicitly configure the one which should be used by default.
#[cfg(feature = "enable_ens")]
pub fn install_default_crypto_provider() {
    if let Err(e) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        telio_log_warn!("Failed to install default crypto provider for rustls: {e:?}");
    }
}

/// When ENS is disabled, we should only have ring provider and there should be no need
/// to explicitly configure the default crypto provider. But just to be on the safe side,
/// (and handle a case where there 3rd crypto provider) we will configure ring either way.
#[cfg(not(feature = "enable_ens"))]
pub fn install_default_crypto_provider() {
    if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
        telio_log_warn!("Failed to install default crypto provider for rustls: {e:?}");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::Ipv4Addr,
        sync::{atomic::AtomicUsize, LazyLock, Mutex},
        time::Duration,
    };

    use async_channel::{self, unbounded, Receiver, Sender};
    use llt_proto::ens::{
        ens_server::{self, EnsServer},
        login_server::{self, LoginServer},
        ChallengeResponse, ConnectionError,
    };
    use rcgen::{
        generate_simple_self_signed, BasicConstraints, CertificateParams, CertifiedKey,
        DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };
    use telio_crypto::SecretKey;
    use telio_sockets::NativeProtector;
    use telio_utils::exponential_backoff::{
        ExponentialBackoff, ExponentialBackoffBounds, MockBackoff,
    };
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::{service::Interceptor, transport::Server};

    use super::*;

    const SUBJECT_ALT_NAMES: LazyLock<Vec<String>> =
        LazyLock::new(|| vec!["localhost".to_string(), "127.0.0.1".to_string()]);

    #[derive(Debug)]
    enum Command {
        Send(ConnectionError),
        Error(tonic::Status),
        End,
    }

    struct State {
        command_rx: Receiver<Command>,
        challenges: Mutex<HashSet<Uuid>>,
        vpn_server_private_key: SecretKey,
    }

    impl State {
        fn new(command_rx: Receiver<Command>, vpn_server_private_key: SecretKey) -> Self {
            Self {
                challenges: Mutex::new(HashSet::default()),
                vpn_server_private_key,
                command_rx,
            }
        }
    }

    // Root CA and a leaf cert issued by it
    #[derive(Debug)]
    struct TlsConfig {
        ca_cert_der: Vec<u8>,
        leaf_cert_pem: String,
        leaf_key_pem: String,
    }

    impl TlsConfig {
        fn new() -> Self {
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

            let mut ca_dn = DistinguishedName::new();
            ca_dn.push(DnType::CommonName, "Test CA");
            ca_dn.push(DnType::OrganizationName, "Test Org");
            ca_params.distinguished_name = ca_dn;

            let ca_key_pair = KeyPair::generate().unwrap();
            let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
            let issuer = Issuer::new(ca_params, ca_key_pair);

            let mut leaf_params = CertificateParams::default();
            let mut leaf_dn = DistinguishedName::new();
            leaf_dn.push(DnType::CommonName, "localhost");
            leaf_params.distinguished_name = leaf_dn;
            leaf_params.subject_alt_names = vec![
                rcgen::SanType::DnsName("localhost".parse().unwrap()),
                rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            ];

            let leaf_key_pair = KeyPair::generate().unwrap();
            let leaf_cert = leaf_params.signed_by(&leaf_key_pair, &issuer).unwrap();

            let ca_cert_der = ca_cert.der().to_vec();
            let leaf_cert_pem = leaf_cert.pem();
            let leaf_key_pem = leaf_key_pair.serialize_pem();

            TlsConfig {
                ca_cert_der,
                leaf_cert_pem,
                leaf_key_pem,
            }
        }
    }

    #[derive(Clone)]
    struct GrpcStub(Arc<State>);

    impl std::ops::Deref for GrpcStub {
        type Target = State;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[tonic::async_trait]
    impl ens_server::Ens for GrpcStub {
        type ConnectionErrorsStream = ReceiverStream<Result<ConnectionError, tonic::Status>>;
        async fn connection_errors(
            &self,
            _request: tonic::Request<ConnectionErrorRequest>,
        ) -> std::result::Result<tonic::Response<Self::ConnectionErrorsStream>, tonic::Status>
        {
            let (tx, rx) = tokio::sync::mpsc::channel(1);

            let command_rx = self.command_rx.clone();
            tokio::spawn(async move {
                loop {
                    println!("next loop iteration...");
                    match command_rx.recv().await.unwrap() {
                        Command::Send(e) => tx.send(Ok(e)).await.unwrap(),
                        Command::Error(status) => tx.send(Err(status)).await.unwrap(),
                        Command::End => break,
                    }
                }
            });

            Ok(tonic::Response::new(ReceiverStream::new(rx)))
        }
    }

    #[tonic::async_trait]
    impl login_server::Login for GrpcStub {
        async fn get_challenge(
            &self,
            _request: tonic::Request<ChallengeRequest>,
        ) -> std::result::Result<tonic::Response<ChallengeResponse>, tonic::Status> {
            let challenge = Uuid::new_v4();
            self.challenges.lock().unwrap().insert(challenge);
            Ok(tonic::Response::new(ChallengeResponse {
                challenge: challenge.to_string(),
            }))
        }
    }

    #[derive(Clone)]
    struct CheckAuthenticationInterceptor(GrpcStub);

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

    struct ServerConfig {
        port: u16,
        public_key: PublicKey,
        command_tx: Sender<Command>,
        tls_config: TlsConfig,
    }

    async fn spawn_server() -> ServerConfig {
        install_default_crypto_provider();
        let server_private_key = SecretKey::gen();

        let (command_tx, command_rx) = unbounded();
        let grpc_stub = GrpcStub(Arc::new(State::new(command_rx, server_private_key.clone())));
        let ens_srv = EnsServer::with_interceptor(
            grpc_stub.clone(),
            CheckAuthenticationInterceptor(grpc_stub.clone()),
        );
        let login_srv = LoginServer::new(grpc_stub.clone());
        let (port_tx, port_rx) = oneshot::channel();
        let tls_config = TlsConfig::new();

        let cert_pem = tls_config.leaf_cert_pem.clone();
        let key_pem = tls_config.leaf_key_pem.clone();
        tokio::spawn({
            let cert_pem = cert_pem.clone();
            async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let actual_addr = listener.local_addr().unwrap();
                port_tx.send(actual_addr.port()).unwrap();

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
            }
        });

        ServerConfig {
            port: port_rx.await.unwrap(),
            public_key: server_private_key.public(),
            command_tx,
            tls_config,
        }
    }

    async fn send_errors(errors_to_emit: &[ConnectionError], errors_tx: Sender<Command>) {
        let errors_to_emit = errors_to_emit.to_vec();
        for e in errors_to_emit {
            errors_tx.send(Command::Send(e)).await.unwrap();
        }
        errors_tx.send(Command::End).await.unwrap();
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_ens() {
        let bounds = ExponentialBackoffBounds::default();
        let backoff = ExponentialBackoff::new(bounds).unwrap();
        let client_private_key = SecretKey::gen();

        let errors_to_emit = [
            ConnectionError {
                code: grpc::Error::Unknown as i32,
                additional_info: None,
            },
            ConnectionError {
                code: grpc::Error::ConnectionLimitReached as i32,
                additional_info: Some("additional info".to_owned()),
            },
        ];

        let server_config = spawn_server().await;

        let allow_only_mlkem = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            10,
            make_socket_pool(),
            allow_only_mlkem,
            Some(server_config.tls_config.ca_cert_der.clone()),
        );

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            server_config.port,
            server_config.public_key,
            client_private_key.clone(),
            backoff.clone(),
        )
        .await
        .unwrap();

        send_errors(&errors_to_emit, server_config.command_tx.clone()).await;
        let _collected_errors = collect_errors(2, &mut rx).await;

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            server_config.port,
            server_config.public_key,
            client_private_key,
            backoff,
        )
        .await
        .unwrap();

        send_errors(&errors_to_emit, server_config.command_tx.clone()).await;
        let collected_errors = collect_errors(2, &mut rx).await;

        assert_eq!(
            errors_to_emit
                .into_iter()
                .map(|e| (e, server_config.public_key.clone()))
                .collect::<Vec<_>>(),
            collected_errors
        );

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
    async fn test_ens_backoff() {
        let client_private_key = SecretKey::gen();

        let errors_to_emit = [
            ConnectionError {
                code: grpc::Error::Unknown as i32,
                additional_info: None,
            },
            ConnectionError {
                code: grpc::Error::ConnectionLimitReached as i32,
                additional_info: Some("additional info".to_owned()),
            },
        ];

        let server_config = spawn_server().await;

        let allow_only_mlkem = true;

        let (mut ens, mut rx) = ErrorNotificationService::new(
            10,
            make_socket_pool(),
            allow_only_mlkem,
            Some(server_config.tls_config.ca_cert_der.clone()),
        );

        let mut backoff = MockBackoff::new();

        backoff.expect_reset().times(4).return_const(());
        backoff
            .expect_get_backoff()
            .times(1)
            .return_const(Duration::from_secs(1));
        backoff.expect_next_backoff().times(1).return_const(());

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            server_config.port,
            server_config.public_key,
            client_private_key.clone(),
            backoff,
        )
        .await
        .unwrap();

        for e in errors_to_emit.clone() {
            server_config
                .command_tx
                .send(Command::Send(e))
                .await
                .unwrap();
        }
        server_config
            .command_tx
            .send(Command::Error(tonic::Status::unknown("some message")))
            .await
            .unwrap();
        server_config.command_tx.send(Command::End).await.unwrap();
        for e in errors_to_emit {
            server_config
                .command_tx
                .send(Command::Send(e))
                .await
                .unwrap();
        }
        let _collected_errors = collect_errors(3, &mut rx).await;
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

        let allow_only_mlkem = true;
        let (mut ens, mut rx) =
            ErrorNotificationService::new(10, make_socket_pool(), allow_only_mlkem, None);

        let result = ens
            .start_monitor_on_port(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port_rx.await.unwrap(),
                server_public_key,
                client_private_key,
                ExponentialBackoff::new(Default::default()).unwrap(),
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
