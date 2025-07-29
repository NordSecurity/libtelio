use std::{net::IpAddr, sync::Arc};

use grpc::{ConnectionError, Empty};
use http::Uri;
use hyper_util::rt::TokioIo;
use telio_model::PublicKey;
use telio_sockets::SocketPool;
use telio_task::io::{
    chan::{Rx, Tx},
    Chan,
};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_info, telio_log_warn};
use tokio::{select, sync::watch, task::JoinHandle};
use tonic::transport::Endpoint;
use tower::service_fn;

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

const ENS_PORT: u16 = 993;

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
    ) -> (Self, Rx<(ConnectionError, PublicKey)>) {
        let Chan { rx, tx }: Chan<(ConnectionError, PublicKey)> = Chan::new(buffer_size);
        (
            Self {
                quit: None,
                tx,
                socket_pool,
            },
            rx,
        )
    }

    /// Start new task that will monitor ENS instance running on the `vpn_ip`:993
    pub async fn start_monitor(
        &mut self,
        vpn_ip: IpAddr,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        self.start_monitor_on_port(vpn_ip, ENS_PORT, public_key)
            .await
    }

    async fn start_monitor_on_port(
        &mut self,
        vpn_ip: IpAddr,
        ens_port: u16,
        vpn_public_key: PublicKey,
    ) -> Result<(), Error> {
        telio_log_info!("Will start ENS monitoring on {vpn_ip}:{ens_port} ({vpn_public_key:?})");
        self.stop().await;

        let (quit_tx, quit_rx): (watch::Sender<bool>, watch::Receiver<bool>) =
            watch::channel(false);

        let vpn_uri = format!("http://{vpn_ip}:{ens_port}");

        let pool = self.socket_pool.clone();
        let tx = self.tx.clone();

        let join_handle = tokio::spawn(async move {
            // This future is too big for keeping it on the stack
            if let Err(e) = Box::pin(task(
                vpn_uri.clone(),
                vpn_public_key,
                pool.clone(),
                tx,
                quit_rx,
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
    pool: Arc<SocketPool>,
    tx: Tx<(ConnectionError, PublicKey)>,
    mut quit_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    'outer: loop {
        let pool = pool.clone();
        let channel = Endpoint::try_from(vpn_uri.clone())?
            .connect_with_connector(service_fn(move |u: Uri| {
                let pool = pool.clone();
                async move {
                    let socket = pool.new_external_tcp_v4(None)?;
                    let h = match u.host() {
                        Some(host) => host,
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "missing host in vpn uri",
                            ))
                        }
                    };
                    let p = match u.port_u16() {
                        Some(port) => port,
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "missing port in vpn uri",
                            ))
                        }
                    };
                    Ok::<_, std::io::Error>(TokioIo::new(
                        socket
                            .connect(format!("{h}:{p}").parse().map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
                            })?)
                            .await?,
                    ))
                }
            }))
            .await?;

        let mut client = grpc::ens_client::EnsClient::new(channel);

        let connection = client
            .connection_errors(tonic::Request::<Empty>::new(Empty::default()))
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

#[cfg(test)]
mod tests {

    use std::net::Ipv4Addr;

    use grpc::{
        ens_server::{self, EnsServer},
        ConnectionError, Empty,
    };
    use telio_crypto::SecretKey;
    use telio_sockets::NativeProtector;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::transport::Server;

    use super::*;

    struct TestENSService(Vec<ConnectionError>);

    #[tonic::async_trait]
    impl ens_server::Ens for TestENSService {
        type ConnectionErrorsStream = ReceiverStream<Result<ConnectionError, tonic::Status>>;
        async fn connection_errors(
            &self,
            _request: tonic::Request<Empty>,
        ) -> std::result::Result<tonic::Response<Self::ConnectionErrorsStream>, tonic::Status>
        {
            let (tx, rx) = mpsc::channel(1);
            let errors = self.0.clone();
            tokio::spawn(async move {
                for error in errors {
                    tx.send(Ok(error)).await.unwrap();
                }
            });

            Ok(tonic::Response::new(ReceiverStream::new(rx)))
        }
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_ens() {
        let pk = SecretKey::gen().public();
        let errors_to_emit = vec![
            (
                ConnectionError {
                    code: grpc::Error::Unknown as i32,
                    additional_info: None,
                },
                pk,
            ),
            (
                ConnectionError {
                    code: grpc::Error::ConnectionLimitReached as i32,
                    additional_info: Some("additional info".to_owned()),
                },
                pk,
            ),
        ];
        let srv = EnsServer::new(TestENSService(
            errors_to_emit.iter().map(|(c, _)| c.clone()).collect(),
        ));
        let (port_tx, port_rx) = oneshot::channel();

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let actual_addr = listener.local_addr().unwrap();
            port_tx.send(actual_addr.port()).unwrap();

            Server::builder()
                .add_service(srv)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let port = port_rx.await.unwrap();

        let socket_pool = Arc::new(SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ));
        let (mut ens, mut rx) = ErrorNotificationService::new(10, socket_pool);

        ens.start_monitor_on_port(IpAddr::V4(Ipv4Addr::LOCALHOST), port, pk)
            .await
            .unwrap();
        let _collected_errors = collect_errors(2, &mut rx).await;
        ens.start_monitor_on_port(IpAddr::V4(Ipv4Addr::LOCALHOST), port, pk)
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
}
