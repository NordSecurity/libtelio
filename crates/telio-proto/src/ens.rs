use std::net::IpAddr;

use grpc::{ConnectionError, Empty};
use telio_task::io::{
    chan::{Rx, Tx},
    Chan,
};
use telio_utils::{telio_log_debug, telio_log_warn};
use tokio::{select, sync::watch};

#[allow(missing_docs)]
pub(crate) mod grpc {
    tonic::include_proto!("ens");
}

const ENS_PORT: u16 = 993;

/// TODO
pub struct ErrorNotificationService {
    quit: Option<watch::Sender<bool>>,
    tx: Tx<ConnectionError>,
}

impl Drop for ErrorNotificationService {
    fn drop(&mut self) {
        self.stop_old_monitor();
    }
}

impl ErrorNotificationService {
    /// TODO
    pub fn new(buffer_size: usize) -> (Self, Rx<ConnectionError>) {
        let Chan { rx, tx }: Chan<ConnectionError> = Chan::new(buffer_size);
        (Self { quit: None, tx }, rx)
    }

    /// TODO
    pub async fn start_monitor(&mut self, vpn_ip: IpAddr) {
        self.start_monitor_on_port(vpn_ip, ENS_PORT).await
    }

    async fn start_monitor_on_port(&mut self, vpn_ip: IpAddr, ens_port: u16) {
        self.stop_old_monitor();

        let (quit_tx, mut quit_rx): (watch::Sender<bool>, watch::Receiver<bool>) =
            watch::channel(false);

        self.quit = Some(quit_tx);

        let vpn_uri = tonic::transport::Uri::builder()
            .scheme("http") //TODO
            .authority(format!("{vpn_ip}:{ens_port}"))
            .path_and_query("/")
            .build()
            .unwrap();
        let mut client = grpc::ens_client::EnsClient::connect(vpn_uri.clone())
            .await
            .unwrap();
        let mut stream = client
            .connection_errors(tonic::Request::<Empty>::new(Empty::default()))
            .await
            .unwrap()
            .into_inner();

        let tx = self.tx.clone();

        let vpn_uri = vpn_uri.to_owned();
        tokio::spawn(async move {
            loop {
                select! {
                    _ = quit_rx.wait_for(|b| *b)=> {
                        println!("got quit");
                        telio_log_debug!("ENS monitor for '{vpn_uri}' ends");
                        break
                    }
                    error_notification = stream.message() => {
                        telio_log_warn!("Received error notification for '{vpn_uri}': {error_notification:?}");
                        match error_notification {
                            Ok(Some(error_notification)) =>{
                                if let Err(e) = tx.try_send(error_notification) {
                                    telio_log_warn!("Failed to publish newly received error notification: {e}");
                                }
                            }
                            Ok(None) => {
                                telio_log_debug!("'{vpn_uri}' closed the grpc stream");
                                break;
                            }
                            Err(_) => todo!(),
                        }
                    }
                };
            }
            telio_log_debug!("ENS monitor for '{vpn_uri}' terminates");
        });
    }

    /// TODO
    pub async fn stop(mut self) {
        self.stop_old_monitor();
    }

    fn stop_old_monitor(&mut self) {
        if let Some(quit) = self.quit.take() {
            if let Err(e) = quit.send(true) {
                telio_log_warn!("Failed to stop previous ENS monitor: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::{net::Ipv4Addr, time::Duration};

    use grpc::{
        ens_server::{self, EnsServer},
        ConnectionError, Empty,
    };
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
            println!("got request");
            let (tx, rx) = mpsc::channel(1);
            let errors = self.0.clone();
            tokio::spawn(async move {
                for error in errors {
                    println!("emitting error: {error:?}");
                    tx.send(Ok(error)).await.unwrap();
                }
            });

            Ok(tonic::Response::new(ReceiverStream::new(rx)))
        }
    }

    #[tokio::test]
    #[test_log::test]
    async fn foo() {
        println!("foo start");
        let errors_to_emit = vec![
            ConnectionError {
                code: grpc::Error::Unknown as i32,
                additional_info: None,
            },
            ConnectionError {
                code: grpc::Error::ConnectionLimitReached as i32,
                additional_info: Some("additional info".to_owned()),
            },
        ];
        let srv = EnsServer::new(TestENSService(errors_to_emit.clone()));
        println!("srv created");
        let (port_tx, port_rx) = oneshot::channel();

        tokio::spawn(async move {
            // TODO: figure out how to bind to random free port
            println!("task started");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let actual_addr = listener.local_addr().unwrap();
            println!("gRPC server listening on: {}", actual_addr);
            println!("Assigned port: {}", actual_addr.port());
            port_tx.send(actual_addr.port()).unwrap();

            Server::builder()
                .add_service(srv)
                .serve("127.0.0.1:4433".parse().unwrap())
                // .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        println!("serve done");
        let _addr = format!("http://127.0.0.0:{}", port_rx.await.unwrap());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let addr = "http://127.0.0.1:4433";
        println!("addr: {addr:?}");
        let (mut ens, mut rx) = ErrorNotificationService::new(10);
        ens.start_monitor_on_port(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433)
            .await;
        let _collected_errors = collect_errors(2, &mut rx).await;
        ens.start_monitor_on_port(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433)
            .await;

        let collected_errors = collect_errors(2, &mut rx).await;

        assert_eq!(errors_to_emit, collected_errors);

        ens.stop().await;

        // Stopping, should eventually be processed by the running task, and it should
        // drop last remaining instance of the Tx side.
        while !rx.is_closed() {}
    }

    async fn collect_errors(n: usize, rx: &mut Rx<ConnectionError>) -> Vec<ConnectionError> {
        let mut ret = vec![];
        for i in 0..n {
            let error = rx.recv().await.unwrap();
            println!("Received error: {error:?}");
            ret.push(error);
        }
        ret
    }
}
