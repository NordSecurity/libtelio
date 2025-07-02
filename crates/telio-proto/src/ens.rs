use grpc::ens_client;
use tonic::transport::Channel;

pub(crate) mod grpc {
    tonic::include_proto!("ens");
}

struct EnsClient {}

async fn start(dst: &str) -> ens_client::EnsClient<Channel> {
    // TODO: always use port 993
    let client = grpc::ens_client::EnsClient::connect(dst.to_owned())
        .await
        .unwrap();
    client
}

#[cfg(test)]
mod tests {

    use std::{sync::Arc, time::Duration};

    use grpc::{
        ens_server::{self, EnsServer},
        ConnectionError, Empty,
    };
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::{wrappers::ReceiverStream, Stream};
    use tonic::transport::Server;

    use super::*;

    struct TestENSService(Vec<ConnectionError>);

    #[tonic::async_trait]
    impl ens_server::Ens for TestENSService {
        type ConnectionErrorsStream = ReceiverStream<Result<ConnectionError, tonic::Status>>;
        async fn connection_errors(
            &self,
            request: tonic::Request<Empty>,
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
        let srv = EnsServer::new(TestENSService(vec![
            ConnectionError {
                code: grpc::Error::Unknown as i32,
                additional_info: None,
            },
            ConnectionError {
                code: grpc::Error::ConnectionLimitReached as i32,
                additional_info: Some("additional info".to_owned()),
            },
        ]));
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
        let addr = format!("http://127.0.0.0:{}", port_rx.await.unwrap());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let addr = "http://127.0.0.1:4433";
        println!("addr: {addr:?}");
        let mut client = start(&addr).await;

        let mut stream = client
            .connection_errors(tonic::Request::<Empty>::new(Empty::default()))
            .await
            .unwrap()
            .into_inner();

        println!("stream:");
        while let Some(error) = stream.message().await.unwrap() {
            println!("Received error: {error:?}");
        }
    }
}
