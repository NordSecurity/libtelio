use std::collections::VecDeque;

use anyhow::Result;
use tokio::sync::{mpsc, oneshot, Mutex};
use tonic::{transport, Request, Response, Status};

use daemon_ipc::ipc_client::IpcClient;
use daemon_ipc::ipc_server::{Ipc, IpcServer};
use daemon_ipc::{CommandReply, CommandRequest};

pub mod daemon_ipc {
    tonic::include_proto!("daemon_ipc");
}

// Not using Arc here, because Ips is Arc internally? Need to verify this.
pub struct MyIpc {
    request_tx: Mutex<mpsc::Sender<String>>,
    response_rx: Mutex<mpsc::Receiver<String>>,
}

#[tonic::async_trait]
impl Ipc for MyIpc {
    async fn send_command(
        &self,
        request: Request<CommandRequest>,
    ) -> Result<Response<CommandReply>, Status> {
        if let Err(e) = self
            .request_tx
            .lock()
            .await
            .send(request.into_inner().message)
            .await
        {
            return Err(Status::unavailable(format!(
                "Server isn't listening for gRPC requests, {}",
                e
            )));
        }

        match self.response_rx.lock().await.recv().await {
            Some(message) => Ok(Response::new(daemon_ipc::CommandReply { message })),
            // TODO This sometimes may happen due to race conditions:
            None => {
                return Err(Status::unavailable(format!(
                    "Response mpsc channel had been closed too early."
                )))
            }
        }
    }
}

pub struct DaemonIPC {
    request_tx: mpsc::Sender<String>,
    response_rx: mpsc::Receiver<String>,
    shutdown_rx: oneshot::Receiver<()>,
}

impl DaemonIPC {
    pub fn new(
        request_tx: mpsc::Sender<String>,
        response_rx: mpsc::Receiver<String>,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            request_tx,
            response_rx,
            shutdown_rx,
        }
    }

    pub async fn listen(self, addr: &str) -> Result<()> {
        let ipc = MyIpc {
            request_tx: Mutex::new(self.request_tx),
            response_rx: Mutex::new(self.response_rx),
        };

        let test = addr.parse()?;

        transport::Server::builder()
            .add_service(IpcServer::new(ipc))
            .serve_with_shutdown(test, async {
                self.shutdown_rx.await.ok();
            })
            .await?;

        Ok(())
    }

    pub fn send_command(addr: &str, cmd: &str) -> Result<String> {
        let runtime = tokio::runtime::Runtime::new()?;

        runtime.block_on(async {
            // TODO not sure if http scheme the best choice here.
            let mut client = IpcClient::connect(format!("http://{}", addr)).await?;

            let request = tonic::Request::new(CommandRequest {
                message: cmd.to_owned(),
            });

            let response = client.send_command(request).await?;

            Ok(response.into_inner().message)
        })
    }

    // Implementing custom retry logic, because the ones I found in crates seemed to be either too much overhead or very sketchy.
    pub fn send_command_with_retries(
        addr: &str,
        cmd: &str,
        retry_delay_list: Vec<tokio::time::Duration>,
    ) -> Result<String> {
        // Converting Vec to VecDeque instead of using VecDeque from the start, because Vec has the vec! macro
        // which makes the calling code a lot cleaner for this function.
        let mut retry_delay_list: VecDeque<std::time::Duration> =
            retry_delay_list.into_iter().collect();
        loop {
            match DaemonIPC::send_command(addr, cmd) {
                Ok(response) => break Ok(response),
                Err(e) => match retry_delay_list.pop_front() {
                    Some(retry_delay) => std::thread::sleep(retry_delay),
                    None => break Err(e),
                },
            }
        }
    }
}
