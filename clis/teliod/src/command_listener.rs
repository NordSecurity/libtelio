use crate::{daemon::TelioTaskCmd, ClientCmd, DaemonSocket, TelioStatusReport, TeliodError};
use serde::{Deserialize, Serialize};
use telio::telio_task::io::chan;
use tokio::sync::oneshot;
use tracing::{error, info};

/// Command response type used to communicate between `telio runner -> daemon -> client`
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum CommandResponse {
    Ok,
    StatusReport(TelioStatusReport),
    Err(String),
}

impl CommandResponse {
    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap_or("Err serializing".to_string())
    }

    pub fn deserialize(input: &str) -> Result<CommandResponse, TeliodError> {
        serde_json::from_str::<CommandResponse>(input)
            .map_err(|e| TeliodError::InvalidResponse(format!("{}", e)))
    }
}

/// Helper to handle generic responses
async fn handle_response<F, T>(
    response_rx: oneshot::Receiver<T>,
    process_response: F,
) -> Result<CommandResponse, TeliodError>
where
    F: FnOnce(T) -> Result<CommandResponse, TeliodError>,
{
    match response_rx.await {
        Ok(response) => process_response(response),
        Err(e) => {
            error!("Error receiving response: {}", e);
            Err(TeliodError::InvalidResponse(e.to_string()))
        }
    }
}

pub struct CommandListener {
    socket: DaemonSocket,
    /// Channel to send commands to telio task
    telio_task_tx: chan::Tx<TelioTaskCmd>,
}

impl CommandListener {
    pub fn new(socket: DaemonSocket, telio_task_tx: chan::Tx<TelioTaskCmd>) -> CommandListener {
        CommandListener {
            socket,
            telio_task_tx,
        }
    }

    async fn process_command(
        &mut self,
        command: &ClientCmd,
    ) -> Result<CommandResponse, TeliodError> {
        match command {
            ClientCmd::GetStatus => {
                info!("Reporting telio status");
                let (response_tx, response_rx) = oneshot::channel();
                #[allow(mpsc_blocking_send)]
                self.telio_task_tx
                    .send(TelioTaskCmd::GetStatus(response_tx))
                    .await
                    .map_err(|e| {
                        error!("Error sending command: {}", e);
                        TeliodError::CommandFailed(ClientCmd::GetStatus)
                    })?;
                // wait for a response from telio runner
                handle_response(response_rx, |report| {
                    Ok(CommandResponse::StatusReport(report))
                })
                .await
            }
            ClientCmd::QuitDaemon =>
            {
                #[allow(mpsc_blocking_send)]
                self.telio_task_tx
                    .send(TelioTaskCmd::Quit)
                    .await
                    .map(|_| CommandResponse::Ok)
                    .map_err(|e| {
                        error!("Error sending command: {}", e);
                        TeliodError::CommandFailed(ClientCmd::QuitDaemon)
                    })
            }
        }
    }

    pub async fn handle_client_connection(&mut self) -> Result<ClientCmd, TeliodError> {
        let mut connection = self.socket.accept().await?;
        let command_str = connection.read_command().await?;

        if let Ok(command) = serde_json::from_str::<ClientCmd>(&command_str) {
            let response = self.process_command(&command).await?;
            connection.respond(response.serialize()).await?;
            Ok(command)
        } else {
            connection
                .respond(
                    CommandResponse::Err(format!("Invalid command: {}", command_str)).serialize(),
                )
                .await?;
            Err(TeliodError::InvalidCommand(command_str))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientCmd, CommandResponse, DaemonSocket};
    use rand::Rng;
    use std::path::Path;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        sync::mpsc,
        task,
    };

    const TEST_SOCKET_PATH: &str = "test_socket";

    // Create a random socket path for the test, since tests run in parallel they can deadlock
    fn make_socket_path() -> String {
        let mut rng = rand::thread_rng();
        format!("{}_{}", TEST_SOCKET_PATH, rng.gen::<u16>())
    }

    // Helper to create a fake command listener
    fn make_command_listener(path: &str) -> CommandListener {
        let (tx, mut task_rx) = mpsc::channel(1);

        // spawn a fake telio task
        task::spawn(async move {
            match task_rx.recv().await.unwrap() {
                TelioTaskCmd::GetStatus(response_tx_channel) => {
                    let status_report = TelioStatusReport::default();
                    response_tx_channel.send(status_report).unwrap();
                }
                _ => (),
            }
        });

        let socket = DaemonSocket::new(Path::new(path)).unwrap();

        CommandListener::new(socket, tx)
    }

    // Simulate client sending command and waiting for response
    async fn client_send_command(path: &str, cmd: &str) -> std::io::Result<CommandResponse> {
        let mut client_stream = UnixStream::connect(&Path::new(path)).await?;
        client_stream.write(format!("{}\n", cmd).as_bytes()).await?;

        let mut data = vec![0; 1024];
        let size = client_stream.read(&mut data).await?;
        let response = String::from_utf8(data[..size].to_vec()).unwrap();
        Ok(CommandResponse::deserialize(response.trim()).unwrap())
    }

    // Broken client, closes connection without waiting for response
    async fn broken_client_send_command(path: &str, cmd: &str) -> std::io::Result<()> {
        let mut client_stream = UnixStream::connect(&Path::new(path)).await?;
        client_stream.write(format!("{}\n", cmd).as_bytes()).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_command_response_serialization() {
        let response = CommandResponse::Ok;
        assert_eq!(response.serialize(), "\"Ok\"");

        let error_response = CommandResponse::Err("Test error".to_string());
        assert_eq!(error_response.serialize(), "{\"Err\":\"Test error\"}");
    }

    #[tokio::test]
    async fn test_command_valid() {
        let path = make_socket_path();
        let mut listener = make_command_listener(&path);

        let command = serde_json::to_string(&ClientCmd::GetStatus).unwrap();
        let (cmd, response) = tokio::join!(
            listener.handle_client_connection(),
            client_send_command(&path, &command)
        );
        assert_eq!(cmd.unwrap(), ClientCmd::GetStatus);
        assert_eq!(
            response.unwrap(),
            CommandResponse::StatusReport(TelioStatusReport::default())
        );
    }

    #[tokio::test]
    async fn test_command_invalid() {
        let path = make_socket_path();
        let mut listener = make_command_listener(&path);

        let command = "garbage";
        let (cmd, _) = tokio::join!(
            listener.handle_client_connection(),
            client_send_command(&path, &command)
        );

        assert!(matches!(cmd, Err(TeliodError::InvalidCommand(_))));
    }

    #[tokio::test]
    async fn test_command_broken() {
        let path = make_socket_path();
        let mut listener = make_command_listener(&path);

        let command = "garbage";
        let (cmd, _) = tokio::join!(
            listener.handle_client_connection(),
            broken_client_send_command(&path, &command)
        );

        assert!(matches!(cmd, Err(TeliodError::Io(_))));
    }
}
