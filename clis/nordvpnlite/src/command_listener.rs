use clap::Parser;
use serde::{Deserialize, Serialize};
use telio::telio_task::io::chan;
use tokio::sync::oneshot;
use tracing::{error, trace};

use crate::{
    comms::DaemonSocket,
    config::Endpoint,
    daemon::{NordVpnLiteError, TelioStatusReport},
};

pub(crate) const TIMEOUT_SEC: u64 = 1;

#[derive(Parser, Debug, PartialEq)]
#[clap()]
#[derive(Serialize, Deserialize)]
pub enum ClientCmd {
    #[clap(about = "Retrieve the status report")]
    GetStatus,
    #[clap(about = "Query if daemon is running")]
    IsAlive,
    #[clap(about = "Stop daemon execution")]
    QuitDaemon,
}

#[derive(Debug)]
pub enum TelioTaskCmd {
    // Get telio status
    GetStatus(oneshot::Sender<TelioStatusReport>),
    // Connect to exit node with endpoint and optional hostname
    ConnectToExitNode(Endpoint),
    // Break the receive loop to quit the daemon and exit gracefully
    Quit,
}

#[derive(Parser, Debug)]
pub(crate) struct DaemonOpts {
    /// Path to the config file
    pub config_path: String,

    /// Do not detach the nordvpnlite process from the terminal
    #[clap(long = "no-detach")]
    pub no_detach: bool,

    /// Specifies the daemons working directory.
    ///
    /// Defaults to "/".
    /// Ignored with no_detach flag.
    #[clap(long = "working-directory", default_value = "/")]
    pub working_directory: String,

    /// Redirect standard output to the specified file
    ///
    /// Defaults to "/var/log/nordvpnlite.log".
    /// Ignored with no-detach flag.
    #[clap(long = "stdout-path", default_value = "/var/log/nordvpnlite.log")]
    pub stdout_path: String,
}

/// NordVPN Lite is a lightweight, standalone VPN client built around
/// the libtelio library. It is designed for embedded and edge environments,
/// that are too resource constrained for the full NordVPN application.
#[derive(Parser, Debug)]
#[clap()]
pub enum Cmd {
    #[clap(about = "Runs the nordvpnlite event loop")]
    Start(DaemonOpts),
    #[clap(flatten)]
    Client(ClientCmd),
}

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

    pub fn deserialize(input: &str) -> Result<CommandResponse, NordVpnLiteError> {
        serde_json::from_str::<CommandResponse>(input)
            .map_err(|e| NordVpnLiteError::InvalidResponse(format!("{e}")))
    }
}

/// Helper to handle generic responses
async fn handle_response<F, T>(
    response_rx: oneshot::Receiver<T>,
    process_response: F,
) -> Result<CommandResponse, NordVpnLiteError>
where
    F: FnOnce(T) -> Result<CommandResponse, NordVpnLiteError>,
{
    match response_rx.await {
        Ok(response) => process_response(response),
        Err(e) => {
            error!("Error receiving response: {}", e);
            Err(NordVpnLiteError::InvalidResponse(e.to_string()))
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
    ) -> Result<CommandResponse, NordVpnLiteError> {
        match command {
            ClientCmd::GetStatus => {
                trace!("Reporting telio status");
                let (response_tx, response_rx) = oneshot::channel();
                #[allow(mpsc_blocking_send)]
                self.telio_task_tx
                    .send(TelioTaskCmd::GetStatus(response_tx))
                    .await
                    .map_err(|e| {
                        error!("Error sending command: {}", e);
                        NordVpnLiteError::CommandFailed(ClientCmd::GetStatus)
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
                        NordVpnLiteError::CommandFailed(ClientCmd::QuitDaemon)
                    })
            }
            ClientCmd::IsAlive => Ok(CommandResponse::Ok),
        }
    }

    pub async fn try_recv_quit(&mut self) -> Result<(), NordVpnLiteError> {
        let mut connection = self.socket.accept().await?;
        let command_str = connection.read_command().await?;

        match serde_json::from_str::<ClientCmd>(&command_str) {
            Ok(ClientCmd::QuitDaemon) => {
                connection.respond(CommandResponse::Ok.serialize()).await?;
                Ok(())
            }
            Ok(_) => {
                connection
                    .respond(
                        CommandResponse::Err("Obtaining nordlynx key, ignoring".to_owned())
                            .serialize(),
                    )
                    .await?;
                Err(NordVpnLiteError::InvalidCommand(command_str))
            }
            Err(e) => {
                connection
                    .respond(
                        CommandResponse::Err(format!("Invalid command: {command_str}")).serialize(),
                    )
                    .await?;
                Err(e.into())
            }
        }
    }

    pub async fn handle_client_connection(&mut self) -> Result<ClientCmd, NordVpnLiteError> {
        let mut connection = self.socket.accept().await?;
        let command_str = connection.read_command().await?;

        if let Ok(command) = serde_json::from_str::<ClientCmd>(&command_str) {
            let response = self.process_command(&command).await?;
            connection.respond(response.serialize()).await?;
            Ok(command)
        } else {
            connection
                .respond(
                    CommandResponse::Err(format!("Invalid command: {command_str}")).serialize(),
                )
                .await?;
            Err(NordVpnLiteError::InvalidCommand(command_str))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandResponse, DaemonSocket};
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
        let mut rng = rand::rng();
        format!("{}_{}", TEST_SOCKET_PATH, rng.random::<u16>())
    }

    // Helper to create a fake command listener
    fn make_command_listener(path: &str) -> CommandListener {
        let (tx, mut task_rx) = mpsc::channel(1);

        // spawn a fake telio task
        task::spawn(async move {
            if let TelioTaskCmd::GetStatus(response_tx_channel) = task_rx.recv().await.unwrap() {
                let status_report = TelioStatusReport::default();
                response_tx_channel.send(status_report).unwrap();
            }
        });

        let socket = DaemonSocket::new(Path::new(path)).unwrap();

        CommandListener::new(socket, tx)
    }

    // Simulate client sending command and waiting for response
    async fn sdsds(path: &str, cmd: &str) -> std::io::Result<CommandResponse> {
        let mut client_stream = UnixStream::connect(&Path::new(path)).await?;
        client_stream
            .write_all(format!("{}\n", cmd).as_bytes())
            .await?;

        let mut data = vec![0; 1024];
        let size = client_stream.read(&mut data).await?;
        let response = String::from_utf8(data[..size].to_vec()).unwrap();
        Ok(CommandResponse::deserialize(response.trim()).unwrap())
    }

    // Broken client, closes connection without waiting for response
    async fn broken_csdslient_send_command(path: &str, cmd: &str) -> std::io::Result<()> {
        let mut client_stream = UnixStream::connect(&Path::new(path)).await?;
        client_stream
            .write_all(format!("{}\n", cmd).as_bytes())
            .await?;

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
            client_send_command(&path, command)
        );

        assert!(matches!(cmd, Err(NordVpnLiteError::InvalidCommand(_))));
    }

    #[tokio::test]
    async fn test_command_broken() {
        let path = make_socket_path();
        let mut listener = make_command_listener(&path);

        let command = "garbage";
        let (cmd, _) = tokio::join!(
            listener.handle_client_connection(),
            broken_client_send_command(&path, command)
        );

        assert!(matches!(cmd, Err(NordVpnLiteError::Io(_))));
    }
}
