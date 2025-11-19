use std::net::IpAddr;

use clap::Parser;
use serde::{Deserialize, Serialize};
use telio::telio_task::io::chan;
use tokio::sync::oneshot;
use tracing::{error, trace};

use crate::{
    comms::{DaemonConnection, DaemonSocket},
    config::Endpoint,
    daemon::{NordVpnLiteError, TelioStatusReport},
};

pub(crate) const TIMEOUT_SEC: u64 = 10;

#[derive(Parser, Debug, PartialEq)]
#[clap()]
#[derive(Serialize, Deserialize)]
pub enum ClientCmd {
    #[clap(name = "status", about = "Retrieve the status report")]
    GetStatus,
    #[clap(hide = true)]
    IsAlive,
    #[clap(name = "stop", about = "Stop daemon execution")]
    QuitDaemon,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitNodeConfig {
    pub endpoint: Endpoint,
    pub dns: Vec<IpAddr>,
}

#[derive(Debug)]
pub enum TelioTaskCmd {
    // Get telio status
    GetStatus(oneshot::Sender<TelioStatusReport>),
    // Connect to exit node with endpoint and optional hostname
    ConnectToExitNode(ExitNodeConfig),
    // Break the receive loop to quit the daemon and exit gracefully
    Quit(oneshot::Sender<()>),
}

#[derive(Parser, Debug)]
pub(crate) struct DaemonOpts {
    /// Specify alternative configuration file
    #[clap(
        long = "config-file",
        short = 'c',
        default_value = "/etc/nordvpnlite/config.json"
    )]
    pub config_path: String,

    /// Do not detach the nordvpnlite process from the terminal
    #[clap(long = "no-detach")]
    pub no_detach: bool,

    /// Specifies the daemons working directory.
    ///
    /// Ignored with no_detach flag.
    #[clap(long = "working-directory", default_value = "/")]
    pub working_directory: String,

    /// Redirect standard output to the specified file
    ///
    /// Ignored with no-detach flag.
    #[clap(long = "stdout-path", default_value = "/var/log/nordvpnlite.log")]
    pub stdout_path: String,
}

/// NordVPN Lite is a lightweight, standalone VPN client built around
/// the libtelio library. It is designed for embedded and edge environments,
/// that are too resource constrained for the full NordVPN application.
#[derive(Parser, Debug)]
#[clap()]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("LIBTELIO_COMMIT_SHA"), ") ", env!("BUILD_PROFILE")))]
pub enum Cmd {
    #[clap(about = "Runs the nordvpnlite event loop")]
    Start(DaemonOpts),
    #[clap(flatten)]
    Client(ClientCmd),
    #[clap(about = "Show countries with available VPN servers")]
    Countries,
}

/// Command response type used to communicate between `telio runner -> daemon -> client`
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum CommandResponse {
    Ok,
    StatusReport(TelioStatusReport),
    DaemonInitializing,
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

    // Main command handling communicating with telio task
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
            ClientCmd::QuitDaemon => {
                trace!("Quitting telio task");
                let (response_tx, response_rx) = oneshot::channel();
                #[allow(mpsc_blocking_send)]
                self.telio_task_tx
                    .send(TelioTaskCmd::Quit(response_tx))
                    .await
                    .map_err(|e| {
                        error!("Error sending command: {}", e);
                        NordVpnLiteError::CommandFailed(ClientCmd::QuitDaemon)
                    })?;
                // Wait for a response from TelioTask
                // this essentually blocks the client quit command until the daemon initiated
                // cleanup
                handle_response(response_rx, |_| Ok(CommandResponse::Ok)).await
            }
            ClientCmd::IsAlive => Ok(CommandResponse::Ok),
        }
    }

    /// Accept a new incoming client connection.
    ///
    /// This wraps `UnixListener::accept()` and is cancel-safe.
    /// Important when used inside a `tokio::select!` loop,
    /// if any other branch completes first, this future may be cancelled.
    /// Once accepted, the connection must be handled by `handle_client_command()`.
    pub async fn accept_client_connection(&mut self) -> Result<DaemonConnection, NordVpnLiteError> {
        Ok(self.socket.accept().await?)
    }

    /// Handle a single command received from a client connection.
    ///
    /// This function reads a `ClientCmd` from the given connection,
    /// passes it on to TelioTask for processing and responds with a reply accordingly.
    /// `is_ready = false` - Ensures that early client commands during daemon startup are accepted.
    /// Note: Inside an already matched `select!` branch, `handle_client_command()` is safe from being cancelled.
    pub async fn handle_client_command(
        &mut self,
        is_ready: bool,
        mut connection: DaemonConnection,
    ) -> Result<ClientCmd, NordVpnLiteError> {
        let command_str = connection.read_command().await?;

        match serde_json::from_str::<ClientCmd>(&command_str) {
            Ok(command) => {
                let response = if is_ready {
                    self.process_command(&command).await?
                } else {
                    // Early command handling before TelioTask is initialized
                    match &command {
                        ClientCmd::QuitDaemon => CommandResponse::Ok,
                        ClientCmd::IsAlive => CommandResponse::Ok,
                        ClientCmd::GetStatus => CommandResponse::DaemonInitializing,
                    }
                };
                connection.respond(response.serialize()).await?;
                Ok(command)
            }
            Err(err) => {
                error!("Failed parsing command {command_str}: {err:?}");
                connection
                    .respond(
                        CommandResponse::Err(format!("Invalid command: {command_str}")).serialize(),
                    )
                    .await?;
                Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandResponse, DaemonSocket};
    use assert_matches::assert_matches;
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
        format!("{}_{}", TEST_SOCKET_PATH, rand::random::<u16>())
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
                TelioTaskCmd::Quit(response_tx_channel) => {
                    response_tx_channel.send(()).unwrap();
                }
                _ => {}
            }
        });

        let socket = DaemonSocket::new(Path::new(path)).unwrap();

        CommandListener::new(socket, tx)
    }

    // Simulate client sending command and waiting for response
    async fn client_send_command(path: &str, cmd: &str) -> std::io::Result<CommandResponse> {
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
    async fn broken_client_send_command(path: &str, cmd: &str) -> std::io::Result<()> {
        let mut client_stream = UnixStream::connect(&Path::new(path)).await?;
        client_stream
            .write_all(format!("{}\n", cmd).as_bytes())
            .await?;

        Ok(())
    }

    async fn test_command_helper(
        command: ClientCmd,
        is_ready: bool,
        broken_client: bool,
    ) -> (
        Result<CommandResponse, std::io::Error>,
        Result<ClientCmd, NordVpnLiteError>,
    ) {
        let path = make_socket_path();
        let mut listener = make_command_listener(&path);

        let command = serde_json::to_string(&command).unwrap();
        let daemon = tokio::spawn(async move {
            let connection = listener.accept_client_connection().await.unwrap();

            listener.handle_client_command(is_ready, connection).await
        });

        let daemon_response = if broken_client {
            broken_client_send_command(&path, &command).await.unwrap();
            Err(std::io::Error::other("broken client, no response"))
        } else {
            client_send_command(&path, &command).await
        };
        let client_command = daemon.await.unwrap();

        (daemon_response, client_command)
    }

    #[tokio::test]
    async fn test_command_response_serialization() {
        let response = CommandResponse::Ok;
        assert_eq!(response.serialize(), "\"Ok\"");

        let error_response = CommandResponse::Err("Test error".to_string());
        assert_eq!(error_response.serialize(), "{\"Err\":\"Test error\"}");
    }

    #[tokio::test]
    async fn test_command_quit() {
        let (response, cmd) = test_command_helper(ClientCmd::QuitDaemon, true, false).await;

        assert_eq!(response.unwrap(), CommandResponse::Ok);
        assert_eq!(cmd.unwrap(), ClientCmd::QuitDaemon);
    }

    #[tokio::test]
    async fn test_command_is_alive() {
        let (response, cmd) = test_command_helper(ClientCmd::IsAlive, true, false).await;

        assert_eq!(response.unwrap(), CommandResponse::Ok);
        assert_eq!(cmd.unwrap(), ClientCmd::IsAlive);
    }

    #[tokio::test]
    async fn test_command_status() {
        let (response, cmd) = test_command_helper(ClientCmd::GetStatus, true, false).await;

        assert_eq!(
            response.unwrap(),
            CommandResponse::StatusReport(TelioStatusReport::default())
        );
        assert_eq!(cmd.unwrap(), ClientCmd::GetStatus);
    }

    #[tokio::test]
    async fn test_command_invalid() {
        let path = make_socket_path();
        let mut listener = make_command_listener(&path);

        let command = "garbage";
        let daemon = tokio::spawn(async move {
            let connection = listener.accept_client_connection().await.unwrap();
            listener.handle_client_command(true, connection).await
        });
        let response = client_send_command(&path, command).await;
        let cmd = daemon.await.unwrap();

        assert_matches!(cmd, Err(NordVpnLiteError::ParsingError(_)));
        assert_matches!(response, Ok(CommandResponse::Err(_)));
    }

    #[tokio::test]
    async fn test_command_invalid_broken() {
        let path = make_socket_path();
        let mut listener = make_command_listener(&path);

        let command = "garbage";
        let daemon = tokio::spawn(async move {
            let connection = listener.accept_client_connection().await.unwrap();
            listener.handle_client_command(true, connection).await
        });
        let _ = broken_client_send_command(&path, command).await;
        let cmd = daemon.await.unwrap();

        assert_matches!(cmd, Err(NordVpnLiteError::Io(_)));
    }

    #[tokio::test]
    async fn test_command_broken() {
        let (_, cmd) = test_command_helper(ClientCmd::GetStatus, true, true).await;

        assert_matches!(cmd, Err(NordVpnLiteError::Io(_)));
    }

    #[tokio::test]
    async fn test_command_early_quit() {
        let (response, cmd) = test_command_helper(ClientCmd::QuitDaemon, false, false).await;

        assert_eq!(cmd.unwrap(), ClientCmd::QuitDaemon);
        assert_eq!(response.unwrap(), CommandResponse::Ok);
    }

    #[tokio::test]
    async fn test_command_early_is_alive() {
        let (response, cmd) = test_command_helper(ClientCmd::IsAlive, false, false).await;

        assert_eq!(cmd.unwrap(), ClientCmd::IsAlive);
        assert_eq!(response.unwrap(), CommandResponse::Ok);
    }

    #[tokio::test]
    async fn test_command_early_status() {
        let (response, cmd) = test_command_helper(ClientCmd::GetStatus, false, false).await;

        assert_eq!(cmd.unwrap(), ClientCmd::GetStatus);
        assert_eq!(response.unwrap(), CommandResponse::DaemonInitializing);
    }
}
