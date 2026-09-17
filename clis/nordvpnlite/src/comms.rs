//! Code for handling inter process communication and abstracting away it's dependencies.

use std::{
    fs,
    io::{Error, ErrorKind, Result, Write},
    path::{Path, PathBuf},
};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[cfg(not(test))]
use interprocess::os::unix::local_socket::ListenerOptionsExt;
use interprocess::{
    local_socket::{
        tokio::{Listener as LocalSocketListener, Stream as LocalSocketStream},
        traits::tokio::{Listener, Stream},
        ListenerOptions, ToFsName,
    },
    os::unix::local_socket::FilesystemUdSocket,
};

/// Struct for handling connections of the daemon's side of the IPC communication with the API.
pub struct DaemonSocket {
    /// The inner socket over which the actual communication is happening.
    socket: LocalSocketListener,
}

impl DaemonSocket {
    /// Returns the path to the Nord VPN Lite socket, when available it uses `/run/`, then
    /// checks `/var/run` and if none of them is available it returns an error.
    ///
    /// # Returns
    ///
    /// A path to the Nord VPN Lite socket wrapped inside result
    pub fn get_ipc_socket_path() -> Result<PathBuf> {
        if Path::new("/run").exists() {
            Ok(PathBuf::from("/run/nordvpnlited.sock"))
        } else if Path::new("/var/run/").exists() {
            Ok(PathBuf::from("/var/run/nordvpnlited.sock"))
        } else {
            Err(Error::new(
                ErrorKind::NotFound,
                "Neither /run/ nor /var/run/ exists",
            ))
        }
    }

    /// Binds the IPC socket to the specified address and returns a handle to the struct
    /// containing the IPC socket.
    ///
    /// # Arguments
    ///
    /// * `ipc_socket_path` - Path of the IPC socket.
    ///
    /// # Returns
    ///
    /// An instance of Self wrapped inside of a Result.
    pub fn new(ipc_socket_path: &Path) -> Result<Self> {
        // Delete the socket file if it already exists
        let _ = fs::remove_file(ipc_socket_path);

        let options = ListenerOptions::new()
            .name(ipc_socket_path.to_fs_name::<FilesystemUdSocket>()?)
            .reclaim_name(true);

        // Disable setting umask for tests.
        // `umask()` C API call is operating on a process level, and therefore is not thread-safe.
        // As multiple cargo tests are executing in parallel this causes a panic.
        #[cfg(not(test))]
        // Mode for unix socket rw-------
        let options = options.mode(0o600);

        let socket = options.create_tokio()?;

        Ok(Self { socket })
    }

    /// Opens a connection on the IPC socket for listening to commands (requests) from the API and
    /// returns them to be processed by the event loop.
    /// The same connection is used to send responses back to the API when the event loop produces them.
    /// Note that since a single socket is used, care should be taken to not deadlock it.
    ///
    /// # Returns
    ///
    /// A struct for receiving commands from the new IPC connection stream and responding to them.
    pub async fn accept(&self) -> Result<DaemonConnection> {
        let stream = self.socket.accept().await?;

        Ok(DaemonConnection { stream })
    }

    /// Function for sending commands to the server.
    /// Also retrieves the response from the IPC server, but blocks while waiting for it.
    /// Both the command and the response are newline-terminated so each side knows when a
    /// message ends without having to close the socket. Commands must therefore not contain
    /// newlines (rejected below), which avoids the deadlock where both sides block waiting on
    /// each other for a message boundary.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address (more specifically path, but left address for clarity) of the IPC socket.
    /// * `cmd` - Command to be sent to the daemon.
    ///
    /// # Returns
    ///
    /// A Result containing a response string.
    pub async fn send_command(addr: &Path, cmd: &str) -> Result<String> {
        if cmd.contains('\n') {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Command cannot contain newline characters",
            ));
        }

        let mut stream =
            LocalSocketStream::connect(addr.to_fs_name::<FilesystemUdSocket>()?).await?;
        let mut buffer = Vec::<u8>::new();
        writeln!(buffer, "{cmd}")?;
        stream.write_all(&buffer).await?;

        let mut response_buffer = String::new();
        let mut reader = BufReader::new(&mut stream);
        if reader.read_line(&mut response_buffer).await? == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Daemon closed the connection without sending a response",
            ));
        }
        if response_buffer.ends_with('\n') {
            response_buffer.pop();
        }

        Ok(response_buffer)
    }
}

impl Drop for DaemonSocket {
    fn drop(&mut self) {
        // Normally this should be cleaned up, but in some cases it is not
        // The ipc path here should be valid, as the daemon socket is created
        // based on whether the path is valid or not.
        if let Ok(socket_path) = DaemonSocket::get_ipc_socket_path() {
            let _ = fs::remove_file(socket_path);
        }
    }
}

/// Struct for tracking a single IPC connection and keeping the stream
/// Mostly needed for keeping the stream while the server is generating a reply.
pub struct DaemonConnection {
    // The inner stream to be abstracted away.
    stream: LocalSocketStream,
}

impl DaemonConnection {
    /// Function for reading from the IPC socket while also abstracting dependencies
    /// and annoying implementation details like new line handling.
    ///
    /// # Returns
    ///
    /// String containing the received command.
    pub async fn read_command(&mut self) -> Result<String> {
        let mut command_buffer = String::new();
        let mut reader = BufReader::new(&mut self.stream);
        if reader.read_line(&mut command_buffer).await? == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Client closed the connection without sending a command",
            ));
        }
        if command_buffer.ends_with('\n') {
            command_buffer.pop();
        }

        Ok(command_buffer)
    }

    /// Function for writing a reply back to the IPC socket after processing the received command.
    /// The response is newline-terminated so the client can detect the end of the message
    /// via `read_line` without relying on the connection being closed. This mirrors the
    /// request framing and assumes the response contains no newlines.
    ///
    /// # Arguments
    ///
    /// * `response` - The response produced by handling a command.
    pub async fn respond(&mut self, mut response: String) -> Result<()> {
        debug_assert!(
            !response.contains('\n'),
            "IPC response must not contain a newline; it would corrupt message framing"
        );
        response.push('\n');
        self.stream.write_all(response.as_bytes()).await?;

        Ok(())
    }
}
