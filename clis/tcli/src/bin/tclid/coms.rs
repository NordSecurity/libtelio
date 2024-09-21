//! Code for handling inter process communication and abstracting away it's dependencies.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

use anyhow::Result;
use interprocess::local_socket::{LocalSocketListener, LocalSocketStream};

/// Struct for handling connections of the TCLID daemon's side of the IPC communication with the API.
pub struct DaemonSocket {
    /// The inner socket over which the actual communication is happening.
    socket: LocalSocketListener,
}

impl DaemonSocket {
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
        let socket = LocalSocketListener::bind(ipc_socket_path)?;

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
    pub fn accept(&self) -> Result<DaemonConnection> {
        let stream = self.socket.accept()?;

        Ok(DaemonConnection { stream })
    }

    /// Function for sending commands to the server.
    /// Also retrieves the response from the IPC server, but blocks while waiting for it.
    /// Note that endlines are used to indicate the end of a message so the server knows when to stop reading and
    /// send a response, otherwise the server would wait until the API closes the socket and won't be able to send a response.
    /// This is also sort of a deadlock risk, so should be handled with care.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address (more specifically path, but left address for clarity) of the IPC socket.
    /// * `cmd` - Command to be sent to the daemon.
    ///
    /// # Returns
    ///
    /// A Result containing a response string.
    pub fn send_command(addr: &Path, cmd: &str) -> Result<String> {
        let mut response_buffer = String::new();
        let mut stream = LocalSocketStream::connect(addr)?;
        writeln!(stream, "{}", cmd)?;
        stream.read_to_string(&mut response_buffer)?;

        Ok(response_buffer)
    }

    /// Function Implementing custom retry logic for send_command, because the public retry crates I found seemed to
    /// either have way too much overhead or be very sketchy in terms of quality.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address (more specifically path, but left address for clarity) of the IPC socket (same as `send_command`).
    /// * `cmd` - Command to be sent to the daemon (same as `send_command`).
    /// * `retry_delay_list` - a list of retry delays. The length of the list is the retry count.
    ///
    /// # Returns
    ///
    /// A Result containing a response string (same as `send_command`).
    pub fn send_command_with_retries(
        addr: &Path,
        cmd: &str,
        retry_delay_list: &[tokio::time::Duration],
    ) -> Result<String> {
        let mut retry_delay_list = retry_delay_list.iter().rev();

        loop {
            match Self::send_command(addr, cmd) {
                Ok(response) => break Ok(response),
                Err(e) => match retry_delay_list.next() {
                    Some(retry_delay) => std::thread::sleep(*retry_delay),
                    None => break Err(e),
                },
            }
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
    pub fn read_command(&mut self) -> Result<String> {
        let mut command_buffer = String::new();
        let mut reader = BufReader::new(std::io::Read::by_ref(&mut self.stream));
        reader.read_line(&mut command_buffer)?;
        // Removing the trailing newline used as a message ending according to platform.
        #[cfg(unix)]
        command_buffer.pop();
        #[cfg(not(unix))]
        todo!("Windows support is not implemented yet");

        Ok(command_buffer)
    }

    /// Function for writing a reply back to the IPC socket after processing the received command.
    ///
    /// # Arguments
    ///
    /// * `response` - The response produced by handling a command.
    pub fn respond(&mut self, response: String) -> Result<()> {
        self.stream.write_all(response.as_bytes())?;

        Ok(())
    }
}
