use std::{io::Error, time::Duration};

use telio_utils::{telio_log_trace, telio_log_warn};

use socket2::Socket;

#[cfg(windows)]
use {std::os::windows::io::AsRawSocket, windows::Win32::Networking::WinSock};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos", doc))]
/// time after which tcp retransmissions will be stopped and the connection will be dropped
const TCP_RXT_CONNDROPTIME: libc::c_int = 0x80;

#[derive(Default)]
pub struct TcpParams {
    pub keepalive_enable: Option<bool>,
    pub keepalive_idle: Option<Duration>,
    pub keepalive_intvl: Option<Duration>,
    pub keepalive_cnt: Option<u32>,
    pub nodelay_enable: Option<bool>,
    pub user_timeout: Option<Duration>,
    pub buf_size: SocketBufSizes,
}

#[derive(Default)]
pub struct SocketBufSizes {
    pub tx_buf_size: Option<usize>,
    pub rx_buf_size: Option<usize>,
}

pub struct UdpParams(pub SocketBufSizes);

impl TcpParams {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn set_tcp_timeout(&self, socket: &Socket) -> Result<(), Error> {
        socket.set_tcp_user_timeout(self.user_timeout)
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    fn set_tcp_timeout(&self, socket: &Socket) -> Result<(), Error> {
        use nix::{setsockopt_impl, sockopt_impl, sys::socket::setsockopt};

        sockopt_impl!(
            ConnDropTime,
            SetOnly,
            libc::IPPROTO_TCP,
            TCP_RXT_CONNDROPTIME,
            u32
        );

        // Setting TCP timeout (darwin)
        if let Some(user_timeout) = self.user_timeout {
            let user_timeout = user_timeout.as_secs() as u32;
            setsockopt(socket, ConnDropTime, &user_timeout)?;
        }

        Ok(())
    }

    #[cfg(windows)]
    fn set_tcp_timeout(&self, socket: &Socket) -> Result<(), Error> {
        if let Some(user_timeout) = self.user_timeout {
            let err = unsafe {
                WinSock::setsockopt(
                    WinSock::SOCKET(socket.as_raw_socket() as usize),
                    WinSock::IPPROTO_TCP.0,
                    WinSock::TCP_MAXRT,
                    Some((user_timeout.as_secs() as u32).to_ne_bytes().as_ref()),
                )
            };
            if err != 0 {
                return Err(Error::from_raw_os_error(err));
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    // Unfortunately socket2 does not support this option on Windows
    fn set_tcp_keepalive_cnt(&self, socket: &Socket) -> Result<(), Error> {
        if let Some(keepalive_cnt) = self.keepalive_cnt {
            let err = unsafe {
                WinSock::setsockopt(
                    WinSock::SOCKET(socket.as_raw_socket() as usize),
                    WinSock::IPPROTO_TCP.0,
                    WinSock::TCP_MAXRT,
                    Some((keepalive_cnt).to_ne_bytes().as_ref()),
                )
            };
            if err != 0 {
                return Err(Error::from_raw_os_error(err));
            }
        }

        Ok(())
    }

    pub fn apply(&self, socket: &Socket) {
        use socket2::TcpKeepalive;

        let addr = socket.local_addr();

        // Setting linger=0 so tcp sockets would close immediately
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        {
            if let Err(err) = socket.set_linger(Some(Duration::from_secs(0))) {
                telio_log_warn!("Failed to set so_linger on tcp socket: {}", err);
            }
        }

        // Setting TCP nodelay
        if let Some(nodelay_enable) = self.nodelay_enable {
            if socket.set_tcp_nodelay(nodelay_enable).is_err() {
                telio_log_warn!(
                    "Cannot set TCP_NODELAY={} for {:?} socket: {}",
                    nodelay_enable,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        // Setting TCP timeout
        if self.set_tcp_timeout(socket).is_err() {
            telio_log_warn!(
                "Cannot set TCP user timeout: {:?} for {:?} socket: {}",
                self.user_timeout,
                socket.local_addr(),
                Error::last_os_error().to_string(),
            );
        }

        // Setting TCP keepalive options
        if let Some(true) = self.keepalive_enable {
            let mut keepalive = TcpKeepalive::new();
            if let Some(idle) = self.keepalive_idle {
                keepalive = keepalive.with_time(idle);
            }
            if let Some(interval) = self.keepalive_intvl {
                keepalive = keepalive.with_interval(interval);
            }
            #[cfg(not(windows))]
            if let Some(count) = self.keepalive_cnt {
                keepalive = keepalive.with_retries(count);
            }
            if socket.set_tcp_keepalive(&keepalive).is_err() {
                telio_log_warn!(
                    "Cannot set TCP keepalive options {:?} for {:?} socket: {}",
                    keepalive,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }

            #[cfg(windows)]
            let _ = self.set_tcp_keepalive_cnt(socket);
        } else if socket.set_keepalive(false).is_err() {
            telio_log_warn!(
                "Cannot disable TCP keepalive for {:?} socket: {}",
                addr,
                Error::last_os_error().to_string(),
            );
        }

        self.buf_size.apply(socket);
    }
}

impl SocketBufSizes {
    pub fn apply(&self, socket: &Socket) {
        telio_log_trace!(
            "recv_buffer_size() = {:?} for {:?} socket",
            socket.recv_buffer_size(),
            socket.local_addr()
        );
        telio_log_trace!(
            "send_buffer_size() = {:?} for {:?} socket",
            socket.send_buffer_size(),
            socket.local_addr()
        );

        if let Some(rx_buf_size) = self.rx_buf_size {
            let _ = socket.set_recv_buffer_size(rx_buf_size).map_err(|_| {
                telio_log_warn!(
                    "Cannot set Rx buf size {} for {:?} socket",
                    rx_buf_size,
                    socket.local_addr()
                );
            });
        }

        if let Some(tx_buf_size) = self.tx_buf_size {
            let _ = socket.set_send_buffer_size(tx_buf_size).map_err(|_| {
                telio_log_warn!(
                    "Cannot set Tx buf size {} for {:?} socket",
                    tx_buf_size,
                    socket.local_addr()
                );
            });
        }
    }
}

impl UdpParams {
    pub fn apply(&self, socket: &Socket) {
        self.0.apply(socket);
    }
}
