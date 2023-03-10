use std::{io::Error, time::Duration};

use telio_utils::{telio_log_trace, telio_log_warn};

use socket2::Socket;

#[cfg(windows)]
use {std::os::windows::io::AsRawSocket, windows::Win32::Networking::WinSock};

#[cfg(not(windows))]
use std::os::unix::io::AsRawFd;

#[cfg(any(target_os = "macos", target_os = "ios", doc))]
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
    #[cfg(not(windows))]
    pub fn apply(&self, socket: &Socket) {
        let sock = socket.as_raw_fd();
        let val_len: libc::socklen_t = 4;
        let mut kp_enabled: bool = false;
        let addr = socket.local_addr();

        // Setting TCP nodelay
        if let Some(nodelay_enable) = self.nodelay_enable {
            let enable = nodelay_enable as u32;

            if unsafe {
                libc::setsockopt(
                    sock,
                    libc::IPPROTO_TCP as libc::c_int,
                    libc::TCP_NODELAY as libc::c_int,
                    &enable as *const u32 as *const libc::c_void,
                    val_len,
                )
            } != 0
            {
                telio_log_warn!(
                    "Cannot set TCP_NODELAY={} for {:?} socket: {}",
                    nodelay_enable,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        // Setting TCP timeout (darwin)
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let Some(user_timeout) = self.user_timeout {
            let user_timeout = user_timeout.as_secs() as u32;

            if unsafe {
                libc::setsockopt(
                    sock,
                    libc::IPPROTO_TCP as libc::c_int,
                    TCP_RXT_CONNDROPTIME as libc::c_int,
                    &user_timeout as *const u32 as *const libc::c_void,
                    val_len,
                )
            } != 0
            {
                telio_log_warn!(
                    "Cannot set TCP_RXT_CONNDROPTIME={} for {:?} socket: {}",
                    user_timeout,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        // Setting TCP timeout (linux, android)
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        if let Some(user_timeout) = self.user_timeout {
            let user_timeout = user_timeout.as_millis() as u32;

            if unsafe {
                libc::setsockopt(
                    sock,
                    libc::IPPROTO_TCP as libc::c_int,
                    libc::TCP_USER_TIMEOUT as libc::c_int,
                    &user_timeout as *const u32 as *const libc::c_void,
                    val_len,
                )
            } != 0
            {
                telio_log_warn!(
                    "Cannot set TCP_USER_TIMEOUT={} for {:?} socket: {}",
                    user_timeout,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        // Enabling/disabling TCP keepalive
        if let Some(keepalive_enable) = self.keepalive_enable {
            kp_enabled = keepalive_enable;
            let enable = keepalive_enable as u32;

            if unsafe {
                libc::setsockopt(
                    sock,
                    libc::SOL_SOCKET as libc::c_int,
                    libc::SO_KEEPALIVE as libc::c_int,
                    &enable as *const u32 as *const libc::c_void,
                    val_len,
                )
            } != 0
            {
                telio_log_warn!(
                    "Cannot set SO_KEEPALIVE={} for {:?} socket: {}",
                    keepalive_enable,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        if kp_enabled {
            // Setting TCP keepalive idle time
            if let Some(keepalive_idle) = self.keepalive_idle {
                let idle = keepalive_idle.as_secs() as u32;

                #[cfg(not(any(target_os = "macos", target_os = "ios")))]
                let idle_nam = libc::TCP_KEEPIDLE as libc::c_int;
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                let idle_nam = libc::TCP_KEEPALIVE as libc::c_int;

                if unsafe {
                    libc::setsockopt(
                        sock,
                        libc::IPPROTO_TCP as libc::c_int,
                        idle_nam,
                        &idle as *const u32 as *const libc::c_void,
                        val_len,
                    )
                } != 0
                {
                    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
                    telio_log_warn!(
                        "Cannot set TCP_KEEPIDLE={} for {:?} socket: {}",
                        idle,
                        addr,
                        Error::last_os_error().to_string(),
                    );

                    #[cfg(any(target_os = "macos", target_os = "ios"))]
                    telio_log_warn!(
                        "Cannot set TCP_KEEPALIVE={} for {:?} socket: {}",
                        idle,
                        addr,
                        Error::last_os_error().to_string(),
                    );
                }
            }

            // Setting TCP keepalive interval time
            if let Some(keepalive_intvl) = self.keepalive_intvl {
                let intvl = keepalive_intvl.as_secs() as u32;

                if unsafe {
                    libc::setsockopt(
                        sock,
                        libc::IPPROTO_TCP as libc::c_int,
                        libc::TCP_KEEPINTVL as libc::c_int,
                        &intvl as *const u32 as *const libc::c_void,
                        val_len,
                    )
                } != 0
                {
                    telio_log_warn!(
                        "Cannot set TCP_KEEPINTVL={} for {:?} socket: {}",
                        intvl,
                        addr,
                        Error::last_os_error().to_string()
                    );
                }
            }

            // Setting TCP keepalive probe count
            if let Some(keepalive_cnt) = self.keepalive_cnt {
                let cnt = keepalive_cnt;

                if unsafe {
                    libc::setsockopt(
                        sock,
                        libc::IPPROTO_TCP as libc::c_int,
                        libc::TCP_KEEPCNT as libc::c_int,
                        &cnt as *const u32 as *const libc::c_void,
                        val_len,
                    )
                } != 0
                {
                    telio_log_warn!(
                        "Cannot set TCP_KEEPCNT={} for {:?} socket: {}",
                        cnt,
                        addr,
                        Error::last_os_error().to_string()
                    );
                }
            }
        }

        self.buf_size.apply(socket);
    }

    #[cfg(windows)]
    pub fn apply(&self, socket: &Socket) {
        let sock = WinSock::SOCKET(socket.as_raw_socket() as usize);
        let val_len: libc::c_int = 4;
        let mut kp_enabled: bool = false;
        let addr = socket.local_addr();

        // Setting TCP nodelay
        if let Some(nodelay_enable) = self.nodelay_enable {
            if unsafe {
                WinSock::setsockopt(
                    sock,
                    WinSock::IPPROTO_TCP.0 as i32,
                    WinSock::TCP_NODELAY as i32,
                    String::from_utf8_unchecked((nodelay_enable as u32).to_ne_bytes().to_vec()),
                    val_len,
                )
            } != 0
            {
                telio_log_warn!(
                    "Cannot set TCP_NODELAY={} for {:?} socket: {}",
                    nodelay_enable,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        // Setting TCP timeout
        if let Some(user_timeout) = self.user_timeout {
            if unsafe {
                WinSock::setsockopt(
                    sock,
                    WinSock::IPPROTO_TCP.0 as i32,
                    WinSock::TCP_MAXRT as i32,
                    String::from_utf8_unchecked(
                        (user_timeout.as_secs() as u32).to_ne_bytes().to_vec(),
                    ),
                    val_len,
                )
            } != 0
            {
                telio_log_warn!(
                    "Cannot set TCP_MAXRT={} for {:?} socket: {}",
                    user_timeout.as_secs(),
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        // Enabling/disabling TCP keepalive
        if let Some(keepalive_enable) = self.keepalive_enable {
            kp_enabled = keepalive_enable;
            if unsafe {
                WinSock::setsockopt(
                    sock,
                    WinSock::SOL_SOCKET as i32,
                    WinSock::SO_KEEPALIVE as i32,
                    String::from_utf8_unchecked((keepalive_enable as u32).to_ne_bytes().to_vec()),
                    val_len,
                )
            } != 0
            {
                telio_log_warn!(
                    "Cannot set SO_KEEPALIVE={} for {:?} socket: {}",
                    keepalive_enable,
                    addr,
                    Error::last_os_error().to_string(),
                );
            }
        }

        if kp_enabled {
            if let Some(keepalive_idle) = self.keepalive_idle {
                // Setting TCP keepalive idle time
                if unsafe {
                    WinSock::setsockopt(
                        sock,
                        WinSock::IPPROTO_TCP.0 as i32,
                        WinSock::TCP_KEEPIDLE as i32,
                        String::from_utf8_unchecked(
                            (keepalive_idle.as_secs() as u32).to_ne_bytes().to_vec(),
                        ),
                        val_len,
                    )
                } != 0
                {
                    telio_log_warn!(
                        "Cannot set TCP_KEEPIDLE={} for {:?} socket: {}",
                        keepalive_idle.as_secs(),
                        addr,
                        Error::last_os_error().to_string(),
                    );
                }
            }

            // Setting TCP keepalive interval time
            if let Some(keepalive_intvl) = self.keepalive_intvl {
                if unsafe {
                    WinSock::setsockopt(
                        sock,
                        WinSock::IPPROTO_TCP.0 as i32,
                        WinSock::TCP_KEEPINTVL as i32,
                        String::from_utf8_unchecked(
                            (keepalive_intvl.as_secs() as u32).to_ne_bytes().to_vec(),
                        ),
                        val_len,
                    )
                } != 0
                {
                    telio_log_warn!(
                        "Cannot set TCP_KEEPINTVL={} for {:?} socket: {}",
                        keepalive_intvl.as_secs(),
                        addr,
                        Error::last_os_error().to_string(),
                    );
                }
            }

            // Setting TCP keepalive probe count
            if let Some(keepalive_cnt) = self.keepalive_cnt {
                if unsafe {
                    WinSock::setsockopt(
                        sock,
                        WinSock::IPPROTO_TCP.0 as i32,
                        WinSock::TCP_KEEPCNT as i32,
                        String::from_utf8_unchecked((keepalive_cnt as u32).to_ne_bytes().to_vec()),
                        val_len,
                    )
                } != 0
                {
                    telio_log_warn!(
                        "Cannot set TCP_KEEPCNT={} for {:?} socket: {}",
                        keepalive_cnt,
                        addr,
                        Error::last_os_error().to_string(),
                    );
                }
            }
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
            let _ = socket
                .set_recv_buffer_size(rx_buf_size as usize)
                .map_err(|_| {
                    telio_log_warn!(
                        "Cannot set Rx buf size {} for {:?} socket",
                        rx_buf_size,
                        socket.local_addr()
                    );
                });
        }

        if let Some(tx_buf_size) = self.tx_buf_size {
            let _ = socket
                .set_send_buffer_size(tx_buf_size as usize)
                .map_err(|_| {
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
