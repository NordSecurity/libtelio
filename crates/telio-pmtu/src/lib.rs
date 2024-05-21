#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "linux.rs"]
mod platform;

use std::{net::IpAddr, ops::Range, sync::Arc, time::Duration};

use tokio::task::JoinHandle;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use platform::PMTUSocket;

// We assume that 1000 is always supported.
//1500 is the Ethernet MTU so we're not expecting PMTU to be higher than that.
#[allow(unused)]
const PMTU_RANGE: Range<u32> = 1000..1501;

#[allow(unused)]
const INTERVAL: Duration = Duration::from_secs(60 * 60); // 1h

pub struct Entity {
    #[allow(unused)]
    socket_pool: Arc<telio_sockets::SocketPool>,
    task: Option<JoinHandle<()>>,
    #[allow(unused)]
    response_timeout: Duration,
}

impl Entity {
    pub fn new(socket_pool: Arc<telio_sockets::SocketPool>, response_timeout: Duration) -> Self {
        Self {
            socket_pool,
            task: None,
            response_timeout,
        }
    }

    pub async fn run(&mut self, host: IpAddr) {
        self.stop().await;
        self.start(host);
    }

    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            telio_utils::telio_log_debug!("Stopping PMTU discovery task");
            task.abort();
            let _ = task.await;
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn start(&mut self, host: IpAddr) {
        telio_utils::telio_log_debug!("Starting PMTU discovery task");

        use std::os::fd::AsRawFd;

        use telio_lana::*;

        async fn probe(
            socket_pool: &telio_sockets::SocketPool,
            host: IpAddr,
            response_timeout: Duration,
        ) -> std::io::Result<u32> {
            let sock = PMTUSocket::new(host, response_timeout)?;
            telio_utils::telio_log_debug!("Making PMTU socket external");
            socket_pool.make_external(sock.as_raw_fd());
            sock.probe_pmtu().await
        }

        let pool = self.socket_pool.clone();
        let timeout = self.response_timeout;
        let task = tokio::spawn(async move {
            let mut timer = telio_utils::interval(INTERVAL);

            loop {
                timer.tick().await;

                match probe(&pool, host, timeout).await {
                    Ok(pmtu) => {
                        telio_utils::telio_log_info!("PMTU -> {host}: {pmtu}");

                        let _ = lana! {
                            send_developer_logging_log,
                            pmtu as i32,
                            telio_lana::moose::LibtelioappLogLevel::Info,
                            format!("PMTU, OS: {}, ARCH: {}", std::env::consts::OS, std::env::consts::ARCH)
                        };
                    }
                    Err(err) => telio_utils::telio_log_warn!("Failed to probe PMTU: {err:?}"),
                }
            }
        });

        self.task = Some(task);
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn start(&mut self, _: IpAddr) {}
}

impl Drop for Entity {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(unix)]
fn create_icmp_socket(host: &std::net::IpAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        os::fd::{FromRawFd, IntoRawFd},
    };

    let (domain, proto, bind_addr) = match host {
        IpAddr::V4(_) => (
            Domain::IPV4,
            Protocol::ICMPV4,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ),
        IpAddr::V6(_) => (
            Domain::IPV6,
            Protocol::ICMPV6,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ),
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(proto))?;

    let bind_addr = SocketAddr::from((bind_addr, 0));
    sock.bind(&bind_addr.into())?;

    let sock = unsafe { std::net::UdpSocket::from_raw_fd(sock.into_raw_fd()) };
    sock.set_nonblocking(true)?;

    tokio::net::UdpSocket::from_std(sock)
}

#[allow(unused)]
fn echo_req_ident() -> u16 {
    rand::random()
}
