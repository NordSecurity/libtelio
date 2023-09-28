use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use socket2::{Domain, Protocol, Socket, Type};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream, ToSocketAddrs, UdpSocket},
};

#[cfg(unix)]
use boringtun::device::MakeExternalBoringtun;
use telio_utils::{telio_log_debug, telio_log_warn};

use crate::{
    native::{AsNativeSocket, NativeSocket},
    Protector, TcpParams, UdpParams,
};

struct SocketGuard {
    socket: NativeSocket,
    protector: ArcProtector,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.protector.clean(self.socket)
    }
}

pub struct External<T: AsNativeSocket> {
    socket: T,
    guard: SocketGuard,
}

#[derive(Clone)]
pub struct SocketPool {
    protect: ArcProtector,
}

type ArcProtector = Arc<dyn Protector>;

impl External<TcpSocket> {
    pub async fn connect(self, addr: SocketAddr) -> io::Result<External<TcpStream>> {
        let Self { guard, socket } = self;
        let socket = socket.connect(addr).await?;
        Ok(External { socket, guard })
    }
}

impl<T: AsNativeSocket> Deref for External<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<T: AsNativeSocket> DerefMut for External<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl<T> AsyncRead for External<T>
where
    T: AsNativeSocket + AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for External<T>
where
    T: AsNativeSocket + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

impl SocketPool {
    pub fn new<T: Protector + 'static>(protect: T) -> Self {
        Self {
            protect: Arc::new(protect),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn set_fwmark(&self, fwmark: u32) {
        self.protect.set_fwmark(fwmark);
    }

    #[cfg(any(target_os = "macos", target_os = "ios", windows))]
    pub fn set_tunnel_interface(&self, interface: u64) {
        self.protect.set_tunnel_interface(interface);
    }

    pub fn new_external_tcp_v4(
        &self,
        params: Option<TcpParams>,
    ) -> io::Result<External<TcpSocket>> {
        let ty = Type::STREAM;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        let ty = ty.nonblocking();

        let socket2_socket = Socket::new(Domain::IPV4, ty, Some(Protocol::TCP))?;

        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        socket2_socket.set_nonblocking(true)?;

        if let Some(params) = params {
            params.apply(&socket2_socket);
        }

        telio_log_debug!(
            "Creating external tcp_v4 socket: {}",
            socket2_socket.as_native_socket()
        );

        self.new_external(TcpSocket::from_std_stream(socket2_socket.into()))
    }

    pub async fn new_udp<A: ToSocketAddrs>(
        addr: A,
        params: Option<UdpParams>,
    ) -> io::Result<UdpSocket> {
        let s = UdpSocket::bind(addr).await?;
        let s = Socket::from(s.into_std()?);

        if let Some(params) = params {
            params.apply(&s);
        }

        UdpSocket::from_std(s.into())
    }

    pub async fn new_internal_udp<A: ToSocketAddrs>(
        &self,
        addr: A,
        params: Option<UdpParams>,
    ) -> io::Result<UdpSocket> {
        let sock = Self::new_udp(addr, params).await?;

        telio_log_debug!("Creating internal udp socket: {}", sock.as_native_socket());

        if let Err(err) = self.make_internal(sock.as_native_socket()) {
            telio_log_warn!("Failed to make udp socket internal: {}", err)
        }

        Ok(sock)
    }

    pub async fn new_external_udp<A: ToSocketAddrs>(
        &self,
        addr: A,
        params: Option<UdpParams>,
    ) -> io::Result<External<UdpSocket>> {
        let socket = Self::new_udp(addr, params).await?;

        telio_log_debug!(
            "Creating external udp socket: {}",
            socket.as_native_socket()
        );
        self.new_external(socket)
    }

    /// wraps protect() on android, fmark on linux and interface binding for others
    pub fn make_external<T: AsNativeSocket>(&self, socket: T) {
        let _ = self.protect.make_external(socket.as_native_socket());
    }

    /// binds socket to tunnel interface on mac and iOS
    pub fn make_internal(&self, _socket: NativeSocket) -> io::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        self.protect.make_internal(_socket)?;
        Ok(())
    }

    fn new_external<T: AsNativeSocket>(&self, socket: T) -> io::Result<External<T>> {
        self.protect.make_external(socket.as_native_socket())?;

        Ok(External {
            guard: SocketGuard {
                protector: self.protect.clone(),
                socket: socket.as_native_socket(),
            },
            socket,
        })
    }
}

#[cfg(unix)]
impl MakeExternalBoringtun for SocketPool {
    fn make_external(&self, socket: NativeSocket) {
        let _ = self.protect.make_external(socket);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4},
        sync::Mutex,
    };

    use mockall::mock;
    use rstest::rstest;

    use crate::{native::NativeSocket, Protect};

    use super::*;

    const PACKET: [u8; 8] = *b"libtelio";

    mock! {
        Protector {}
        impl Protector for Protector {
            fn make_external(&self, socket: NativeSocket) -> io::Result<()>;
            fn clean(&self, socket: NativeSocket);
            #[cfg(target_os = "linux")]
            fn set_fwmark(&self, fwmark: u32);
            #[cfg(any(target_os = "macos", windows))]
            fn set_tunnel_interface(&self, interface: u64);
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            fn make_internal(&self, interface: i32) -> Result<(), std::io::Error>;
        }
    }

    #[tokio::test]
    async fn test_external_drops_protector() {
        let mut protect = MockProtector::default();

        protect.expect_make_external().returning(|_| Ok(()));
        protect.expect_clean().return_const(());

        let pool = SocketPool::new(protect);

        let tcp = pool.new_external_tcp_v4(None).expect("tcp");
        let _ = tcp
            .connect(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                9999,
            )))
            .await;
    }

    #[tokio::test]
    async fn create_and_clean_sockets() {
        let mut protect = MockProtector::default();

        let socks = Arc::new(Mutex::new(Vec::new()));

        protect
            .expect_make_external()
            .returning({
                let socks = socks.clone();
                move |s| {
                    socks.lock().unwrap().push(s);
                    Ok(())
                }
            })
            .times(2);

        protect.expect_clean().return_const(()).times(2);

        let pool = SocketPool::new(protect);
        {
            let tcp = pool.new_external_tcp_v4(None).expect("tcp");
            let udp = pool
                .new_external_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), None)
                .await
                .expect("udp");

            assert_eq!(
                socks.lock().unwrap().clone(),
                vec![tcp.as_native_socket(), udp.as_native_socket()]
            );
        }
    }

    #[tokio::test]
    async fn create_socket_with_protect_fn() {
        let socks = Arc::new(Mutex::new(Vec::new()));
        let protect: Protect = {
            let socks = socks.clone();
            Arc::new(move |s| {
                socks.lock().unwrap().push(s);
            })
        };
        let pool = SocketPool::new(protect);
        let tcp = pool.new_external_tcp_v4(None).expect("tcp");

        assert_eq!(socks.lock().unwrap().clone(), vec![tcp.as_native_socket()]);
    }

    #[rstest]
    #[case(IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[cfg(not(windows))]
    #[case(IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    #[case(IpAddr::V6(Ipv6Addr::LOCALHOST))]
    #[cfg(not(any(windows, tarpaulin)))]
    #[case(IpAddr::V6(Ipv6Addr::UNSPECIFIED))]
    #[tokio::test]
    async fn internal_udp_socket_can_transfer_data(#[case] ip_addr: IpAddr) {
        let protect = MockProtector::default();
        let pool = SocketPool::new(protect);
        let addr = SocketAddr::new(ip_addr, 0);
        let socket = match pool.new_internal_udp(addr, None).await {
            Ok(socket) => socket,
            Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                // host has no interface with ipv4/ipv6
                return;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        };
        let local_addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let protect = MockProtector::default();
            let pool = SocketPool::new(protect);
            let addr = SocketAddr::new(ip_addr, 0);
            let socket = pool.new_internal_udp(addr, None).await.unwrap();
            socket.send_to(&PACKET, local_addr).await.unwrap();
        });
        let mut buf = [0; PACKET.len()];
        assert_eq!(PACKET.len(), socket.recv_from(&mut buf).await.unwrap().0);
        assert_eq!(PACKET, buf);
    }

    #[rstest]
    #[case(IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[cfg(not(windows))]
    #[case(IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    #[case(IpAddr::V6(Ipv6Addr::LOCALHOST))]
    #[cfg(not(any(windows, tarpaulin)))]
    #[case(IpAddr::V6(Ipv6Addr::UNSPECIFIED))]
    #[tokio::test]
    async fn external_udp_socket_can_transfer_data(#[case] ip_addr: IpAddr) {
        let mut protect = MockProtector::default();
        protect.expect_make_external().returning(|_| Ok(()));
        protect.expect_clean().return_const(());
        let pool = SocketPool::new(protect);
        let addr = SocketAddr::new(ip_addr, 0);
        let socket = match pool.new_internal_udp(addr, None).await {
            Ok(socket) => socket,
            Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {
                // host has no interface with ipv4/ipv6
                return;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        };
        let local_addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut protect = MockProtector::default();
            protect.expect_make_external().returning(|_| Ok(()));
            protect.expect_clean().return_const(());
            let pool = SocketPool::new(protect);
            let addr = SocketAddr::new(ip_addr, 0);
            let socket = pool.new_external_udp(addr, None).await.unwrap();
            socket.send_to(&PACKET, local_addr).await.unwrap();
        });
        let mut buf = [0; PACKET.len()];
        assert_eq!(PACKET.len(), socket.recv_from(&mut buf).await.unwrap().0);
        assert_eq!(PACKET, buf);
    }
}
