use std::net::UdpSocket;

pub trait SocketConfigurator {
    fn configure(&self, socket: &UdpSocket);
}
