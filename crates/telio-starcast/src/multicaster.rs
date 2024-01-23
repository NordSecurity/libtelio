use std::net::IpAddr;
use std::{net::SocketAddr, sync::Arc};
use telio_sockets::SocketPool;
use telio_task::io::{wait_for_tx, Chan};
use telio_task::{io::mc_chan::Tx, task_exec, BoxAction, Runtime, Task};
use telio_utils::{telio_log_debug, telio_log_error};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::{RwLock, RwLockMappedWriteGuard, RwLockWriteGuard, Semaphore};
use tokio::task::JoinHandle;

const MULTICAST_TRANSPORT_PORT: u16 = 13569;
const MAX_PACKET: usize = 2048;

/// Multicaster task that resends locally generated
/// multicast traffic to other peers
pub struct Multicaster {
    meshnet_peer_ips: Vec<IpAddr>,
    transport_socket: Arc<UdpSocket>,
    chan: Arc<RwLock<Chan<Vec<u8>>>>,
    tun_to_transport_task: Option<JoinHandle<()>>,
    transport_to_local_task: Option<JoinHandle<()>>,
}

impl Multicaster {
    pub async fn new(
        peers: &Vec<IpAddr>,
        socket_pool: Arc<SocketPool>,
        chan: Chan<Vec<u8>>,
    ) -> Result<Self, String> {
        let socket = socket_pool
            .new_internal_udp(
                SocketAddr::from(([0, 0, 0, 0], MULTICAST_TRANSPORT_PORT)),
                None,
            )
            .await
            .map_err(|e| {
                telio_log_error!("Failed to bind multicast socket: {:?}", e);
                format!("Failed to bind multicast socket: {:?}", e)
            })?;
        Ok(Self {
            meshnet_peer_ips: peers.to_owned(),
            transport_socket: Arc::new(socket),
            chan: Arc::new(RwLock::new(chan)),
            tun_to_transport_task: None,
            transport_to_local_task: None,
        })
    }

    pub async fn start_multicaster(&mut self) {
        self.tun_to_transport_task = Some(tokio::spawn(Multicaster::tun_to_transport(
            self.chan.clone(),
            self.meshnet_peer_ips.clone(),
            self.transport_socket.clone(),
        )));
        self.transport_to_local_task = Some(tokio::spawn(Self::transport_to_local(
            self.transport_socket.clone(),
        )));
    }

    pub async fn stop(&mut self) {
        if let Some(handle) = &self.transport_to_local_task {
            handle.abort();
        }
        if let Some(handle) = &self.tun_to_transport_task {
            handle.abort();
        }
    }

    pub async fn tun_to_transport(
        read_chan: Arc<RwLock<Chan<Vec<u8>>>>,
        peers: Vec<IpAddr>,
        transport_sock: Arc<UdpSocket>,
    ) {
        loop {
            let packet = match read_chan.write().await.rx.recv().await {
                Some(packet) => packet,
                None => {
                    telio_log_error!("failed to receive multicast packet from tun channel");
                    return;
                }
            };

            for addr in &peers {
                let res = transport_sock
                    .send_to(
                        &packet,
                        SocketAddr::new(addr.clone(), MULTICAST_TRANSPORT_PORT),
                    )
                    .await;
                if let Err(e) = res {
                    telio_log_error!(
                        "Failed to forward multicast packet to {:?}, error: {}",
                        addr,
                        e
                    );
                }
            }
        }
    }

    pub async fn transport_to_local(transport_sock: Arc<UdpSocket>) {
        let mut receiving_buffer = vec![0u8; MAX_PACKET];
        loop {
            let res = transport_sock.recv(&mut receiving_buffer).await;
            if let Err(e) = res {
                telio_log_error!("failed to receive on multicast transport socket: {e}");
            }
            // rewrite sending out packets
        }
    }
}
