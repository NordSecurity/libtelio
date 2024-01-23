use crate::{multicaster::Multicaster, receiver::Receiver};

use boringtun::noise::Tunn;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use telio_crypto::{PublicKey, SecretKey};
use telio_sockets::SocketPool;
use telio_task::io::Chan;
use telio_utils::telio_log_error;
use telio_wg::DynamicWg;
use telio_wg::{uapi::Peer, WireGuard};
use tokio::{net::UdpSocket, sync::RwLock};
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret};

pub struct MulticasterPeer {
    multicaster: RwLock<Multicaster>,
    receiver: RwLock<Receiver>,
}

#[derive(Clone)]
pub struct MulticasterIp {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

impl MulticasterPeer {
    pub async fn new(
        public_key: &PublicKey,
        wg: Arc<DynamicWg>,
        socket_pool: Arc<SocketPool>,
    ) -> Result<Self, String> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| {
                telio_log_error!("Failed to bind multicast socket: {:?}", e);
                format!("Failed to bind multicast socket: {:?}", e)
            })?;

        let (transport_chan, vpeer_chan) = Chan::pipe();

        let multicast_secret_key = SecretKey::gen();

        let telio_public_key: PublicKeyDalek = PublicKeyDalek::from(public_key.0);

        let peer: Arc<Tunn> = Arc::<Tunn>::from(Tunn::new(
            StaticSecret::from(multicast_secret_key.into_bytes()),
            telio_public_key,
            None,
            None,
            0,
            None,
        )?);

        let arc_skt = Arc::new(socket);

        let multicaster_ip = Arc::new(MulticasterIp {
            ipv4: Ipv4Addr::new(100, 64, 0, 5),
            // IPv6 address is a test address
            ipv6: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
        });

        let wg_port = wg
            .wait_for_listen_port(Duration::from_secs(1))
            .await
            .map_err(|e| {
                telio_log_error!("BoringTun adapter error: {:?}", e);
                format!("BoringTun adapter error: {:?}", e)
            })?;
        let wg_sock = Arc::new(SocketAddr::from(([127, 0, 0, 1], wg_port)));

        Ok(MulticasterPeer {
            multicaster: RwLock::new(
                Multicaster::new(
                    arc_skt.clone(),
                    wg,
                    wg_sock.clone(),
                    socket_pool.clone(),
                    transport_chan,
                    peer.clone(),
                    multicaster_ip.clone(),
                )
                .await?,
            ),
            receiver: RwLock::new(
                Receiver::new(
                    arc_skt.clone(),
                    wg_sock.clone(),
                    vpeer_chan,
                    multicast_secret_key,
                    peer.clone(),
                    multicaster_ip.clone(),
                )
                .await?,
            ),
        })
    }

    pub async fn start(&self) {
        self.multicaster.write().await.start_multicaster().await;
        self.receiver.write().await.start_receiver().await;
    }

    pub async fn stop(&self) {
        self.multicaster.write().await.stop().await;
        self.receiver.write().await.stop().await;
    }

    pub async fn get_peer(&self) -> Result<Peer, ipnetwork::IpNetworkError> {
        self.receiver.read().await.get_peer()
    }
}

#[cfg(test)]
mod test {
    use telio_task::io::Chan;
    #[tokio::test(flavor = "multi_thread")]
    async fn test_pipes() {
        let (transport_chan, vpeer_chan) = Chan::pipe();
        let mut rx = transport_chan.rx;
        let tx = vpeer_chan.tx;
        tokio::spawn(async move {
            loop {
                let byte: u32 = rx.recv().await.unwrap_or_default();
                println!("byte: {byte}");
            }
        });

        println!("hello");
        let _ = tx.send(20).await;
        println!("hello 2");
        let _ = tx.send(30).await;
        println!("hello 3");
    }
}
