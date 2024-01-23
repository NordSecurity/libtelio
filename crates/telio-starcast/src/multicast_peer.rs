use crate::{multicaster::Multicaster, receiver::Receiver};

use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{net::SocketAddr, sync::Arc};
use telio_crypto::{PublicKey, SecretKey};
use telio_sockets::native::AsNativeSocket;
use telio_sockets::SocketPool;
use telio_task::io::Chan;
use telio_wg::uapi::Peer;
use tokio::sync::RwLock;

pub struct MulticasterPeer {
    multicaster: RwLock<Multicaster>,
    receiver: RwLock<Receiver>,
}

impl MulticasterPeer {
    pub async fn new(
        telio_wg_port: u16,
        public_key: &PublicKey,
        meshnet_peer_ips: &Vec<IpAddr>,
        socket_pool: Arc<SocketPool>,
    ) -> Result<Self, String> {
        let (transport_chan, vpeer_chan) = Chan::pipe();

        Ok(MulticasterPeer {
            multicaster: RwLock::new(
                Multicaster::new(meshnet_peer_ips, socket_pool.clone(), transport_chan).await?,
            ),
            receiver: RwLock::new(Receiver::new(telio_wg_port, public_key, vpeer_chan).await?),
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

    pub async fn get_peer(&self) -> Peer {
        self.receiver.read().await.get_peer()
    }
}

#[cfg(test)]
mod test {
    use telio_task::io::Chan;
    #[tokio::test(flavor = "multi_thread")]
    async fn test_pipes() {
        let (mut transport_chan, mut vpeer_chan) = Chan::pipe();
        let mut rx = transport_chan.rx;
        let mut tx = vpeer_chan.tx;
        let handle = tokio::spawn(async move {
            loop {
                let byte: u32 = rx.recv().await.unwrap_or_default();
                print!("byte: {byte}\n");
            }
        });

        println!("hello");
        let _ = tx.send(20).await;
        println!("hello 2");
        let _ = tx.send(30).await;
        println!("hello 3");
    }
}
