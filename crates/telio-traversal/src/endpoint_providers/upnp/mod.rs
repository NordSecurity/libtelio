pub mod igd;

use crate::endpoint_providers::upnp::igd::{Igd, IgdCommands, PortMapping, ServiceCmdType};
use crate::endpoint_providers::{
    EndpointCandidate, EndpointCandidatesChangeEvent, EndpointProvider, EndpointProviderType,
    Error, PongEvent,
};
use crate::ping_pong_handler::PingPongHandler;
use async_trait::async_trait;
use futures::prelude::*;
use rand::Rng;
use rupnp::Error::HttpErrorCode;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use telio_crypto::PublicKey;
use telio_proto::{Session, WGPort};
use telio_sockets::External;
use telio_task::{io::chan::Tx, task_exec, BoxAction, Runtime, Task};
use telio_utils::{
    exponential_backoff::{Backoff, ExponentialBackoff, ExponentialBackoffBounds},
    telio_log_error, telio_log_info, PinnedSleep,
};
use telio_wg::{DynamicWg, WireGuard};
use tokio::{net::UdpSocket, sync::Mutex};

const MAX_SUPPORTED_PACKET_SIZE: usize = 1500;
const UPNP_INTERVAL: Duration = Duration::from_secs(60);

pub struct UpnpEndpointProvider<
    Wg: WireGuard = DynamicWg,
    I: IgdCommands = Igd,
    E: Backoff = ExponentialBackoff,
> {
    task: Task<State<Wg, I, E>>,
}

impl<Wg: WireGuard> UpnpEndpointProvider<Wg> {
    pub fn start(
        udp_socket: External<UdpSocket>,
        wg: Arc<Wg>,
        exponential_backoff_bounds: ExponentialBackoffBounds,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
    ) -> Result<Self, Error> {
        Ok(Self::start_with(
            udp_socket,
            wg,
            ExponentialBackoff::new(exponential_backoff_bounds)?,
            ping_pong_handler,
            Igd::default(),
        ))
    }
}

impl<Wg: WireGuard, I: IgdCommands, E: Backoff> UpnpEndpointProvider<Wg, I, E> {
    pub fn start_with(
        udp_socket: External<UdpSocket>,
        wg: Arc<Wg>,
        exponential_backoff: E,
        ping_pong_handler: Arc<Mutex<PingPongHandler>>,
        igd_dev: I,
    ) -> Self {
        let udp_socket = Arc::new(udp_socket);
        let rx_buff = vec![0u8; MAX_SUPPORTED_PACKET_SIZE];

        Self {
            task: Task::start(State {
                udp_socket,
                ip_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                wg,
                proxy_port_mapping: PortMapping::default(),
                wg_port_mapping: PortMapping::default(),
                endpoint_candidate: None,
                pong_events_tx: None,
                epc_event_tx: None,
                exponential_backoff,
                upnp_interval: PinnedSleep::new(UPNP_INTERVAL, ()),
                rx_buff,
                igd: igd_dev,
                ping_pong_handler,
            }),
        }
    }

    pub async fn get_endpoint_candidate(&self) -> Option<EndpointCandidate> {
        task_exec!(&self.task, async move |s| {
            let _ = s.check_endpoint_candidate().await;
            Ok(s.endpoint_candidate.clone())
        })
        .await
        .unwrap_or(None)
    }

    pub async fn get_internal_socket(&self) -> Option<SocketAddr> {
        task_exec!(&self.task, async move |s| {
            if s.endpoint_candidate.is_some() {
                Ok(Some(SocketAddr::new(
                    s.ip_addr,
                    s.proxy_port_mapping.internal,
                )))
            } else {
                Ok(None)
            }
        })
        .await
        .unwrap_or(None)
    }

    pub async fn stop(self) {
        let _ = task_exec!(&self.task, async move |s| {
            if s.endpoint_candidate.is_some() {
                let dummy_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
                // Ignore port deletion Errors
                let _ = s
                    .igd
                    .igd_service_command(
                        ServiceCmdType::DeleteRoute,
                        s.proxy_port_mapping,
                        dummy_ip,
                    )
                    .await;
                let _ = s
                    .igd
                    .igd_service_command(ServiceCmdType::DeleteRoute, s.wg_port_mapping, dummy_ip)
                    .await;
            };
            Ok(())
        })
        .await;
        let _ = self.task.stop().await.resume_unwind();
    }
}

#[async_trait]
impl<Wg: WireGuard> EndpointProvider for UpnpEndpointProvider<Wg> {
    fn name(&self) -> &'static str {
        "UPnP"
    }

    async fn subscribe_for_pong_events(&self, tx: Tx<PongEvent>) {
        task_exec!(&self.task, async move |s| {
            s.pong_events_tx = Some(tx);
            Ok(())
        })
        .await
        .unwrap_or_default()
    }

    async fn subscribe_for_endpoint_candidates_change_events(
        &self,
        tx: Tx<EndpointCandidatesChangeEvent>,
    ) {
        task_exec!(&self.task, async move |s| {
            s.epc_event_tx = Some(tx);
            Ok(())
        })
        .await
        .unwrap_or_default()
    }

    async fn trigger_endpoint_candidates_discovery(&self) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| {
            Ok(s.check_endpoint_candidate().await)
        })
        .await?
    }

    async fn handle_endpoint_gone_notification(&self) {
        task_exec!(&self.task, async move |s| {
            s.endpoint_candidate = None;
            Ok(())
        })
        .await
        .unwrap_or_default()
    }

    async fn send_ping(
        &self,
        addr: SocketAddr,
        session_id: Session,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| Ok(s
            .send_ping(addr, session_id, &public_key)
            .await))
        .await?
    }

    async fn get_current_endpoints(&self) -> Option<Vec<EndpointCandidate>> {
        task_exec!(&self.task, async move |s| {
            if let Some(candidate) = s.endpoint_candidate.clone() {
                return Ok(Some(vec![candidate]));
            }
            Ok(None)
        })
        .await
        .unwrap_or(None)
    }
}

struct State<Wg: WireGuard, I: IgdCommands, E: Backoff> {
    udp_socket: Arc<External<UdpSocket>>,
    ip_addr: IpAddr,
    wg: Arc<Wg>,
    proxy_port_mapping: PortMapping,
    wg_port_mapping: PortMapping,
    endpoint_candidate: Option<EndpointCandidate>,
    pong_events_tx: Option<Tx<PongEvent>>,
    epc_event_tx: Option<Tx<EndpointCandidatesChangeEvent>>,
    exponential_backoff: E,
    upnp_interval: PinnedSleep<()>,
    rx_buff: Vec<u8>,
    igd: I,
    ping_pong_handler: Arc<Mutex<PingPongHandler>>,
}

impl<Wg: WireGuard, I: IgdCommands, E: Backoff> State<Wg, I, E> {
    async fn send_ping(
        &self,
        addr: SocketAddr,
        session_id: Session,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        let wg_port = if let Some(port) = self.get_wg_port() {
            port
        } else {
            return Err(Error::NoWGListenPort);
        };
        self.ping_pong_handler
            .lock()
            .await
            .send_ping(addr, wg_port, &*self.udp_socket, session_id, public_key)
            .await
    }

    /// Get wg port identified by stun
    fn get_wg_port(&self) -> Option<WGPort> {
        if let Some(epc) = &self.endpoint_candidate {
            return Some(WGPort(epc.wg.port()));
        }
        None
    }

    async fn check_endpoint_candidate(&mut self) -> Result<(), Error> {
        tokio::time::timeout(Duration::from_secs(5), async move {
            if self.endpoint_candidate.is_none() {
                self.create_endpoint_candidate().await;
                return Ok(());
            };

            match self.is_current_endpoint_valid().await {
                Ok(_) => telio_log_info!("The current Upnp endpoint is valid."),
                Err(e) => {
                    if let Error::UpnpError(HttpErrorCode(
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                    )) = e
                    {
                        telio_log_info!("Failed to delete/check route: route does not exist")
                    } else {
                        telio_log_info!("Error current Upnp endpoint is invalid: {}", e);

                        telio_log_info!("Deleting a old Upnp endpoint");
                        // Ignore Error on port deletion
                        let _ = self.igd.igd_service_command(
                            ServiceCmdType::DeleteRoute,
                            self.wg_port_mapping,
                            self.ip_addr,
                        );
                        let _ = self.igd.igd_service_command(
                            ServiceCmdType::DeleteRoute,
                            self.proxy_port_mapping,
                            self.ip_addr,
                        );
                    }

                    telio_log_info!("Creating a new Upnp endpoint");
                    self.create_endpoint_candidate().await;
                }
            };
            Ok(())
        })
        .await
        .unwrap_or(Ok(()))
    }

    async fn is_current_endpoint_valid(&mut self) -> Result<(), Error> {
        self.igd
            .igd_service_command(
                ServiceCmdType::CheckRoute,
                self.proxy_port_mapping,
                self.ip_addr,
            )
            .await?;
        self.igd
            .igd_service_command(
                ServiceCmdType::CheckRoute,
                self.wg_port_mapping,
                self.ip_addr,
            )
            .await?;
        Ok(())
    }

    fn create_random_endpoint_ports(&mut self) {
        self.wg_port_mapping.external = rand::thread_rng().gen_range(1024..49151);
        self.proxy_port_mapping.external = loop {
            let rand = rand::thread_rng().gen_range(1024..49151);
            if rand != self.wg_port_mapping.external {
                break rand;
            }
        };
    }

    async fn create_endpoint_candidate(&mut self) {
        self.create_random_endpoint_ports();

        self.proxy_port_mapping.internal = match self.udp_socket.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => return,
        };

        if let Some(port) = self.igd.get_wg_interface_port(self.wg.clone()).await {
            self.wg_port_mapping.internal = port;
        } else {
            return;
        }

        match self.igd.get_igd(self.udp_socket.clone()).await {
            Ok(ip) => self.ip_addr = ip,
            Err(e) => {
                telio_log_error!("Error get IGD device {:?}", e);
                return;
            }
        }

        self.endpoint_candidate = match self
            .igd
            .add_endpoint(self.ip_addr, self.proxy_port_mapping, self.wg_port_mapping)
            .await
        {
            Ok(ep) => Some(ep),
            Err(e) => {
                telio_log_error!("Error getting endpoint candidate: {:?}", e);
                None
            }
        };

        if let Some(epc) = self.endpoint_candidate.clone() {
            if let Some(epc_tx) = &self.epc_event_tx {
                telio_log_info!("Got UpnpEndpointCanditate: {:?}", epc);
                let _ = epc_tx.send((EndpointProviderType::Upnp, vec![epc])).await;
            }
        }
    }

    async fn handle_ping_rx(
        &mut self,
        encrypted_buf: &[u8],
        addr: &SocketAddr,
    ) -> Result<(), Error> {
        let wg_port = if let Some(port) = self.get_wg_port() {
            port
        } else {
            return Err(Error::NoWGListenPort);
        };

        self.ping_pong_handler
            .lock()
            .await
            .handle_rx_packet(
                encrypted_buf,
                addr,
                wg_port,
                &self.udp_socket,
                &self.pong_events_tx,
            )
            .await
    }
}

#[async_trait]
impl<Wg: WireGuard, I: IgdCommands, E: Backoff> Runtime for State<Wg, I, E> {
    const NAME: &'static str = "UpnpEndpointProvider";

    type Err = ();

    async fn wait_with_update<F>(&mut self, update: F) -> std::result::Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, std::result::Result<(), Self::Err>>> + Send,
    {
        tokio::select! {
            Ok((len, addr)) = self.udp_socket.recv_from(&mut self.rx_buff) => {
                let buff = self.rx_buff.clone();
                let _ = self.handle_ping_rx(&buff[..len], &addr).await;
            }
            _ = &mut self.upnp_interval => {
                if self.check_endpoint_candidate().await.is_ok(){
                    self.upnp_interval =  PinnedSleep::new(self.exponential_backoff.get_backoff(), ());
                } else {
                    self.exponential_backoff.next_backoff();
                };
            }
            // Incoming task
            update = update => {
                return update(self).await;
            }
            else => {
                return Ok(());
            },
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint_providers::upnp::igd::{MockIgdCommands, PortMapping, ServiceCmdType};
    use crate::endpoint_providers::{EndpointCandidate, Error};
    use lazy_static::lazy_static;
    use mockall::mock;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;
    use telio_crypto::PublicKey;
    use telio_crypto::SecretKey;
    use telio_sockets::{NativeProtector, SocketPool};
    use telio_utils::exponential_backoff::MockBackoff;
    use telio_wg::uapi::{Interface, Peer};
    use telio_wg::Error as wgError;
    use tokio::sync::Mutex;

    mock! {
        pub Wg {}
        #[async_trait]
        impl WireGuard for Wg {
            async fn get_interface(&self) -> Result<Interface, wgError>;
            async fn get_adapter_luid(&self) -> Result<u64, wgError>;
            async fn wait_for_listen_port(&self, d: Duration) -> Result<u16, wgError>;
            async fn get_wg_socket(&self, ipv6: bool) -> Result<Option<i32>, wgError>;
            async fn set_secret_key(&self, key: SecretKey) -> Result<(), wgError>;
            async fn set_fwmark(&self, fwmark: u32) -> Result<(), wgError>;
            async fn add_peer(&self, peer: Peer) -> Result<(), wgError>;
            async fn del_peer(&self, key: PublicKey) -> Result<(), wgError>;
            async fn drop_connected_sockets(&self) -> Result<(), wgError>;
            async fn time_since_last_rx(&self, public_key: PublicKey) -> Result<Option<Duration>, wgError>;
            async fn time_since_last_endpoint_change(&self, public_key: PublicKey) -> Result<Option<Duration>, wgError>;
            async fn stop(self);
        }
    }

    lazy_static! {
        static ref ENDPOINT: Mutex<EndpointCandidate> = Mutex::new(EndpointCandidate {
            wg: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1000),
            udp: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 2000),
        });
    }

    async fn igd_service_command(
        command_type: ServiceCmdType,
        mapping: PortMapping,
    ) -> Result<(), Error> {
        if command_type == ServiceCmdType::AddRoute || command_type == ServiceCmdType::DeleteRoute {
            return Ok(());
        } else {
            if ENDPOINT.lock().await.wg.port() == mapping.external {
                return Ok(());
            } else if ENDPOINT.lock().await.udp.port() == mapping.external {
                return Ok(());
            }
        }
        return Err(Error::FailedToGetUpnpService);
    }

    async fn add_endpoint(wg: PortMapping, proxy: PortMapping) -> Result<EndpointCandidate, Error> {
        let mut epc = ENDPOINT.lock().await;
        epc.wg.set_port(wg.external);
        epc.udp.set_port(proxy.external);
        Ok(EndpointCandidate {
            wg: epc.wg,
            udp: epc.udp,
        })
    }

    async fn get_wg_port() -> Option<u16> {
        Some(2000)
    }

    async fn get_igd() -> Result<IpAddr, Error> {
        Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    pub async fn prepare_test_setup() -> UpnpEndpointProvider<MockWg, MockIgdCommands, MockBackoff>
    {
        let spool = SocketPool::new(NativeProtector::new().unwrap());
        let udp_socket = spool
            .new_external_udp((Ipv4Addr::UNSPECIFIED, 0), None)
            .await
            .unwrap();

        // These are not properly used yet, just dummy variables
        let mut wg = MockWg::default();
        let wg_port = 12345;
        let wg_peers = Vec::<(PublicKey, Peer)>::new();
        let backoff_array = [4000, 12000, 44444, 7654, 10000, 765432];

        let mut mock = MockIgdCommands::new();
        wg.expect_get_interface().returning(move || {
            Ok(Interface {
                listen_port: Some(wg_port),
                peers: wg_peers.clone().into_iter().collect(),
                ..Default::default()
            })
        });

        mock.expect_add_endpoint()
            .returning(move |_, proxy_port, wg_port| Box::pin(add_endpoint(proxy_port, wg_port)));
        mock.expect_igd_service_command()
            .returning(move |command_type, mapping, _| {
                Box::pin(igd_service_command(command_type, mapping))
            });
        mock.expect_get_igd()
            .return_once(move |_| Box::pin(get_igd()));
        mock.expect_get_wg_interface_port()
            .returning(move |_| Box::pin(get_wg_port()));

        UpnpEndpointProvider::start_with(
            udp_socket,
            Arc::new(wg),
            {
                let mut result = MockBackoff::default();
                let backoff_array_idx = Rc::new(RefCell::new(0));
                let backoff_array_idx_a = backoff_array_idx.clone();
                result.expect_get_backoff().returning_st(move || {
                    Duration::from_millis(backoff_array[*backoff_array_idx_a.borrow()])
                });
                let backoff_array_idx_b = backoff_array_idx.clone();
                result.expect_next_backoff().returning_st(move || {
                    backoff_array_idx_b.replace_with(|idx| *idx + 1);
                });
                result.expect_reset().returning_st(move || {
                    backoff_array_idx.replace(0);
                });
                result
            },
            Arc::new(Mutex::new(PingPongHandler::new(SecretKey::gen()))),
            mock,
        )
    }

    #[tokio::test]
    async fn create_upnp_endpoint() {
        let upnp = prepare_test_setup().await;
        let epc = upnp.get_endpoint_candidate().await;
        let sock = upnp.get_internal_socket().await;

        assert!(sock.is_some());
        assert!(epc.is_some());
    }
}
