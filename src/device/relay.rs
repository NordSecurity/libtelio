use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use telio_sockets::{SocketBufSizes, SocketPool, UdpParams};
use telio_wg::uapi::AnalyticsEvent;
use tokio::task::JoinHandle;

use telio_crypto::{PublicKey, SecretKey};
use telio_model::{
    api_config::{Features, PathType},
    event::{Event, Set},
    report_event, EndpointMap,
};
use telio_nurse::{config::Config as NurseConfig, data::MeshConfigUpdateEvent, Nurse};
use telio_proxy::Error as ProxyError;
use telio_relay::{
    derp::{Config as DerpConfig, DerpRelay, Server as DerpServer},
    multiplexer::{Error as MultiplexerError, Multiplexer},
};
use telio_task::io::{chan, mc_chan::Tx, Chan, McChan};
use telio_task::{task_exec, Task};
use telio_traversal::{
    ConfigBuilder as RouterConfigBuilder, Error as RouterError, PathSetIo, Router,
};

use telio_utils::{telio_err_with_log, telio_log_debug, telio_log_trace};

pub type Result<T = ()> = std::result::Result<T, Error>;

const SOCK_BUF_SZ: usize = 212992;

#[derive(Clone)]
pub struct Config {
    pub mesh_ip: IpAddr,
    pub nodes: HashSet<PublicKey>,
    pub servers: Vec<DerpServer>,
}

pub struct Relay {
    rt: Option<Runtime>,
    private_key: SecretKey,
    wg_port: Option<u16>,
    socket_pool: Arc<SocketPool>,
    event_ch: Tx<Box<Event>>,
    path_change_ch: chan::Tx<(PublicKey, PathType)>,
    analytics_ch: Option<Tx<Box<AnalyticsEvent>>>,
    config_update_ch: Option<Tx<Box<MeshConfigUpdateEvent>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    #[error(transparent)]
    Router(#[from] RouterError),
    #[error(transparent)]
    Multiplexer(#[from] MultiplexerError),
    #[error("Relay not running")]
    NotStarted,
    #[error("Relay runtime not started")]
    RuntimeNotStarted,
}

struct Runtime {
    router: Router,
    wait: JoinHandle<()>,
    multiplexer: Multiplexer,
    derp: DerpRelay,
    nurse: Option<Task<Nurse>>,
}

impl Relay {
    pub async fn start(
        private_key: &SecretKey,
        wg_port: Option<u16>,
        socket_pool: Arc<SocketPool>,
        event_ch: Tx<Box<Event>>,
        path_change_ch: chan::Tx<(PublicKey, PathType)>,
        analytics_ch: Option<Tx<Box<AnalyticsEvent>>>,
        config_update_ch: Option<Tx<Box<MeshConfigUpdateEvent>>>,
    ) -> Result<Self> {
        Ok(Self {
            rt: None,
            private_key: *private_key,
            wg_port,
            socket_pool,
            event_ch,
            path_change_ch,
            analytics_ch,
            config_update_ch,
        })
    }

    pub async fn stop(mut self) {
        if let Some(rt) = self.rt {
            rt.stop().await;
        }
        self.rt = None
    }

    pub async fn set_private_key(&mut self, private_key: &SecretKey) -> Result<()> {
        if let Some(rt) = &mut self.rt {
            self.private_key = *private_key;
            rt.derp
                .set_config(DerpConfig {
                    secret_key: *private_key,
                    ..rt.derp.get_config().await
                })
                .await;
            return Ok(());
        }
        telio_err_with_log!(Error::RuntimeNotStarted)
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        if let Some(rt) = self.rt.as_ref() {
            rt.derp.reconnect().await;
            telio_log_trace!("Derp Reconnected");
            return Ok(());
        }
        telio_err_with_log!(Error::RuntimeNotStarted)
    }

    pub async fn set_config(
        &mut self,
        features: &Features,
        config: Option<Config>,
        wg_port: Option<u16>,
    ) -> Result<EndpointMap> {
        if config.is_none() {
            if let Some(rt) = self.rt.take() {
                rt.stop().await;
            }
            return Ok(EndpointMap::new());
        }

        if self.rt.is_none() {
            self.rt = Some(
                Runtime::start(
                    DerpConfig {
                        secret_key: self.private_key,
                        mesh_ip: config
                            .as_ref()
                            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |a| a.mesh_ip),
                        servers: config.as_ref().map_or(vec![], |c| c.servers.clone()),
                        ..Default::default()
                    },
                    features,
                    self.wg_port,
                    self.socket_pool.clone(),
                    self.event_ch.clone(),
                    self.path_change_ch.clone(),
                    self.analytics_ch.clone(),
                    self.config_update_ch.clone(),
                )
                .await?,
            );
        }

        if let Some(rt) = self.rt.as_mut() {
            let nodes = config.as_ref().map_or(HashSet::new(), |c| c.nodes.clone());
            let from = rt
                .router
                .proxy
                .get_endpoint_map()
                .await
                .unwrap_or_default()
                .keys()
                .cloned()
                .collect::<HashSet<PublicKey>>();

            let insert_keys = &nodes - &from;
            let remove_keys = &from - &nodes;

            telio_log_debug!("key inserted: {:?}", &insert_keys);
            telio_log_debug!("key removed: {:?}", &remove_keys);

            let derp_config = DerpConfig {
                servers: config.as_ref().map_or(vec![], |c| c.servers.clone()),
                secret_key: self.private_key,
                allowed_pk: nodes.clone(),
                ..rt.derp.get_config().await
            };
            rt.derp.set_config(derp_config.clone()).await;
            rt.router
                .configure(
                    RouterConfigBuilder::default()
                        .wg_port(wg_port)
                        .peers(nodes)
                        .derp(derp_config)
                        .build()
                        .map_err(|err| Error::Router(err.into()))?,
                )
                .await?;

            if let Some(nurse) = &rt.nurse {
                let _ = task_exec!(nurse, async move |state| {
                    state.set_nodes(insert_keys, remove_keys).await;

                    Ok(())
                })
                .await;
            }

            return Ok(rt.router.proxy.get_endpoint_map().await?);
        }

        telio_err_with_log!(Error::RuntimeNotStarted)
    }

    pub async fn get_connected_server(&self) -> Result<Option<DerpServer>> {
        if let Some(rt) = self.rt.as_ref() {
            telio_log_trace!("get_connected_server() - OK");
            return Ok(rt.derp.get_connected_server().await);
        }
        telio_err_with_log!(Error::RuntimeNotStarted)
    }

    pub async fn get_relay_config(&self) -> Result<DerpConfig> {
        if let Some(rt) = self.rt.as_ref() {
            telio_log_trace!("get_relay_config() - OK");
            return Ok(rt.derp.get_config().await);
        }
        telio_err_with_log!(Error::RuntimeNotStarted)
    }

    pub fn is_runtime_started(&self) -> bool {
        self.rt.as_ref().is_some()
    }
}

impl Runtime {
    #[allow(clippy::too_many_arguments)]
    async fn start(
        config: DerpConfig,
        features: &Features,
        wg_port: Option<u16>,
        socket_pool: Arc<SocketPool>,
        event_ch: Tx<Box<Event>>,
        path_change_ch: chan::Tx<(PublicKey, PathType)>,
        analytics_ch: Option<Tx<Box<AnalyticsEvent>>>,
        config_update_ch: Option<Tx<Box<MeshConfigUpdateEvent>>>,
    ) -> Result<Runtime> {
        telio_log_trace!("starting relay runtime...");
        // Pipe for multiplexer -> derp communication
        let (chan_l, chan_r) = Chan::pipe();
        // Multiplexer component
        let multiplexer = Multiplexer::start(chan_l);
        // Derp relay events channel
        let McChan {
            rx: mut devent_rx,
            tx: devent_tx,
        } = McChan::default();

        let private_key = config.secret_key;

        // Derp component
        let derp = DerpRelay::start_with(
            chan_r,
            socket_pool.clone(),
            config.clone(),
            devent_tx.clone(),
        );

        let err_ch = event_ch.clone();
        let join_devent = tokio::spawn(async move {
            while let Ok(event) = devent_rx.recv().await {
                let rel_event = Event::new::<DerpServer>().set(*event);

                report_event!(err_ch, rel_event);
            }
        });

        let nurse = if telio_lana::is_lana_initialized() {
            if let Some(nurse_features) = &features.nurse {
                Some(Task::start(
                    Nurse::new(
                        private_key.public(),
                        NurseConfig::new(nurse_features),
                        &devent_tx,
                        &event_ch,
                        &multiplexer,
                        analytics_ch,
                        config_update_ch,
                    )
                    .await,
                ))
            } else {
                telio_log_debug!("nurse not configured");
                None
            }
        } else {
            telio_log_debug!("lana not initialized");
            None
        };

        // Start Router
        let feature_paths = features.paths.as_ref().cloned().unwrap_or_default();

        let sock = socket_pool
            .new_external_udp(
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                Some(UdpParams(SocketBufSizes {
                    rx_buf_size: Some(SOCK_BUF_SZ),
                    tx_buf_size: Some(SOCK_BUF_SZ),
                })),
            )
            .await?;

        let router = Router::start(
            feature_paths,
            PathSetIo {
                relay: multiplexer.get_channel().await?,
                udp_hole_punch: (sock, multiplexer.get_channel().await?),
            },
            path_change_ch,
        )?;
        router
            .configure(
                RouterConfigBuilder::default()
                    .wg_port(wg_port)
                    .derp(config)
                    .build()
                    .map_err(|err| Error::Router(err.into()))?,
            )
            .await?;

        Ok(Runtime {
            router,
            multiplexer,
            derp,
            nurse,
            wait: tokio::spawn(async move {
                let _ = join_devent.await;
            }),
        })
    }

    async fn stop(self) {
        telio_log_trace!("stopping...");
        self.router.stop().await;
        self.derp.stop().await;
        self.multiplexer.stop().await;

        if let Some(nurse) = self.nurse {
            nurse.stop().await;
        }

        let _ = self.wait.await;
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    // TODO add tests
    use super::*;
    use crate::device::relay::{Config, Relay};
    use std::{collections::HashSet, net::Ipv4Addr};
    use telio_proto::Packet;
    use telio_relay::{
        derp::{Config as DerpConfig, DerpRelay, Server as DerpServer},
        multiplexer::Multiplexer,
    };
    use telio_task::io::McChan;
    use tokio::net::UdpSocket;

    struct RelayTest {
        peer_public_key: PublicKey,
        wg_socket: UdpSocket,
        derp: DerpRelay,
        multiplexer: Multiplexer,
        relay: Relay,
        endpoint_map: EndpointMap,
        relay_channel: Chan<(PublicKey, Packet)>,
    }

    use telio_test::await_timeout;

    impl RelayTest {
        async fn new() -> RelayTest {
            let wg_socket = await_timeout!(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let wg_port = wg_socket.local_addr().unwrap().port();

            let private_key = "eA/Pfd+Pl7odFOjpiyTGhJYkgP0ujfqf1lqMmThuc3E="
                .parse::<SecretKey>()
                .unwrap();

            let peer_public_key = "REjdn4zY2TFx2AMujoNGPffo9vDiRDXpGG4jHPtx2AY="
                .parse::<PublicKey>()
                .unwrap();

            let (event_tx, _event_rx) = tokio::sync::broadcast::channel(1);
            let (path_event_tx, _path_event_rx) = tokio::sync::mpsc::channel(1);

            // Pipe for multiplexer -> derp communication
            let (chan_l, chan_r) = Chan::pipe();

            // Multiplexer component
            let multiplexer = Multiplexer::start(chan_l);
            //TODO adapt to dump the channels
            telio_log_trace!("mutiplexer started");

            // Derp relay events channel
            let McChan {
                rx: _devent_rx,
                tx: devent_tx,
            } = McChan::default();

            let pool = Arc::new(SocketPool::default());
            // Derp component
            let derp = DerpRelay::start_with(
                chan_r,
                pool.clone(),
                DerpConfig {
                    secret_key: private_key,
                    ..Default::default()
                },
                devent_tx,
            );

            let mut relay = Relay::start(
                &private_key,
                Some(wg_port),
                pool,
                event_tx.clone(),
                path_event_tx,
                None,
                None,
            )
            .await
            .unwrap();

            let endpoint_map = {
                let mut nodes = HashSet::new();
                nodes.insert(peer_public_key);

                let fake_server = DerpServer {
                    hostname: "de0000.nordvpn.com".into(),
                    relay_port: 8765,
                    ..Default::default()
                };

                let config = Config {
                    nodes,
                    servers: vec![fake_server],
                    mesh_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                };

                let features = Default::default();

                await_timeout!(relay.set_config(&features, Some(config), Some(wg_port))).unwrap()
            };

            let relay_channel = multiplexer.get_channel().await.unwrap();

            Self {
                peer_public_key,
                wg_socket,
                derp,
                multiplexer,
                relay,
                endpoint_map,
                relay_channel,
            }
        }
    }
}
