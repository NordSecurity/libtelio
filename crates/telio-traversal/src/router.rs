use std::collections::HashSet;

use derive_builder::Builder;
use telio_crypto::PublicKey;
use telio_model::api_config::{FeaturePaths, PathType};
use telio_proto::DataMsg;
use telio_proxy::{Config as ProxyConfig, Io as ProxyIo, UdpProxy};
use telio_relay::Config as DerpConfig;

use telio_task::{
    io::{chan::Tx, Chan},
    ExecError,
};
use tokio::sync::mpsc::error::SendError;

use crate::paths::{Io as PathsIo, PathSetIo, Paths};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Task was stooped")]
    Stopped,
    #[error("Could not acquire channel")]
    Channel,
    #[error("Peer already exists")]
    PeerExists,
    #[error("Derp config not set for path set builder")]
    DerpConfigNotSet,
    #[error(transparent)]
    TaskError(#[from] ExecError),
    #[error(transparent)]
    Proxy(#[from] telio_proxy::Error),
    #[error("Router configuration failed: {0}")]
    Config(#[from] ConfigBuilderError),
    #[error(transparent)]
    Send(#[from] SendError<(PublicKey, DataMsg)>),
    #[error(transparent)]
    Route(#[from] crate::RouteError),
    #[error(transparent)]
    UdpHolePunch(#[from] crate::udp_hole_punch::Error),
}

#[derive(Builder, Default, Clone)]
pub struct Config {
    #[builder(default)]
    pub wg_port: Option<u16>,
    #[builder(default)]
    pub peers: HashSet<PublicKey>,
    #[builder(default)]
    pub derp: DerpConfig,
}

pub struct Router {
    pub proxy: UdpProxy,
    paths: Paths,
}

impl Router {
    pub fn start(
        features: FeaturePaths,
        path_set_io: PathSetIo,
        path_change_tx: Tx<(PublicKey, PathType)>,
    ) -> Result<Self, Error> {
        let (to_proxy, to_paths) = Chan::pipe();

        Ok(Router {
            proxy: UdpProxy::start(ProxyIo { relay: to_paths }),
            paths: Paths::start(
                features,
                PathsIo {
                    data: to_proxy,
                    events: path_change_tx,
                },
                path_set_io,
            )?,
        })
    }

    pub async fn configure(&self, config: Config) -> Result<(), Error> {
        self.paths.configure(config.clone()).await?;
        self.proxy.configure(config.into()).await?;
        Ok(())
    }

    pub async fn stop(self) {
        self.paths.stop().await;
        self.proxy.stop().await;
    }
}

impl From<Config> for ProxyConfig {
    fn from(c: Config) -> Self {
        ProxyConfig {
            wg_port: c.wg_port,
            peers: c.peers,
        }
    }
}
