use async_trait::async_trait;
use telio_crypto::PublicKey;
use tokio::time::Duration;

use crate::paths::relay::Default;
use crate::routes::udp_hole_punch::UdpHolePunch;
use crate::{Configure, Route, RouteResult};

pub enum RouteType {
    Relay { relay: Default },
    UdpHolePunch { udp_hole_punch: UdpHolePunch },
}

impl RouteType {
    pub async fn stop(self) {
        match self {
            RouteType::Relay { relay: _ } => {}
            RouteType::UdpHolePunch { udp_hole_punch } => {
                udp_hole_punch.stop().await;
            }
        }
    }
}

#[async_trait]
impl Route for RouteType {
    async fn set_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
        match self {
            RouteType::Relay { relay } => relay.set_nodes(nodes).await,
            RouteType::UdpHolePunch { udp_hole_punch } => udp_hole_punch.set_nodes(nodes).await,
        }
    }

    async fn update_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
        match self {
            RouteType::Relay { relay } => relay.update_nodes(nodes).await,
            RouteType::UdpHolePunch { udp_hole_punch } => udp_hole_punch.update_nodes(nodes).await,
        }
    }

    async fn reset_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
        match self {
            RouteType::Relay { relay } => relay.reset_nodes(nodes).await,
            RouteType::UdpHolePunch { udp_hole_punch } => udp_hole_punch.reset_nodes(nodes).await,
        }
    }

    async fn is_reachable(&self, node: PublicKey) -> bool {
        match self {
            RouteType::Relay { relay } => relay.is_reachable(node).await,
            RouteType::UdpHolePunch { udp_hole_punch } => udp_hole_punch.is_reachable(node).await,
        }
    }

    async fn rtt(&self, node: PublicKey) -> RouteResult<Duration> {
        match self {
            RouteType::Relay { relay } => relay.rtt(node).await,
            RouteType::UdpHolePunch { udp_hole_punch } => udp_hole_punch.rtt(node).await,
        }
    }
}

#[async_trait]
impl Configure for RouteType {
    async fn configure(&self, config: telio_relay::Config) {
        match self {
            RouteType::Relay { relay } => relay.configure(config).await,
            RouteType::UdpHolePunch { udp_hole_punch } => udp_hole_punch.configure(config).await,
        }
    }
}
