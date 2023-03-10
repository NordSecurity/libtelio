use std::time::Duration;

use crate::route_type::RouteType;
use crate::{Configure, Route, RouteResult};
use async_trait::async_trait;
use telio_crypto::PublicKey;
use telio_proto::DataMsg;
use telio_task::io::Chan;

use super::Path;

pub struct Default;

#[async_trait]
impl Configure for Default {
    async fn configure(&self, _config: telio_relay::Config) {}
}

#[async_trait]
impl Route for Default {
    async fn set_nodes(&self, _nodes: Vec<PublicKey>) -> RouteResult<()> {
        Ok(())
    }

    async fn update_nodes(&self, _nodes: Vec<PublicKey>) -> RouteResult<()> {
        Ok(())
    }

    async fn reset_nodes(&self, _nodes: Vec<PublicKey>) -> RouteResult<()> {
        Ok(())
    }

    async fn is_reachable(&self, _node: PublicKey) -> bool {
        true
    }

    async fn rtt(&self, _node: PublicKey) -> RouteResult<Duration> {
        unimplemented!("Not yet used.")
    }
}

pub fn build(relay: Chan<(PublicKey, DataMsg)>) -> Path {
    Path {
        route: RouteType::Relay { relay: Default },
        channel: relay,
        changes: None,
    }
}
