use telio_crypto::PublicKey;
use telio_model::api_config::PathType;
use telio_proto::{CallMeMaybeMsgDeprecated, DataMsg};
use telio_sockets::External;
use telio_task::io::Chan;
use telio_utils::telio_log_trace;
use tokio::net::UdpSocket;

use crate::{
    paths::{relay, udp_hole_punch},
    Error,
};

use super::set::PathSet;

pub trait PathSetBuilder: Send + Sized {
    fn build(self) -> Result<PathSet, Error>;
}

pub struct PathSetIo {
    pub relay: Chan<(PublicKey, DataMsg)>,
    pub udp_hole_punch: (
        External<UdpSocket>,
        Chan<(PublicKey, CallMeMaybeMsgDeprecated)>,
    ),
}

pub struct PathSetBuilderDefault {
    io: PathSetIo,
    priority: Vec<PathType>,
}

impl PathSetBuilderDefault {
    pub fn new(io: PathSetIo, priority: Vec<PathType>) -> Self {
        Self { io, priority }
    }
}

impl PathSetBuilder for PathSetBuilderDefault {
    fn build(self) -> Result<PathSet, Error> {
        let mut paths = PathSet::new();

        let mut relay = Some(self.io.relay);
        let mut uhp = Some(self.io.udp_hole_punch);

        for path_type in self.priority.iter() {
            match *path_type {
                PathType::Relay => {
                    if let Some(data) = relay.take() {
                        paths.add_next(*path_type, relay::build(data));
                    }
                }
                PathType::UdpHolePunch => {
                    if let Some((sock, cmm)) = uhp.take() {
                        paths.add_next(*path_type, udp_hole_punch::build(cmm, sock)?);
                    }
                }
            }
            telio_log_trace!("Added path: {:?}", path_type);
        }

        Ok(paths)
    }
}
