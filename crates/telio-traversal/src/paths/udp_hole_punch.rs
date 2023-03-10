use crate::routes::udp_hole_punch::{Error, UdpHolePunch};
use telio_crypto::PublicKey;
use telio_proto::CallMeMaybeMsgDeprecated;
use telio_sockets::External;
use telio_task::io::Chan;
use tokio::net::UdpSocket;

use super::{Path, RouteType};

pub fn build(
    cmm: Chan<(PublicKey, CallMeMaybeMsgDeprecated)>,
    udp_sock: External<UdpSocket>,
) -> Result<Path, Error> {
    let Chan {
        tx: event_tx,
        rx: event_rx,
    } = Chan::default();

    let (ldata, rdata) = Chan::pipe();
    #[cfg(test)]
    let dummy: i32 = 0;
    match UdpHolePunch::start(
        udp_sock,
        ldata,
        cmm,
        event_tx,
        #[cfg(test)]
        dummy,
    ) {
        Ok(udp_hole_punch) => Ok(Path {
            route: RouteType::UdpHolePunch { udp_hole_punch },
            channel: rdata,
            changes: Some(event_rx),
        }),
        Err(error) => Err(error),
    }
}
