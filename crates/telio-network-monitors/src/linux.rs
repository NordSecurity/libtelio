use neli::{
    consts::{netfilter::NetfilterMsg, socket::NlFamily::Route},
    socket::asynchronous::NlSocketHandle as TokioSocket,
    utils::Groups,
};
use netlink_packet_core::{NetlinkDeserializable, NetlinkHeader};
use netlink_packet_route::RouteNetlinkMessage;
use std::io;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};
use tokio::task::JoinHandle;

/// Sets up linux network monitoring task
pub async fn setup_network_monitor() -> Option<JoinHandle<io::Result<()>>> {
    match open_netlink_socket().await {
        Ok(sock) => read_event(sock).await,
        Err(e) => {
            telio_log_error!("Unable to open network monitor socket: {e:?}");
            None
        }
    }
}

async fn open_netlink_socket() -> Result<TokioSocket, io::Error> {
    let mut group = Groups::empty();

    // See: https://github.com/torvalds/linux/blob/c107785c7e8dbabd1c18301a1c362544b5786282/include/uapi/linux/rtnetlink.h#L692-L699
    const RTMGRP_LINK: u32 = 0x0001;
    const RTMGRP_IPV4_IFADDR: u32 = 0x0010;
    const RTMGRP_IPV4_ROUTE: u32 = 0x0040;

    group.add_bitmask(RTMGRP_LINK);
    group.add_bitmask(RTMGRP_IPV4_IFADDR);
    group.add_bitmask(RTMGRP_IPV4_ROUTE);

    let s = TokioSocket::connect(Route, None, group).map_err(io::Error::other)?;
    telio_log_debug!("Network monitor socket opened");
    Ok(s)
}

async fn read_event(sock: TokioSocket) -> Option<JoinHandle<io::Result<()>>> {
    Some(tokio::spawn({
        async move {
            loop {
                recv_netfilter_messages(&sock).await;
                crate::monitor::notify();
            }
        }
    }))
}

async fn recv_netfilter_messages(sock: &TokioSocket) -> (Vec<u16>, usize) {
    let mut known_kinds = vec![];
    let mut unknowns = 0;
    match sock.recv_all::<NetfilterMsg, Vec<u8>>().await {
        Ok((messages, _groups)) => {
            for m in messages {
                let mut h = NetlinkHeader::default();
                h.length = *m.nl_len();
                h.message_type = m.nl_type().into();
                h.flags = m.nl_flags().bits();
                h.sequence_number = *m.nl_seq();
                h.port_number = *m.nl_pid();

                let rtnetlink_msg = m
                    .get_payload()
                    .and_then(|payload| RouteNetlinkMessage::deserialize(&h, payload).ok());

                match rtnetlink_msg {
                    Some(msg) => {
                        telio_log_debug!("Received netfilter message: {msg:?}");
                        known_kinds.push(msg.message_type());
                    }
                    None => {
                        telio_log_debug!("Received unknown netfilter message: {m:?}");
                        unknowns += 1;
                    }
                }
            }
        }
        Err(e) => {
            telio_log_warn!("Failed to receive incomming netlink message: {e}");
        }
    }

    (known_kinds, unknowns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unregister_callback() {
        let monitor_handle = setup_network_monitor().await;

        if let Some(handle) = monitor_handle {
            handle.abort();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(handle.is_finished());
        }
    }
}
