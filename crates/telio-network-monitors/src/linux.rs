use crate::monitor::PATH_CHANGE_BROADCAST;
use neli::{
    consts::socket::NlFamily::Route,
    socket::{tokio::NlSocket as TokioSocket, NlSocket},
    FromBytesWithInput,
};
use std::io;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_warn};
use tokio::task::JoinHandle;

const RTMGRP_LINK: u32 = 0x0001;
const RTMGRP_IPV4_IFADDR: u32 = 0x0010;

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
    let s = NlSocket::connect(Route, None, &[RTMGRP_LINK, RTMGRP_IPV4_IFADDR])?;
    let sock = TokioSocket::new(s)?;
    telio_log_debug!("Network monitor socket opened");
    Ok(sock)
}

async fn read_event(mut sock: TokioSocket) -> Option<JoinHandle<io::Result<()>>> {
    Some(tokio::spawn({
        let mut buffer: Vec<u8> = Vec::new();

        // Uninitialized object to satisfy recv constraints.
        // Since data isn't required from recv, hence initialzing
        // it properly isn't necessary as well.
        #[derive(Debug, FromBytesWithInput)]
        struct Payload;

        async move {
            loop {
                let _ = sock
                    .recv::<neli::consts::rtnl::Rtm, Payload>(&mut buffer)
                    .await;
                {
                    telio_log_debug!("Network path updated");
                    if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
                        telio_log_warn!("Failed to notify about changed path: {e}");
                    }
                }
            }
        }
    }))
}
