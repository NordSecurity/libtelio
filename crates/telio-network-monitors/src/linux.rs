use crate::monitor::PATH_CHANGE_BROADCAST;
use neli::{
    consts::socket::NlFamily::Route,
    socket::{tokio::NlSocket as TokioSocket, NlSocket},
};
use std::io;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_info, telio_log_warn};
use tokio::{io::AsyncReadExt, task::JoinHandle};

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
        let mut buffer: Vec<u8> = vec![0; 4096]; // Might not matter, read_buf returns 0 when network interfaces change

        async move {
            loop {
                let _ = sock.read_buf(&mut buffer).await?;
                {
                    telio_log_info!("Detected network interface modification, notifying..");
                    if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
                        telio_log_warn!("Failed to notify about changed path: {e}");
                    }
                }
            }
        }
    }))
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
