use std::mem;

use libc::{bind, recvmsg, socket, AF_NETLINK, NETLINK_ROUTE, SOCK_RAW};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};
use tokio::sync::oneshot::Receiver;
use tokio::task::JoinHandle;

use crate::monitor::PATH_CHANGE_BROADCAST;

/// Setup network path monitor for linux
pub fn setup_network_monitor(termination_channel_rx: Receiver<()>) {
    match open_netlink_socket() {
        Ok(sock) => read_event(sock, termination_channel_rx),
        Err(e) => telio_log_error!("Unable to open network monitor socket {e:?}"),
    }
}

fn open_netlink_socket() -> Result<i32, i32> {
    let sockfd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if sockfd < 0 {
        return Err(sockfd);
    }

    let addr = netlink::Struct_sockaddr_nl {
        nl_family: AF_NETLINK as u16,
        nl_groups: netlink::RTM_NEWLINK | 0x1,
        ..Default::default()
    };

    let res = unsafe {
        bind(
            sockfd,
            &addr as *const _ as *const _,
            mem::size_of::<netlink::Struct_sockaddr_nl>() as u32,
        )
    };

    telio_log_debug!("Network monitor binding with socket {res}");
    Ok(sockfd)
}

fn read_event(socket: i32, mut termination_channel_rx: Receiver<()>) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let buf = vec![0; 1024 / mem::size_of::<netlink::Struct_nlmsghdr>()];
        let mut sa = netlink::Struct_sockaddr_nl::default();
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut msg = libc::msghdr {
            msg_name: &mut sa as *mut _ as *mut _,
            msg_namelen: mem::size_of_val(&sa) as u32,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        while termination_channel_rx.try_recv().is_err() {
            let _ = unsafe { recvmsg(socket, &mut msg, 0) };
            telio_log_trace!("Network path update notification");
            if let Err(e) = PATH_CHANGE_BROADCAST.send(()) {
                telio_log_warn!("Failed to notify about changed path {e}");
            }
        }
    })
}
