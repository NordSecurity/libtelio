use async_trait::async_trait;
use futures::future::BoxFuture;
use neptun::device::{tun::TunSocket, DeviceConfig, DeviceHandle};
use slog::{o, Drain};
use slog_stdlog::StdLog;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{IntoRawFd, RawFd};
use std::sync::Arc;
use std::{io, ops::Deref};
use telio_crypto::PublicKey;
use telio_utils::telio_log_debug;
use tokio::sync::RwLock;

use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::uapi::{self, Cmd, Response};

use libc::socket;
pub use neptun::device::Error;
use telio_sockets::SocketPool;

#[cfg(not(any(test, feature = "test-adapter")))]
use crate::{FirewallInboundCb, FirewallOutboundCb};

pub struct NepTUN {
    device: RwLock<DeviceHandle>,
    reset_conns_cb: super::FirewallResetConnsCb,
}

impl NepTUN {
    #[allow(clippy::too_many_arguments)]
    #[cfg(not(any(test, feature = "test-adapter")))]
    pub fn start(
        name: &str,
        tun: Option<RawFd>,
        socket_pool: Arc<SocketPool>,
        firewall_process_inbound_callback: FirewallInboundCb,
        firewall_process_outbound_callback: FirewallOutboundCb,
        firewall_reset_connections_callback: super::FirewallResetConnsCb,
        skt_buffer_size: Option<u32>,
        inter_thread_channel_size: Option<u32>,
        max_inter_thread_batched_pkts: Option<u32>,
        enable_ipv6: bool,
    ) -> Result<Self, AdapterError> {
        use std::os::fd::RawFd;

        let config = DeviceConfig {
            // Apple's NepTUN device runs most efficiently on a single perf-core
            n_threads: {
                if cfg!(target_os = "android") {
                    // A large set of supported android devices
                    // have 4 "performance" cores
                    4
                } else if cfg!(not(any(
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "tvos"
                ))) {
                    num_cpus::get()
                } else {
                    1
                }
            },
            use_connected_socket: cfg!(not(any(
                target_os = "ios",
                target_os = "macos",
                target_os = "tvos"
            ))),
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            open_uapi_socket: false,
            protect: socket_pool,
            firewall_process_inbound_callback,
            firewall_process_outbound_callback,
            skt_buffer_size: skt_buffer_size.map(|v| v as usize),
            inter_thread_channel_size: inter_thread_channel_size.map(|v| v as usize),
            max_inter_thread_batched_pkts: max_inter_thread_batched_pkts.map(|v| v as usize),
            enable_ipv6,
        };

        let device = match tun {
            Some(tun) => DeviceHandle::new_with_tun(TunSocket::new_from_fd(tun)?, config)?,
            None => DeviceHandle::new(name, config)?,
        };

        Ok(NepTUN {
            device: RwLock::new(device),
            reset_conns_cb: firewall_reset_connections_callback,
        })
    }

    async fn send_uapi_cmd_str(&self, cmd: &str) -> String {
        self.device.read().await.send_uapi_cmd(cmd)
    }
}

#[async_trait]
impl Adapter for NepTUN {
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> Result<Response, AdapterError> {
        let res = self.send_uapi_cmd_str(&cmd.to_string()).await;
        Ok(uapi::response_from_str(&res)?)
    }

    fn get_adapter_luid(&self) -> u64 {
        0
    }

    async fn drop_connected_sockets(&self) {
        self.device.read().await.drop_connected_sockets();
    }

    async fn stop(&self) {
        self.device.read().await.trigger_exit();
        self.device.write().await.wait();
    }

    async fn inject_reset_packets(&self, exit_pubkey: &PublicKey) {
        let Some(cb) = self.reset_conns_cb.as_ref() else {
            return;
        };

        telio_log_debug!("Reseting existing connection with packet injection");

        let dev = self.device.read().await;
        let dev = dev.device.read();
        let mut tun = dev.iface();

        cb(exit_pubkey, &mut tun);
    }

    async fn set_tun(&self, tun: super::Tun) -> Result<(), AdapterError> {
        let new_tun = TunSocket::new_from_fd(tun.into_raw_fd())?;
        self.device.write().await.set_iface(new_tun)?;
        Ok(())
    }

    fn clone_box(&self) -> Option<Box<dyn Adapter>> {
        None
    }
}
