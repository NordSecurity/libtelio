use async_trait::async_trait;
use boringtun::device::{tun::TunSocket, DeviceConfig, DeviceHandle, Tun};
use futures::future::BoxFuture;
use slog::{o, Drain, Logger};
use slog_stdlog::StdLog;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::uapi::{self, Cmd, Response};

pub use boringtun::device::Error;
use libc::socket;
use telio_sockets::SocketPool;

#[cfg(not(test))]
pub type FirewallCb = Option<Arc<dyn Fn(&[u8; 32], &[u8]) -> bool + Send + Sync>>;

pub struct BoringTun {
    device: RwLock<DeviceHandle>,
}

impl BoringTun {
    #[cfg(not(test))]
    pub fn start(
        name: &str,
        tun: Option<NativeTun>,
        socket_pool: Arc<SocketPool>,
        firewall_process_inbound_callback: FirewallCb,
        firewall_process_outbound_callback: FirewallCb,
    ) -> Result<Self, AdapterError> {
        let logger = Logger::root(StdLog.fuse(), o!());
        let config = DeviceConfig {
            n_threads: 4,
            use_connected_socket: cfg!(not(any(target_os = "ios", target_os = "macos"))),
            logger,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            open_uapi_socket: false,
            protect: socket_pool,
            firewall_process_inbound_callback,
            firewall_process_outbound_callback,
        };

        let device = match tun {
            Some(tun) => DeviceHandle::new_with_tun(TunSocket::new_from_fd(tun)?, config)?,
            None => DeviceHandle::new(name, config)?,
        };

        Ok(BoringTun {
            device: RwLock::new(device),
        })
    }

    async fn send_uapi_cmd_str(&self, cmd: &str) -> String {
        self.device.read().await.send_uapi_cmd(cmd)
    }
}

#[async_trait]
impl Adapter for BoringTun {
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> Response {
        let res = self.send_uapi_cmd_str(&cmd.to_string()).await;
        uapi::response_from_str(&res)
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
}
