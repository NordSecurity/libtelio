//! Native WireGuard support on Linux

#![warn(clippy::unwrap_used)]

use super::{Adapter, Error as AdapterError, Tun as NativeTun};
use crate::uapi::{Cmd, Cmd::Get, Cmd::Set, Interface, Peer, Response};
use futures::executor::block_on;
use futures::future::{BoxFuture, FutureExt};
use ipnet::{IpNet, PrefixLenError};
use std::collections::BTreeMap;
use std::net::IpAddr;
use telio_crypto::{PublicKey, SecretKey};
use telio_utils::{telio_log_error, telio_log_info};
use tokio::sync::Mutex;
use wireguard_uapi::{
    err, get, linux::set::WgDeviceF, set, xplatform, DeviceInterface, RouteSocket, WgSocket,
};

/// Linux native WireGuard adapter implementation
pub struct LinuxNativeWg {
    ifname: String,
    rtsocket: Mutex<RouteSocket>,
    wgsocket: Mutex<WgSocket>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("SetDevice: {source:?}")]
    SetDevice {
        #[from]
        source: err::SetDeviceError,
    },
    #[error("Connect: {source:?}")]
    Connect {
        #[from]
        source: err::ConnectError,
    },
    #[error("LinkDeviceError: {source:?}")]
    LinkDevice {
        #[from]
        source: err::LinkDeviceError,
    },
}

impl LinuxNativeWg {
    #[cfg(not(any(test, feature = "test-adapter")))]
    pub fn start(name: &str) -> Result<Self, AdapterError> {
        let mut rtsocket = RouteSocket::connect().map_err(Error::from)?;

        rtsocket.add_device(name).map_err(Error::from)?;
        let wgsocket = WgSocket::connect().map_err(Error::from)?;

        Ok(Self {
            ifname: name.to_owned(),
            rtsocket: Mutex::new(rtsocket),
            wgsocket: Mutex::new(wgsocket),
        })
    }
}

#[async_trait::async_trait]
impl Adapter for LinuxNativeWg {
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> Result<Response, AdapterError> {
        Ok(match cmd {
            Get => {
                let dev = self.get_wg_data(&self.ifname).await;
                Response {
                    errno: dev.as_ref().map_or(1, |_| 0),
                    interface: dev.map(Interface::from),
                }
            }
            Set(device) => Response {
                errno: self.set_wg_data(&self.ifname, device).await,
                interface: None,
            },
        })
    }

    fn get_adapter_luid(&self) -> u64 {
        0
    }

    async fn stop(&self) {
        let _ = self.rtsocket.lock().await.del_device(&self.ifname);
    }

    async fn set_tun(&self, _tun: super::Tun) -> Result<(), AdapterError> {
        Err(AdapterError::UnsupportedAdapter)
    }

    fn clone_box(&self) -> Option<Box<dyn Adapter>> {
        None
    }
}

impl Drop for LinuxNativeWg {
    fn drop(&mut self) {
        if let Ok(mut rs) = RouteSocket::connect() {
            let _ = rs.del_device(&self.ifname);
        }
    }
}

impl LinuxNativeWg {
    async fn get_wg_data(&self, ifname: &str) -> Option<get::Device> {
        let dev_ifc = DeviceInterface::from_name(ifname);
        let dev = self.wgsocket.lock().await.get_device(dev_ifc);

        if let Err(e) = dev {
            telio_log_error!("LinuxNativeWg: [GET01] {}", e);

            return None;
        }

        dev.ok()
    }

    async fn set_wg_data(&self, ifname: &str, device: &xplatform::set::Device) -> i32 {
        let mut dev = set::Device::from_ifname(ifname).peers(
            device
                .peers
                .iter()
                .map(|peer| {
                    let mut dev_peer = set::Peer::from_public_key(&peer.public_key)
                        .flags({
                            let mut flags = vec![];

                            if matches!(peer.remove, Some(x) if x) {
                                flags.push(set::WgPeerF::RemoveMe);
                            }
                            if matches!(peer.update_only, Some(x) if x) {
                                flags.push(set::WgPeerF::UpdateOnly);
                            }
                            if matches!(peer.replace_allowed_ips, Some(x) if x) {
                                flags.push(set::WgPeerF::ReplaceAllowedIps);
                            }

                            flags
                        })
                        .allowed_ips(
                            peer.allowed_ips
                                .iter()
                                .map(|ip| set::AllowedIp {
                                    ipaddr: &ip.ipaddr,
                                    cidr_mask: Some(ip.cidr_mask),
                                })
                                .collect(),
                        );

                    dev_peer.preshared_key = peer.preshared_key.as_deref();
                    dev_peer.endpoint = peer.endpoint.as_ref();
                    dev_peer.persistent_keepalive_interval = peer.persistent_keepalive_interval;

                    dev_peer
                })
                .collect(),
        );

        dev.private_key = device.private_key.as_deref();
        dev.listen_port = device.listen_port;
        dev.fwmark = device.fwmark;

        match self.wgsocket.lock().await.set_device(dev) {
            Ok(_) => 0,
            Err(e) => {
                telio_log_error!("LinuxNativeWg: [SET01] {}", e);
                1
            }
        }
    }
}
