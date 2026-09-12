//! Active tunnel health check with automatic exit node switching.
//!
//! Every `interval_seconds` a TCP connection to one of `probe_targets` is opened through
//! the tunnel interface. When none succeeds, the same probe goes out through the uplink:
//! a working uplink means the tunnel itself is broken, while a dead uplink is nothing a
//! server switch could fix, so the failure count resets instead of growing. That
//! comparison keeps an ISP outage from causing pointless server churn.
//!
//! After `failure_threshold` consecutive broken-tunnel probes, the daemon switches to the
//! next server from the list fetched at startup. The API is not queried again: with exit
//! routing in place, its requests would be routed into the tunnel that is down.

use std::{net::SocketAddr, time::Duration};

use futures::future::select_ok;
use tokio::{net::TcpSocket, sync::mpsc, time};
use tracing::{debug, error, info, warn};

use crate::{
    command_listener::{ExitNodeConfig, TelioTaskCmd, TIMEOUT_SEC},
    config::{Endpoint, NordVpnLiteConfig},
    interface::read_default_route_device,
};

/// Monitor the tunnel until the telio task's command channel closes.
///
/// `servers` is the list the current connection was chosen from; its first entry is the
/// server in use.
pub(crate) async fn run(
    config: &NordVpnLiteConfig,
    servers: Vec<Endpoint>,
    telio_tx: mpsc::Sender<TelioTaskCmd>,
) {
    let health_check = &config.health_check;
    if health_check.probe_targets.is_empty() {
        error!("Health check not started: probe_targets is empty");
        return;
    }
    let mut rotation = Rotation::new(servers);
    if rotation.is_empty() {
        warn!("Health check not started: no servers to switch between");
        return;
    }

    let tunnel = config.interface.name.as_str();
    let interval = Duration::from_secs(health_check.interval_seconds.max(1));
    let probe_timeout = Duration::from_secs(health_check.probe_timeout_seconds.max(1));
    let settle = Duration::from_secs(health_check.settle_seconds);
    let threshold = health_check.failure_threshold.max(1);

    info!(
        "Health check started on {tunnel}: probing every {interval:?}, switching after {threshold} consecutive failures ({} servers)",
        rotation.len()
    );

    let mut failures = 0;
    let mut uplink_down = false;
    time::sleep(settle).await;

    while !telio_tx.is_closed() {
        time::sleep(interval).await;

        if probe(tunnel, &health_check.probe_targets, probe_timeout).await {
            if failures > 0 || uplink_down {
                info!("Tunnel probe through {tunnel} succeeded again");
            }
            failures = 0;
            uplink_down = false;
            continue;
        }

        let uplink = health_check
            .wan_interface
            .clone()
            .or_else(read_default_route_device);
        let uplink_ok = match uplink.as_deref() {
            Some(device) => probe(device, &health_check.probe_targets, probe_timeout).await,
            None => false,
        };
        let uplink = uplink.as_deref().unwrap_or("<no default route>");

        if !uplink_ok {
            if !uplink_down {
                warn!("Tunnel probe failed, but uplink {uplink} is unreachable too; not switching servers");
                uplink_down = true;
            }
            failures = 0;
            continue;
        }
        uplink_down = false;

        failures += 1;
        warn!("Tunnel probe through {tunnel} failed while uplink {uplink} works ({failures}/{threshold})");
        if failures < threshold {
            continue;
        }
        failures = 0;

        let Some(endpoint) = rotation.next_server() else {
            error!("Health check has no server to switch to");
            continue;
        };
        info!(
            "Switching exit node to {} [{}]",
            endpoint.address,
            endpoint.hostname.as_deref().unwrap_or_default()
        );
        let command = TelioTaskCmd::SwitchExitNode(ExitNodeConfig {
            endpoint,
            dns: config.dns.clone(),
            post_quantum: config.post_quantum,
        });
        if let Err(e) = telio_tx
            .send_timeout(command, Duration::from_secs(TIMEOUT_SEC))
            .await
        {
            error!("Failed to request exit node switch: {e}");
        }
        time::sleep(settle).await;
    }

    debug!("Health check stopped");
}

/// Cycles through the server list, starting after the entry currently in use.
struct Rotation {
    servers: Vec<Endpoint>,
    next: usize,
}

impl Rotation {
    fn new(servers: Vec<Endpoint>) -> Self {
        // Entry 0 is the server the daemon connected to at startup.
        Self { servers, next: 1 }
    }

    fn len(&self) -> usize {
        self.servers.len()
    }

    fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// The next server, wrapping around; `None` only for an empty list. With a single
    /// server (a fixed `vpn.server`) this keeps returning it, which reconnects to it.
    fn next_server(&mut self) -> Option<Endpoint> {
        let len = self.servers.len();
        if len == 0 {
            return None;
        }
        let index = self.next % len;
        self.next = index + 1;
        self.servers.get(index).cloned()
    }
}

/// Whether any of `targets` accepts a TCP connection through `interface` within `timeout`.
async fn probe(interface: &str, targets: &[SocketAddr], timeout: Duration) -> bool {
    if targets.is_empty() {
        return false;
    }
    let attempts = targets
        .iter()
        .map(|target| Box::pin(connect_through(interface, *target)));
    match time::timeout(timeout, select_ok(attempts)).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            debug!("Probe through {interface} failed: {e}");
            false
        }
        Err(_) => {
            debug!("Probe through {interface} timed out after {timeout:?}");
            false
        }
    }
}

/// Open, then immediately drop, a TCP connection to `target` bound to `interface`.
async fn connect_through(interface: &str, target: SocketAddr) -> std::io::Result<()> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // SO_BINDTODEVICE, as used by `ping -I`: the connection can only leave through
    // `interface`, whatever the policy routing rules would otherwise pick.
    socket.bind_device(Some(interface.as_bytes()))?;
    socket.connect(target).await.map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use telio_core::crypto::PublicKey;
    use tokio::net::TcpListener;

    fn server(hostname: &str) -> Endpoint {
        Endpoint {
            address: Ipv4Addr::LOCALHOST.into(),
            public_key: PublicKey::default(),
            hostname: Some(hostname.to_owned()),
        }
    }

    fn hostnames(rotation: &mut Rotation, count: usize) -> Vec<Option<String>> {
        (0..count)
            .map(|_| rotation.next_server().and_then(|s| s.hostname))
            .collect()
    }

    fn some(names: &[&str]) -> Vec<Option<String>> {
        names.iter().map(|n| Some((*n).to_owned())).collect()
    }

    #[test]
    fn rotation_starts_after_the_server_in_use_and_wraps() {
        let mut rotation = Rotation::new(vec![server("a"), server("b"), server("c")]);
        assert_eq!(hostnames(&mut rotation, 4), some(&["b", "c", "a", "b"]));
    }

    #[test]
    fn rotation_with_a_single_server_reconnects_to_it() {
        let mut rotation = Rotation::new(vec![server("a")]);
        assert_eq!(hostnames(&mut rotation, 2), some(&["a", "a"]));
    }

    #[test]
    fn rotation_without_servers_yields_nothing() {
        let mut rotation = Rotation::new(Vec::new());
        assert!(rotation.is_empty());
        assert!(rotation.next_server().is_none());
    }

    #[tokio::test]
    async fn probe_without_targets_fails() {
        assert!(!probe("lo", &[], Duration::from_secs(1)).await);
    }

    /// Binding to a device can require CAP_NET_RAW; skip rather than fail where denied.
    fn can_bind_device() -> bool {
        let allowed = TcpSocket::new_v4()
            .and_then(|socket| socket.bind_device(Some(b"lo")))
            .is_ok();
        if !allowed {
            eprintln!("skipping: binding a socket to a device is not permitted here");
        }
        allowed
    }

    #[tokio::test]
    async fn probe_succeeds_when_any_target_accepts() {
        if !can_bind_device() {
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let closed = {
            let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
            unused.local_addr().unwrap()
        };

        assert!(probe("lo", &[closed, open], Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn probe_fails_when_no_target_accepts() {
        if !can_bind_device() {
            return;
        }
        let closed = {
            let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
            unused.local_addr().unwrap()
        };

        assert!(!probe("lo", &[closed], Duration::from_secs(2)).await);
    }
}
