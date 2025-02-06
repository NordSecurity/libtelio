use socket2::Type;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use std::{convert::TryInto, net::IpAddr};
use surge_ping::{Client, Config as PingerConfig, PingIdentifier, PingSequence, ICMP};

use telio_sockets::SocketPool;
use telio_utils::{telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn, DualTarget};

const PING_PAYLOAD_SIZE: usize = 56;

/// Information needed to check the reachability of endpoints.
///
/// Can be used with both IPv4 and IPv6 addresses.
#[derive(Clone)]
pub struct Pinger {
    client_v4: Arc<Client>,
    client_v6: Option<Arc<Client>>,
    /// Number of tries
    pub no_of_tries: u32,
    socket_pool: Arc<SocketPool>,
}

/// Information gathered after a ping action
#[derive(Debug, Default, Clone)]
pub struct PingResults {
    /// The pinged host address
    pub host: Option<IpAddr>,
    /// Number of successful pings
    pub successful_pings: u32,
    /// Number of failed pings
    pub unsuccessful_pings: u32,
    /// The average RTT
    pub avg_rtt: Option<Duration>,
}

/// Information gathered after a ping action to a DualTarget
#[derive(Clone, Debug, Default)]
pub struct DualPingResults {
    /// The results for the IPv4 address
    pub v4: Option<PingResults>,
    /// The results for the IPv6 address
    pub v6: Option<PingResults>,
}

impl Pinger {
    const PING_TIMEOUT: Duration = Duration::from_secs(5);

    /// Create new instance of `Ping` with a socket pool.
    /// For performing pings inside of the tunnel.
    ///
    /// # Arguments
    ///
    /// * `no_of_tries` - How many pings should be sent.
    /// * `ipv6` - Enable IPv6 support.
    /// * `socket_pool` - SocketPool used to protect the sockets.
    pub fn new(
        no_of_tries: u32,
        ipv6: bool,
        socket_pool: Arc<SocketPool>,
    ) -> std::io::Result<Self> {
        let client_v6 = if ipv6 {
            let client_v6 = Arc::new(Self::build_client(ICMP::V6)?);
            telio_log_trace!("Making pinger IPv6 socket internal");
            socket_pool.make_internal(client_v6.get_socket().get_native_sock())?;
            Some(client_v6)
        } else {
            None
        };

        let client_v4 = Arc::new(Self::build_client(ICMP::V4)?);
        telio_log_trace!("Making pinger IPv4 socket internal");
        socket_pool.make_internal(client_v4.get_socket().get_native_sock())?;

        Ok(Self {
            client_v4,
            client_v6,
            no_of_tries,
            socket_pool,
        })
    }

    /// Perform the configured number of pings against the endpoint specified in the argument node.
    ///
    /// # Arguments
    ///
    /// * `target` - `DualTarget` instance representing the target node.
    pub async fn perform(&self, target: DualTarget) -> DualPingResults {
        let dpr = self.perform_average_rtt(&target).await;
        telio_log_debug!("{:?}, no_of_tries: {}", dpr, self.no_of_tries);

        dpr
    }

    async fn perform_average_rtt(&self, target: &DualTarget) -> DualPingResults {
        let mut dpresults = DualPingResults::default();

        match target.get_targets() {
            Ok(t) => {
                match t.0 {
                    IpAddr::V4(_) => {
                        dpresults.v4 = self.ping_action(t.0).await;
                    }
                    IpAddr::V6(_) => {
                        dpresults.v6 = self.ping_action(t.0).await;
                    }
                }

                if let Some(secondary) = t.1 {
                    match secondary {
                        IpAddr::V4(_) => {
                            dpresults.v4 = self.ping_action(secondary).await;
                        }
                        IpAddr::V6(_) => {
                            dpresults.v6 = self.ping_action(secondary).await;
                        }
                    }
                }
            }
            Err(_) => {
                telio_log_error!("No target to ping");
            }
        }

        dpresults
    }

    async fn ping_action(&self, host: IpAddr) -> Option<PingResults> {
        let mut results = PingResults {
            host: Some(host),
            ..Default::default()
        };

        let ping_id = PingIdentifier(rand::random());
        telio_log_debug!("Trying to ping {:?} host, {:#06x}", host, ping_id.0);

        let (mut pinger, socket) = match host {
            IpAddr::V4(_) => (
                self.client_v4.pinger(host, ping_id).await,
                self.client_v4.get_socket().get_native_sock(),
            ),
            IpAddr::V6(_) => {
                if let Some(client) = &self.client_v6 {
                    (
                        client.pinger(host, ping_id).await,
                        client.get_socket().get_native_sock(),
                    )
                } else {
                    return None;
                }
            }
        };

        pinger.timeout(Self::PING_TIMEOUT);
        #[cfg(test)]
        pinger.timeout(Duration::from_millis(10));

        let mut sum = Duration::default();

        for i in 0..self.no_of_tries {
            // This is a temporary solution for iOS due to NECP re-binding the socket to
            // the main interface after every write, refer to LLT-5886
            //
            // TODO: LLT-5991: Refactor writing ICMP packets directly into the tunnel
            if cfg!(any(target_os = "ios", target_os = "tvos")) {
                telio_log_trace!("Making pinger socket internal");
                if let Err(e) = self.socket_pool.make_internal(socket) {
                    telio_log_warn!("Failed to make socket internal, error: {:?}", e);
                }
            }

            match pinger
                .ping(
                    PingSequence(i.try_into().unwrap_or(0)),
                    &[0; PING_PAYLOAD_SIZE],
                )
                .await
            {
                Ok((_, duration)) => {
                    sum = sum.saturating_add(duration);
                    results.successful_pings += 1;
                }
                Err(e) => {
                    results.unsuccessful_pings += 1;
                    telio_log_debug!("Ping {} error: {}", host, e.to_string());
                }
            }
        }

        results.avg_rtt = sum.checked_div(results.successful_pings);
        Some(results)
    }

    fn build_client(proto: ICMP) -> std::io::Result<Client> {
        let mut config_builder = PingerConfig::builder().kind(proto);
        if cfg!(target_os = "macos") {
            config_builder = config_builder.sock_type_hint(Type::RAW);
        }
        // Raw sockets are not allowed on iOS, instead use
        // socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        if cfg!(any(target_os = "ios", target_os = "tvos")) {
            config_builder = config_builder.sock_type_hint(Type::DGRAM);
        }
        if cfg!(not(target_os = "android")) {
            match proto {
                ICMP::V4 => {
                    config_builder = config_builder.bind((Ipv4Addr::UNSPECIFIED, 0).into());
                }
                ICMP::V6 => {
                    config_builder = config_builder.bind((Ipv6Addr::UNSPECIFIED, 0).into());
                }
            }
        }
        Client::new(&config_builder.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telio_sockets::protector::MockProtector;

    // Basic constructor test
    #[tokio::test]
    async fn test_pinger_new_v6_sock_pool() {
        let mut protect = MockProtector::default();
        protect.expect_make_internal().returning(|_| Ok(()));

        let pinger = Pinger::new(1, true, Arc::new(SocketPool::new(protect)))
            .expect("Failed to create Pinger");
        assert!(pinger.client_v4.get_socket().get_native_sock() > 0);
        assert!(pinger.client_v6.is_some());
        assert_eq!(pinger.no_of_tries, 1);
    }

    // Basic ping test
    #[tokio::test]
    async fn test_ping_localhost() {
        let mut protect = MockProtector::default();
        protect.expect_make_internal().returning(|_| Ok(()));

        let pinger = Pinger::new(2, false, Arc::new(SocketPool::new(protect)))
            .expect("Failed to create Pinger");

        let target =
            DualTarget::new(("127.0.0.1".parse().ok(), None)).expect("Failed to create target");

        let result = pinger.perform(target).await;
        assert!(
            result.v4.unwrap().successful_pings > 0,
            "Expected at least one successful ping to 127.0.0.1"
        );
        assert!(result.v6.is_none());
    }
}
