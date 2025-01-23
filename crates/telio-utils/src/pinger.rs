use socket2::Type;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use std::{convert::TryInto, net::IpAddr};
use surge_ping::{Client, Config as PingerConfig, PingIdentifier, PingSequence, ICMP};

use crate::{telio_log_debug, telio_log_error, DualTarget};

/// Information needed to check the reachability of endpoints.
///
/// Can be used with both IPv4 and IPv6 addresses.
pub struct Pinger {
    client_v4: Arc<Client>,
    client_v6: Option<Arc<Client>>,
    /// Number of tries
    pub no_of_tries: u32,
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

    /// Create new instance of `Ping`.
    ///
    /// # Arguments
    ///
    /// * `no_of_tries` - How many pings should be sent.
    pub fn new(no_of_tries: u32, ipv6: bool) -> std::io::Result<Self> {
        let client_v6 = if ipv6 {
            Some(Arc::new(Self::build_client(ICMP::V6)?))
        } else {
            None
        };

        Ok(Self {
            client_v4: Arc::new(Self::build_client(ICMP::V4)?),
            client_v6,
            no_of_tries,
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

        telio_log_debug!("Trying to ping {:?} host", host);

        let mut pinger = match host {
            IpAddr::V4(_) => {
                self.client_v4
                    .clone()
                    .pinger(host, PingIdentifier(rand::random()))
                    .await
            }
            IpAddr::V6(_) => {
                if let Some(client) = &self.client_v6 {
                    client
                        .clone()
                        .pinger(host, PingIdentifier(rand::random()))
                        .await
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
            match pinger
                .ping(PingSequence(i.try_into().unwrap_or(0)), &[0; 56])
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
        if cfg!(any(
            target_os = "ios",
            target_os = "macos",
            target_os = "tvos",
        )) {
            config_builder = config_builder.sock_type_hint(Type::RAW);
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
