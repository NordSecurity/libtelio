use std::sync::Arc;
use std::time::Duration;
use std::{convert::TryInto, net::IpAddr};
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use telio_utils::{telio_log_debug, telio_log_error, DualTarget};

use crate::qos::NodeInfo;

/// Information needed to check the reachability of endpoints.
///
/// Can be used with both IPv4 and IPv6 addresses.
pub struct Ping {
    client_v4: Arc<Client>,
    client_v6: Arc<Client>,
    no_of_tries: u32,
}

#[derive(Debug, Clone)]
struct PingResults {
    successful_pings: u32,
    unsuccessful_pings: u32,
    avg_rtt: Option<Duration>,
}

#[derive(Debug)]
struct DualPingResults {
    v4: Option<PingResults>,
    v6: Option<PingResults>,
}

impl Ping {
    const PING_TIMEOUT: Duration = Duration::from_secs(5);

    /// Create new instance of `Ping`.
    ///
    /// # Arguments
    ///
    /// * `no_of_tries` - How many pings should be sent.
    pub fn new(no_of_tries: u32) -> std::io::Result<Self> {
        Ok(Self {
            client_v4: Arc::new(Client::new(&Config::default())?),
            client_v6: Arc::new(Client::new(&Config::builder().kind(ICMP::V6).build())?),
            no_of_tries,
        })
    }

    /// Perform the configured number of pings against the endpoint specified in the argument node.
    ///
    /// # Arguments
    ///
    /// * `node` - `NodeInfo` instance to get endpoint to ping and to store RTT information.
    pub async fn perform(&self, node: &mut NodeInfo) {
        // TODO this needs some refinement
        let dpr = self.perform_average_rtt(&node.endpoint).await;

        telio_log_debug!(
            "Ping results: {:?}, no_of_tries: {:?}",
            dpr,
            self.no_of_tries
        );

        if let Some(results_v4) = dpr.v4 {
            let u64_avg = results_v4
                .avg_rtt
                .map_or(Duration::from_millis(0), |a| a)
                .as_millis()
                .try_into()
                .unwrap_or(0u64);
            let _ = node.rtt_histogram.increment(u64_avg);
            let _ = node
                .rtt_loss_histogram
                .increment((100 * results_v4.unsuccessful_pings / self.no_of_tries) as u64);
        }

        if let Some(results_v6) = dpr.v6 {
            let u64_avg = results_v6
                .avg_rtt
                .map_or(Duration::from_millis(0), |a| a)
                .as_millis()
                .try_into()
                .unwrap_or(0u64);
            let _ = node.rtt6_histogram.increment(u64_avg);
            let _ = node
                .rtt6_loss_histogram
                .increment((100 * results_v6.unsuccessful_pings / self.no_of_tries) as u64);
        }
    }

    async fn perform_average_rtt(&self, target: &DualTarget) -> DualPingResults {
        let mut dpresults = DualPingResults { v4: None, v6: None };

        let ping_action = |client: Arc<Client>, host| async move {
            let mut results = PingResults {
                successful_pings: 0,
                unsuccessful_pings: 0,
                avg_rtt: None,
            };
            let mut pinger = client.pinger(host, PingIdentifier(rand::random())).await;
            let payload = [0; 56];
            pinger.timeout(Self::PING_TIMEOUT);

            let mut sum = Duration::default();

            for i in 0..self.no_of_tries {
                if let Ok((_, duration)) = pinger
                    .ping(PingSequence(i.try_into().unwrap_or(0)), &payload)
                    .await
                {
                    sum = sum.saturating_add(duration);
                    results.successful_pings += 1;
                } else {
                    results.unsuccessful_pings += 1;
                }
            }

            results.avg_rtt = sum.checked_div(results.successful_pings);
            results
        };

        match target.get_targets() {
            Ok(t) => {
                match t.0 {
                    IpAddr::V4(_) => {
                        dpresults.v4 = Some(ping_action(self.client_v4.clone(), t.0).await);
                    }
                    IpAddr::V6(_) => {
                        dpresults.v6 = Some(ping_action(self.client_v6.clone(), t.0).await);
                    }
                }

                if let Some(secondary) = t.1 {
                    match secondary {
                        IpAddr::V4(_) => {
                            dpresults.v4 = Some(ping_action(self.client_v4.clone(), t.0).await);
                        }
                        IpAddr::V6(_) => {
                            dpresults.v6 = Some(ping_action(self.client_v6.clone(), t.0).await);
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
}
