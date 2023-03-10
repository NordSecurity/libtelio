use std::sync::Arc;
use std::time::Duration;
use std::{convert::TryInto, net::IpAddr};
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};

use crate::qos::NodeInfo;

/// Information needed to check the reachability of endpoints.
///
/// Can be used with both IPv4 and IPv6 addresses.
pub struct Ping {
    client_v4: Arc<Client>,
    client_v6: Arc<Client>,
    no_of_tries: u32,
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
        let avg = self.perform_average_rtt(node.endpoint).await;

        if let Some(avg) = avg {
            let u64_avg = avg.as_millis().try_into().unwrap_or(0u64);
            let _ = node.rtt_histogram.increment(u64_avg);
        }
    }

    async fn perform_average_rtt(&self, node: IpAddr) -> Option<Duration> {
        let client = match node {
            IpAddr::V4(_) => self.client_v4.clone(),
            IpAddr::V6(_) => self.client_v6.clone(),
        };

        let mut pinger = client.pinger(node, PingIdentifier(rand::random())).await;
        let payload = [0; 56];
        pinger.timeout(Self::PING_TIMEOUT);

        let mut sum = Duration::default();
        let mut successful_pings = 0;

        for i in 0..self.no_of_tries {
            if let Ok((_, duration)) = pinger
                .ping(PingSequence(i.try_into().unwrap_or(0)), &payload)
                .await
            {
                sum = sum.saturating_add(duration);
                successful_pings += 1;
            } else {
                // TODO: Log error
            }
        }

        sum.checked_div(successful_pings)
    }
}
