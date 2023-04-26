use async_trait::async_trait;
use histogram::Histogram;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::Instant;

use tokio::time::{interval_at, Interval};

use telio_crypto::PublicKey;
use telio_task::{io::mc_chan, Runtime, RuntimeExt, WaitResponse};
use telio_wg::uapi::{AnalyticsEvent, PeerState};

use telio_utils::telio_log_debug;

use crate::config::QoSConfig;

use crate::rtt::ping::Ping;

/// Enum denoting ways to calculate RTT.
#[derive(Eq, PartialEq, Debug, Deserialize)]
pub enum RttType {
    /// Simple ping request.
    Ping,
}

/// Information about a node in the meshnet.
#[derive(Clone)]
pub struct NodeInfo {
    pub public_key: PublicKey,
    pub peer_state: PeerState,
    pub last_event: Instant,

    // Connection duration
    pub last_state_change: Instant,
    pub connected_time: u64,

    // RTT
    pub endpoint: IpAddr,
    pub rtt_histogram: Histogram,

    // Throughput
    pub last_tx_bytes: u64,
    pub last_rx_bytes: u64,
    pub tx_histogram: Histogram,
    pub rx_histogram: Histogram,
}

impl NodeInfo {
    fn update_throughput_info(&mut self, event: &AnalyticsEvent) {
        if let Some(duration) = event.timestamp.checked_duration_since(self.last_event) {
            let mut duration_as_seconds = duration.as_secs();
            if duration_as_seconds < 1 {
                duration_as_seconds = 1;
            }

            let current_tx = event.tx_bytes.saturating_sub(self.last_tx_bytes);
            let current_rx = event.rx_bytes.saturating_sub(self.last_rx_bytes);

            self.last_tx_bytes = event.tx_bytes;
            self.last_rx_bytes = event.rx_bytes;

            // If more than one second elapsed, split data across those seconds
            let tx_increment_value = current_tx / duration_as_seconds;
            let rx_increment_value = current_rx / duration_as_seconds;

            for _ in 0..duration_as_seconds {
                let _ = self.tx_histogram.increment(tx_increment_value);
                let _ = self.rx_histogram.increment(rx_increment_value);
            }
        };
    }

    fn update_connection_duration(&mut self, event: &AnalyticsEvent) {
        if self.peer_state != event.peer_state {
            // Connected -> Disconnected
            if self.peer_state == PeerState::Connected {
                // Connected time
                let duration = event
                    .timestamp
                    .checked_duration_since(self.last_state_change);
                telio_log_debug!("adding {:?} to connected_time", duration);
                self.connected_time += duration
                    .map(|duration| duration.as_secs())
                    .unwrap_or_default();
            }

            self.peer_state = event.peer_state;
            self.last_state_change = event.timestamp;
        }
    }
}

impl From<AnalyticsEvent> for NodeInfo {
    fn from(event: AnalyticsEvent) -> Self {
        Self {
            public_key: event.public_key,
            peer_state: event.peer_state,
            last_event: event.timestamp,
            last_state_change: event.timestamp,
            connected_time: 0,
            endpoint: event.endpoint.ip(),
            rtt_histogram: Histogram::new(),
            last_tx_bytes: 0,
            last_rx_bytes: 0,
            tx_histogram: Histogram::new(),
            rx_histogram: Histogram::new(),
        }
    }
}

/// QoS data.
#[derive(Default)]
pub struct OutputData {
    pub rtt: String,
    pub tx: String,
    pub rx: String,
    pub connection_duration: String,
}

impl OutputData {
    /// Create a new `OutputData` containing the contents of two `OutputData`
    pub fn merge(a: OutputData, b: OutputData) -> Self {
        OutputData {
            rtt: OutputData::merge_strings(a.rtt, b.rtt, ','),
            tx: OutputData::merge_strings(a.tx, b.tx, ','),
            rx: OutputData::merge_strings(a.rx, b.rx, ','),
            connection_duration: OutputData::merge_strings(
                a.connection_duration,
                b.connection_duration,
                ';',
            ),
        }
    }

    fn merge_strings(a: String, b: String, separator: char) -> String {
        let mut result = String::new();
        if a.is_empty() {
            result.push_str(&b);
        } else if b.is_empty() {
            result.push_str(&a);
        } else {
            result.push_str(&a);
            result.push(separator);
            result.push_str(&b);
        }
        result
    }
}

/// Wrapper for channel(s) to communicate with WireGuard.
pub struct Io {
    pub wg_channel: mc_chan::Rx<Box<AnalyticsEvent>>,
}

/// Analytics data about a meshnet.
pub struct Analytics {
    rtt_interval: Interval,
    io: Io,
    nodes: HashMap<PublicKey, NodeInfo>,
    ping_backend: Option<Ping>,
    buckets: u32,
}

#[async_trait]
impl Runtime for Analytics {
    const NAME: &'static str = "Nurse QoS Analytics";

    type Err = ();

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        tokio::select! {
            // Wireguard event
            Ok(wg_event) = self.io.wg_channel.recv() => {
                Self::guard(async move {
                    self.handle_wg_event(*wg_event).await;
                    Ok(())
                })
            },

            _ = self.rtt_interval.tick() => {
                Self::guard(async move {
                    self.perform_ping().await;
                    Ok(())
                })
            }
        }
    }
}

impl Analytics {
    /// Create empty analytics instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Config for QoS component.
    /// * `io` - Channel(s) for communicating with WireGuard.
    ///
    /// # Returns
    ///
    /// A new `Analytics` instance with the given configuration but with no nodes.
    pub fn new(config: QoSConfig, io: Io) -> Self {
        let ping_backend = if config.rtt_types.contains(&RttType::Ping) {
            Ping::new(config.rtt_tries).ok()
        } else {
            None
        };

        Self {
            rtt_interval: interval_at(tokio::time::Instant::now(), config.rtt_interval),
            io,
            nodes: HashMap::new(),
            ping_backend,
            buckets: config.buckets,
        }
    }

    /// Wrapper function around `Analytics::get_data_from_nodes_hashmap`.
    pub fn get_data(&mut self, sorted_public_keys_set: &BTreeSet<PublicKey>) -> OutputData {
        Analytics::get_data_from_nodes_hashmap(
            &mut self.nodes,
            self.buckets,
            sorted_public_keys_set,
        )
    }

    /// Get QoS data from the specified nodes in the meshnet.
    ///
    /// # Arguments
    ///
    /// * `nodes` - Nodes from which data should be gathered.
    /// * `buckets` - How many buckets the histogram should be sorted into.
    /// * `sorted_public_keys` - Keys corresponding to the nodes which should be selected.
    ///
    /// # Returns
    ///
    /// QoS data about the requested nodes
    pub fn get_data_from_nodes_hashmap(
        nodes: &mut HashMap<PublicKey, NodeInfo>,
        buckets: u32,
        sorted_public_keys: &BTreeSet<PublicKey>,
    ) -> OutputData {
        let mut output = OutputData::default();

        for key in sorted_public_keys {
            if let Some(node) = nodes.get(key) {
                // RTT
                output.rtt.push_str(&Analytics::percentile_histogram(
                    &node.rtt_histogram,
                    buckets,
                ));
                output.rtt.push(',');

                // Throughput
                output.tx.push_str(&Analytics::percentile_histogram(
                    &node.tx_histogram,
                    buckets,
                ));
                output.tx.push(',');

                output.rx.push_str(&Analytics::percentile_histogram(
                    &node.rx_histogram,
                    buckets,
                ));
                output.rx.push(',');

                // Connection duration
                let mut total_connected_time = node.connected_time;
                if node.peer_state == PeerState::Connected {
                    let duration = Instant::now().checked_duration_since(node.last_state_change);
                    telio_log_debug!(
                        "connected at the collection interval, adding: {:?}",
                        duration
                    );
                    total_connected_time += duration
                        .map(|duration| duration.as_secs())
                        .unwrap_or_default();
                }
                output
                    .connection_duration
                    .push_str(&total_connected_time.to_string());
                output.connection_duration.push(';');
            } else {
                output.rtt.push_str(&Analytics::empty_data(buckets));
                output.rtt.push(',');

                output.tx.push_str(&Analytics::empty_data(buckets));
                output.tx.push(',');

                output.rx.push_str(&Analytics::empty_data(buckets));
                output.rx.push(',');

                output.connection_duration.push_str("0;");
            }
        }

        // Pop the last ','
        output.rtt.pop();
        output.tx.pop();
        output.rx.pop();
        output.connection_duration.pop();

        output
    }

    /// Clear cached data
    pub fn reset_cached_data(&mut self) {
        // Clear cached data
        for node in self.nodes.values_mut() {
            // Keep the nodes, but clear the histograms
            node.rtt_histogram = Histogram::new();
            node.tx_histogram = Histogram::new();
            node.rx_histogram = Histogram::new();

            // Even if the state doesn't really change, reset connection duration info
            node.last_state_change = Instant::now();
            node.connected_time = 0;
        }
    }

    async fn handle_wg_event(&mut self, event: AnalyticsEvent) {
        telio_log_debug!("WG event: {:?}", event);
        self.nodes
            .entry(event.public_key)
            .and_modify(|n| {
                // Update current state
                n.update_connection_duration(&event);

                // Update rtt info
                n.endpoint = event.endpoint.ip();

                // Update throughput info
                n.update_throughput_info(&event);

                // Update last event timestamp
                n.last_event = event.timestamp;
            })
            .or_insert_with(|| NodeInfo::from(event));
    }

    async fn perform_ping(&mut self) {
        if let Some(pinger) = &self.ping_backend {
            for (_, node) in self.nodes.iter_mut() {
                pinger.perform(node).await;
            }
        }
    }

    /// Serialize a historgram to a string.
    ///
    /// # Arguments
    ///
    /// * `histogram` - The histogram to be serialized.
    /// * `buckets` - How many buckets the histogram should be divided into.
    ///
    /// # Returns
    ///
    /// The serialized version of the histogram, where the buckets are separated by colons.
    pub fn percentile_histogram(histogram: &Histogram, buckets: u32) -> String {
        let bucket_size = 100.00 / (buckets as f64);
        let mut current_step = bucket_size;
        let mut output = String::new();

        for _ in 0..buckets {
            output.push_str(
                &histogram
                    .percentile(current_step)
                    .unwrap_or_default()
                    .to_string(),
            );
            output.push(':');
            current_step += bucket_size;
        }

        // Pop the last ':'
        output.pop();
        output
    }

    fn empty_data(buckets: u32) -> String {
        let mut output = String::new();
        for _ in 0..buckets {
            output.push_str("0:");
        }
        // Pop lat ':'
        output.pop();
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use histogram::Histogram;
    use std::net::{IpAddr, Ipv4Addr};

    use telio_crypto::PublicKey;

    #[test]
    fn percentile() {
        let histogram = default_histogram();
        let empty = Histogram::new();

        let output_2_buckets = Analytics::percentile_histogram(&histogram, 2);
        assert_eq!(output_2_buckets, String::from("60:100"));

        let output_5_buckets = Analytics::percentile_histogram(&histogram, 5);
        assert_eq!(output_5_buckets, String::from("20:40:70:90:100"));

        let output_empty_histogram = Analytics::percentile_histogram(&empty, 5);
        assert_eq!(output_empty_histogram, String::from("0:0:0:0:0"));
    }

    #[test]
    fn data_format() {
        let a_public_key = PublicKey(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let b_public_key = PublicKey(*b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        let histogram = default_histogram();

        let a_node = dummy_node(&a_public_key, &histogram, 100);
        let b_node = dummy_node(&b_public_key, &histogram, 200);

        let mut hashmap = HashMap::new();
        hashmap.insert(a_public_key.clone(), a_node);
        hashmap.insert(b_public_key.clone(), b_node);

        let output = Analytics::get_data_from_nodes_hashmap(
            &mut hashmap,
            5,
            &BTreeSet::<PublicKey>::from([
                a_public_key,
                PublicKey(*b"ABBBBBBBBBBBBBBBBBBBAAAAAAAAAAAA"),
                b_public_key,
            ]),
        );

        let expected_output = OutputData {
            rtt: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            tx: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            rx: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            connection_duration: String::from("100;0;200"),
        };

        assert_eq!(output.rtt, expected_output.rtt);
        assert_eq!(output.tx, expected_output.tx);
        assert_eq!(output.rx, expected_output.rx);
        assert_eq!(
            output.connection_duration,
            expected_output.connection_duration
        );
    }

    fn default_histogram() -> Histogram {
        let mut a = Histogram::new();
        for i in 1..11 {
            a.increment(i * 10).unwrap();
        }
        a
    }

    fn dummy_node(public_key: &PublicKey, histogram: &Histogram, connected_time: u64) -> NodeInfo {
        NodeInfo {
            public_key: public_key.clone(),
            peer_state: PeerState::Disconnected,
            last_event: Instant::now(),
            last_state_change: Instant::now(),
            connected_time,
            endpoint: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            rtt_histogram: histogram.clone(),
            last_rx_bytes: 0,
            last_tx_bytes: 0,
            tx_histogram: histogram.clone(),
            rx_histogram: histogram.clone(),
        }
    }
}
