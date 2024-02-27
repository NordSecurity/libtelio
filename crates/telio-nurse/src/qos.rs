use async_trait::async_trait;
use histogram::Histogram;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::time::{interval_at, Duration, Interval, MissedTickBehavior};

use telio_crypto::PublicKey;
use telio_task::{io::mc_chan, Runtime, RuntimeExt, WaitResponse};
use telio_wg::uapi::{AnalyticsEvent, PeerState};

use telio_utils::{telio_log_debug, telio_log_trace, DualTarget};

use crate::config::QoSConfig;

use crate::rtt::ping::{DualPingResults, Ping};

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
    pub last_wg_event: Instant,
    pub connected_time: Duration,

    // RTT
    pub ip_addresses: Vec<DualTarget>,
    pub rtt_histogram: Histogram,
    pub rtt_loss_histogram: Histogram,
    pub rtt6_histogram: Histogram,
    pub rtt6_loss_histogram: Histogram,

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

    fn update_connection_duration(&mut self, event: &AnalyticsEvent, pause: bool) {
        if self.peer_state == PeerState::Connected && !pause {
            // Connected time
            let duration = event.timestamp.checked_duration_since(self.last_wg_event);
            self.connected_time += duration.unwrap_or_default();
        }

        self.peer_state = event.peer_state;
        self.last_wg_event = event.timestamp;
    }
}

impl From<AnalyticsEvent> for NodeInfo {
    fn from(event: AnalyticsEvent) -> Self {
        Self {
            public_key: event.public_key,
            peer_state: event.peer_state,
            last_event: event.timestamp,
            last_wg_event: event.timestamp,
            connected_time: Duration::default(),
            ip_addresses: event.dual_ip_addresses,
            rtt_histogram: Histogram::new(),
            rtt_loss_histogram: Histogram::new(),
            rtt6_histogram: Histogram::new(),
            rtt6_loss_histogram: Histogram::new(),
            last_tx_bytes: 0,
            last_rx_bytes: 0,
            tx_histogram: Histogram::new(),
            rx_histogram: Histogram::new(),
        }
    }
}

/// QoS data.
#[derive(Debug, Default, PartialEq)]
pub struct OutputData {
    pub rtt: String,
    pub rtt_loss: String,
    pub rtt6: String,
    pub rtt6_loss: String,
    pub tx: String,
    pub rx: String,
    pub connection_duration: String,
}

impl OutputData {
    /// Create an empty `OutputData`
    #[allow(dead_code)]
    pub fn new(buckets: u32) -> Self {
        OutputData {
            rtt: Analytics::empty_data(buckets),
            rtt_loss: Analytics::empty_data(buckets),
            rtt6: Analytics::empty_data(buckets),
            rtt6_loss: Analytics::empty_data(buckets),
            tx: Analytics::empty_data(buckets),
            rx: Analytics::empty_data(buckets),
            connection_duration: String::from("0"),
        }
    }

    /// Create a new `OutputData` containing the contents of two `OutputData`
    pub fn merge(a: OutputData, b: OutputData) -> Self {
        OutputData {
            rtt: OutputData::merge_strings(a.rtt, b.rtt, ','),
            rtt_loss: OutputData::merge_strings(a.rtt_loss, b.rtt_loss, ','),
            rtt6: OutputData::merge_strings(a.rtt6, b.rtt6, ','),
            rtt6_loss: OutputData::merge_strings(a.rtt6_loss, b.rtt6_loss, ','),
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
    ping_backend: Arc<Option<Ping>>,
    ping_channel_rx: mpsc::Receiver<(PublicKey, DualPingResults)>,
    ping_channel_tx: mpsc::WeakSender<(PublicKey, DualPingResults)>,
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
                    self.handle_wg_event(&wg_event).await;
                    Ok(())
                })
            },

            _ = self.rtt_interval.tick(), if self.ping_channel_tx.upgrade().is_none() => {
                self.perform_ping();
                Self::next()
            },

            Some(node_ping_res) = self.ping_channel_rx.recv() => {
                Self::guard(async move {
                    self.process_node_ping_results(node_ping_res);
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
        let (ping_channel_tx, ping_channel_rx) = mpsc::channel(1);

        let ping_backend = if config.rtt_types.contains(&RttType::Ping) {
            Arc::new(Ping::new(config.rtt_tries).ok())
        } else {
            Arc::new(None)
        };
        let mut rtt_interval = interval_at(tokio::time::Instant::now(), config.rtt_interval);
        rtt_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        Self {
            rtt_interval,
            io,
            nodes: HashMap::new(),
            ping_backend,
            ping_channel_rx,
            ping_channel_tx: ping_channel_tx.downgrade(),
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

                output.rtt_loss.push_str(&Analytics::percentile_histogram(
                    &node.rtt_loss_histogram,
                    buckets,
                ));
                output.rtt_loss.push(',');

                output.rtt6.push_str(&Analytics::percentile_histogram(
                    &node.rtt6_histogram,
                    buckets,
                ));
                output.rtt6.push(',');

                output.rtt6_loss.push_str(&Analytics::percentile_histogram(
                    &node.rtt6_loss_histogram,
                    buckets,
                ));
                output.rtt6_loss.push(',');

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

                output
                    .connection_duration
                    .push_str(&node.connected_time.as_secs().to_string());
                output.connection_duration.push(';');
            } else {
                output.rtt.push_str(&Analytics::empty_data(buckets));
                output.rtt.push(',');

                output.rtt_loss.push_str(&Analytics::empty_data(buckets));
                output.rtt_loss.push(',');

                output.rtt6.push_str(&Analytics::empty_data(buckets));
                output.rtt6.push(',');

                output.rtt6_loss.push_str(&Analytics::empty_data(buckets));
                output.rtt6_loss.push(',');

                output.tx.push_str(&Analytics::empty_data(buckets));
                output.tx.push(',');

                output.rx.push_str(&Analytics::empty_data(buckets));
                output.rx.push(',');

                output.connection_duration.push_str("0;");
            }
        }

        // Pop the last ','
        output.rtt.pop();
        output.rtt_loss.pop();
        output.rtt6.pop();
        output.rtt6_loss.pop();
        output.tx.pop();
        output.rx.pop();
        output.connection_duration.pop();

        output
    }

    /// Clear cached data.
    pub fn reset_cached_data(&mut self) {
        for node in self.nodes.values_mut() {
            // Keep the nodes, but clear the histograms
            node.rtt_histogram = Histogram::new();
            node.rtt_loss_histogram = Histogram::new();
            node.rtt6_histogram = Histogram::new();
            node.rtt6_loss_histogram = Histogram::new();
            node.tx_histogram = Histogram::new();
            node.rx_histogram = Histogram::new();
            node.connected_time = Duration::default();
        }
    }

    /// Update peer data from a received WG event.
    /// # Arguments
    ///
    /// * `event` - Received WG event.
    async fn handle_wg_event(&mut self, event: &AnalyticsEvent) {
        telio_log_trace!("WG event: {:?}", event);
        self.nodes
            .entry(event.public_key)
            .and_modify(|n| {
                // Check if peer was not paused
                let pause: bool = (event.timestamp - n.last_event).as_secs() > 10;
                // Update current state
                n.update_connection_duration(event, pause);
                // Update rtt info (mesh address)
                n.ip_addresses = event.dual_ip_addresses.clone();
                // Update throughput info
                n.update_throughput_info(event);
                // Update last event timestamp
                n.last_event = event.timestamp;
            })
            .or_insert_with(|| NodeInfo::from(event.clone()));
    }

    /// Launch ping task for every node.
    fn perform_ping(&mut self) {
        if !self.nodes.is_empty() {
            let (ping_channel_tx, ping_channel_rx) = mpsc::channel(self.nodes.len());
            self.ping_channel_rx = ping_channel_rx;
            self.ping_channel_tx = ping_channel_tx.downgrade();

            for (_, node) in self.nodes.iter() {
                if node.peer_state != PeerState::Connected {
                    telio_log_debug!(
                        "{:?} is in {:?} state, skipping analytics ping.",
                        node.public_key,
                        node.peer_state
                    );
                    continue;
                }

                let (pk, ip_addresses) = (node.public_key, node.ip_addresses.clone());
                let pinger = Arc::clone(&self.ping_backend);
                let ping_channel_tx = ping_channel_tx.clone();

                tokio::spawn(async move {
                    if let Some(pinger) = &*pinger {
                        let mut dpr = DualPingResults::default();
                        let mut ip_addresses = ip_addresses.iter().peekable();

                        while let Some(ip_address) = ip_addresses.next() {
                            dpr = Box::pin(pinger.perform((pk, *ip_address))).await;

                            if let Some(results_v4) = &dpr.v4 {
                                if results_v4.successful_pings != 0 {
                                    break;
                                }
                            }
                            if let Some(results_v6) = &dpr.v6 {
                                if results_v6.successful_pings != 0 {
                                    break;
                                }
                            }

                            if let Some(next_ip) = ip_addresses.peek() {
                                let _ = ping_channel_tx.send((pk, dpr.clone())).await;
                                telio_log_debug!(
                                    "Node was not reachable through {:?}, trying {:?}.",
                                    ip_address,
                                    next_ip
                                );
                            }
                        }

                        let _ = ping_channel_tx.send((pk, dpr)).await;
                    }
                });
            }
        }
    }

    fn process_node_ping_results(&mut self, dpr: (PublicKey, DualPingResults)) {
        if let Some(pinger) = &*self.ping_backend {
            self.nodes.entry(dpr.0).and_modify(|node| {
                if let Some(results_v4) = dpr.1.v4 {
                    let rtt_avg = std::convert::TryInto::try_into(
                        results_v4
                            .avg_rtt
                            .map_or(Duration::from_millis(0), |a| a)
                            .as_millis(),
                    )
                    .unwrap_or(0u64);
                    let rtt_loss =
                        (100 * results_v4.unsuccessful_pings / pinger.no_of_tries) as u64;

                    let _ = node.rtt_histogram.increment(rtt_avg);
                    let _ = node.rtt_loss_histogram.increment(rtt_loss);
                }

                if let Some(results_v6) = dpr.1.v6 {
                    let u64_avg = std::convert::TryInto::try_into(
                        results_v6
                            .avg_rtt
                            .map_or(Duration::from_millis(0), |a| a)
                            .as_millis(),
                    )
                    .unwrap_or(0u64);
                    let _ = node.rtt6_histogram.increment(u64_avg);
                    let _ = node.rtt6_loss_histogram.increment(
                        (100 * results_v6.unsuccessful_pings / pinger.no_of_tries) as u64,
                    );
                }
            });
        }
    }

    /// Serialize a histogram to a string.
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
        // Pop last ':'
        output.pop();
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use histogram::Histogram;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use telio_task::io::McChan;

    use telio_crypto::{PublicKey, SecretKey};

    #[test]
    fn test_percentile() {
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
    fn test_data_format() {
        let a_public_key = PublicKey(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let b_public_key = PublicKey(*b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        let histogram = default_histogram();

        let a_node = dummy_node(a_public_key, &histogram, Duration::from_secs(100));
        let b_node = dummy_node(b_public_key, &histogram, Duration::from_secs(200));

        let mut hashmap = HashMap::new();
        hashmap.insert(a_public_key, a_node);
        hashmap.insert(b_public_key, b_node);

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
            rtt_loss: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            rtt6: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            rtt6_loss: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            tx: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            rx: String::from("20:40:70:90:100,0:0:0:0:0,20:40:70:90:100"),
            connection_duration: String::from("100;0;200"),
        };

        assert_eq!(output, expected_output);
    }

    #[tokio::test]
    async fn test_handle_new_wg_event() {
        let mut analytics = setup();
        let mut event = generate_event();

        // assert that node is inserted successfully
        analytics.handle_wg_event(&event).await;
        let node = analytics.nodes.get(&event.public_key).unwrap();

        assert_eq!(analytics.nodes.len(), 1);
        assert_eq!(node.public_key, event.public_key);
        assert_eq!(node.peer_state, PeerState::Connected);
        assert_eq!(node.last_event, event.timestamp);
        assert_eq!(node.last_wg_event, event.timestamp);
        assert_eq!(node.ip_addresses, event.dual_ip_addresses);

        // histograms should be empty
        let mut expected_output = OutputData::new(analytics.buckets);
        let output = analytics.get_data(&BTreeSet::<PublicKey>::from([event.public_key]));

        assert_eq!(output, expected_output);

        // update node with different data
        event.timestamp += Duration::from_secs(2);
        event.dual_ip_addresses = vec![DualTarget::new((
            Some(Ipv4Addr::new(192, 168, 1, 1)),
            Some(Ipv6Addr::new(0xfc02, 0, 0, 0, 0, 0, 0, 0x01)),
        ))
        .unwrap()];
        event.peer_state = PeerState::Disconnected;
        event.tx_bytes = 10;
        event.rx_bytes = 20;

        analytics.handle_wg_event(&event).await;
        let node = analytics.nodes.get(&event.public_key).unwrap();

        assert_eq!(analytics.nodes.len(), 1);
        assert_eq!(node.public_key, event.public_key);
        assert_eq!(node.peer_state, PeerState::Disconnected);
        assert_eq!(node.last_event, event.timestamp);
        assert_eq!(node.last_wg_event, event.timestamp);
        assert_eq!(node.ip_addresses, event.dual_ip_addresses);
        assert_eq!(node.connected_time, Duration::from_secs(2));

        // throughput in B/sec, so it's split by half as connected time is 2s
        expected_output.tx = "5:5:5:5:5".to_owned();
        expected_output.rx = "10:10:10:10:10".to_owned();
        expected_output.connection_duration = "2".to_owned();
        let output = analytics.get_data(&BTreeSet::<PublicKey>::from([event.public_key]));

        assert_eq!(output, expected_output);

        analytics.reset_cached_data();
        let output = analytics.get_data(&BTreeSet::<PublicKey>::from([event.public_key]));
        expected_output = OutputData::new(analytics.buckets);

        assert_eq!(output, expected_output);
    }

    #[tokio::test]
    async fn test_handle_wg_event_after_ping() {
        let mut analytics = setup();
        let mut event = generate_event();

        // insert node through first event
        analytics.handle_wg_event(&event).await;

        // perform a couple of pings to fill up histograms
        for _ in 0..4 {
            analytics.perform_ping();
            let node_ping_res = analytics.ping_channel_rx.recv().await.unwrap();
            analytics.process_node_ping_results((node_ping_res.0, node_ping_res.1));
        }

        let output = analytics.get_data(&BTreeSet::<PublicKey>::from([event.public_key]));

        // pinging localhost is usually < 0ms so histograms look empty
        assert_eq!(output, OutputData::new(analytics.buckets));

        // Add invalid ipv6 address and some dummy data
        event.dual_ip_addresses = vec![DualTarget::new((
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            Some(Ipv6Addr::new(0xfc02, 0, 0, 0, 0, 0, 0, 0x01)),
        ))
        .unwrap()];
        event.timestamp += Duration::from_secs(2);
        event.tx_bytes = 10;
        event.rx_bytes = 20;
        analytics.handle_wg_event(&event).await;

        event.timestamp += Duration::from_secs(5);
        event.tx_bytes = 50;
        event.rx_bytes = 80;
        analytics.handle_wg_event(&event).await;

        // perform ping with new data
        analytics.perform_ping();
        let node_ping_res = analytics.ping_channel_rx.recv().await.unwrap();
        analytics.process_node_ping_results((node_ping_res.0, node_ping_res.1));

        let node = analytics.nodes.get(&node_ping_res.0).unwrap();
        assert_eq!(node.public_key, event.public_key);
        assert_eq!(node.peer_state, PeerState::Connected);
        assert_eq!(node.last_event, event.timestamp);
        assert_eq!(node.last_wg_event, event.timestamp);
        assert_eq!(node.connected_time, Duration::from_secs(7));
        assert_eq!(node.ip_addresses, event.dual_ip_addresses);
        assert_eq!(node.last_tx_bytes, 50);
        assert_eq!(node.last_rx_bytes, 80);

        let output = analytics.get_data(&BTreeSet::<PublicKey>::from([event.public_key]));
        let expected_output = OutputData {
            rtt: "0:0:0:0:0".to_owned(),
            rtt_loss: "0:0:0:0:0".to_owned(),
            rtt6: "0:0:0:0:0".to_owned(),
            rtt6_loss: "0:0:0:100:100".to_owned(),
            tx: "5:8:8:8:8".to_owned(),
            rx: "10:12:12:12:12".to_owned(),
            connection_duration: String::from("7"),
        };

        assert_eq!(output, expected_output);
    }

    fn setup() -> Analytics {
        let wg_channel = McChan::new(1);
        let io = Io {
            wg_channel: wg_channel.rx,
        };
        let config = QoSConfig {
            rtt_interval: Duration::from_millis(500),
            rtt_tries: 1,
            rtt_types: vec![RttType::Ping],
            buckets: 5,
        };

        Analytics::new(config, io)
    }

    fn generate_event() -> AnalyticsEvent {
        let sk = SecretKey::gen();
        let pk = sk.public();
        let timestamp = Instant::now();
        let dual_ip_addresses = vec![DualTarget::new((
            Some(Ipv4Addr::new(127, 0, 0, 1)),
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ))
        .unwrap()];
        AnalyticsEvent {
            public_key: pk,
            dual_ip_addresses,
            peer_state: PeerState::Connected,
            timestamp,
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),
        }
    }

    fn default_histogram() -> Histogram {
        let mut a = Histogram::new();
        for i in 1..11 {
            a.increment(i * 10).unwrap();
        }
        a
    }

    fn dummy_node(
        public_key: PublicKey,
        histogram: &Histogram,
        connected_time: Duration,
    ) -> NodeInfo {
        NodeInfo {
            public_key,
            peer_state: PeerState::Disconnected,
            last_event: Instant::now(),
            last_wg_event: Instant::now(),
            connected_time,
            ip_addresses: vec![DualTarget::new((Some(Ipv4Addr::new(127, 0, 0, 1)), None)).unwrap()],
            rtt_histogram: histogram.clone(),
            rtt_loss_histogram: histogram.clone(),
            rtt6_histogram: histogram.clone(),
            rtt6_loss_histogram: histogram.clone(),
            last_rx_bytes: 0,
            last_tx_bytes: 0,
            tx_histogram: histogram.clone(),
            rx_histogram: histogram.clone(),
        }
    }
}
