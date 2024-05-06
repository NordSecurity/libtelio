use telio_model::features::{FeatureNurse, FeatureQoS};
use tokio::time::Duration;

use telio_model::features::RttType;

/// Configuration for Nurse
pub struct Config {
    /// Heartbeat analytics config
    pub heartbeat_config: HeartbeatConfig,

    /// QoS analytics config
    pub qos_config: Option<QoSConfig>,
}

impl Config {
    /// Create a new Nurse config
    pub fn new(features: &FeatureNurse) -> Self {
        Self {
            heartbeat_config: HeartbeatConfig::new(features),
            qos_config: features.qos.as_ref().map(QoSConfig::new),
        }
    }
}

/// Configuration for Heartbeat component from Nurse
pub struct HeartbeatConfig {
    /// Initial time period to wait until the first collection happens in seconds, if none, defaults to 'send_interval'
    pub initial_collect_interval: Duration,

    /// How often to collect data, in seconds
    pub collect_interval: Duration,

    /// How long to wait for the answers from other nodes after sending the collection message in seconds
    pub collect_answer_timeout: Duration,

    /// The unique identifier of the device, used for meshnet ID
    pub fingerprint: String,

    /// Control flag to collect nat type
    pub is_nat_type_collection_enabled: bool,
}

impl HeartbeatConfig {
    /// Create a new Heartbeat config
    pub(crate) fn new(features: &FeatureNurse) -> Self {
        Self {
            initial_collect_interval: Duration::from_secs(features.initial_heartbeat_interval),
            fingerprint: features.fingerprint.clone(),
            collect_interval: Duration::from_secs(features.heartbeat_interval),
            collect_answer_timeout: Duration::from_secs(10),
            is_nat_type_collection_enabled: features.enable_nat_type_collection,
        }
    }
}

/// Configuration options for QoS.
pub struct QoSConfig {
    /// How often to collect data, in seconds (5 minutes default)
    pub rtt_interval: Duration,

    /// Number of tries for every type of RTT analytics
    pub rtt_tries: u32,

    /// Types of RTT analytics
    pub rtt_types: Vec<RttType>,

    /// Number of buckets
    pub buckets: u32,
}

impl QoSConfig {
    /// Create a new QoS config
    fn new(features: &FeatureQoS) -> Self {
        Self {
            rtt_interval: Duration::from_secs(features.rtt_interval),
            rtt_tries: features.rtt_tries,
            rtt_types: features.rtt_types.clone(),
            buckets: features.buckets,
        }
    }
}

/// Configuration for Aggregator component from Nurse
#[derive(Clone, Default)]
pub struct AggregatorConfig {
    /// Collect relay events
    pub relay_events: bool,

    /// Collect nat traversal events
    pub nat_traversal_events: bool,
}

impl AggregatorConfig {
    /// Create a new Aggregator config
    pub fn new(features: &FeatureNurse) -> Self {
        Self {
            relay_events: features.enable_relay_conn_data,
            nat_traversal_events: features.enable_nat_traversal_conn_data,
        }
    }
}
