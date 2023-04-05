use telio_model::api_config::{FeatureNurse, FeatureQoS};
use tokio::time::Duration;

use crate::qos::RttType;

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
            qos_config: QoSConfig::new(&features.qos),
        }
    }
}

/// Configuration for Heartbeat component from Nurse
pub struct HeartbeatConfig {
    /// Initial time period to wait until the first collection happens in seconds, if none, defaults to 'send_interval'
    pub initial_collect_interval: Option<Duration>,

    /// How often to collect data, in seconds
    pub collect_interval: Duration,

    /// How long to wait for the answers from other nodes after sending the collection message in seconds
    pub collect_answer_timeout: Duration,

    /// The unique identifier of the device, used for meshnet ID
    pub fingerprint: String,
}

impl HeartbeatConfig {
    const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3600); // 60 minutes

    /// Create a new Heartbeat config
    fn new(features: &FeatureNurse) -> Self {
        let collect_interval = features
            .heartbeat_interval
            .map(|interval| Duration::from_secs(interval.into()))
            .unwrap_or(Self::DEFAULT_HEARTBEAT_INTERVAL);

        Self {
            fingerprint: features.fingerprint.clone(),
            collect_interval,
            ..Default::default()
        }
    }
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            initial_collect_interval: None,
            collect_interval: Duration::from_secs(3600),
            collect_answer_timeout: Duration::from_secs(5),
            fingerprint: String::new(),
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
    const DEFAULT_RTT_COLLECT_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
    const DEFAULT_RTT_TRIES: u32 = 3;
    const DEFAULT_BUCKETS: u32 = 5;

    /// Create a new QoS config
    fn new(qos_features: &Option<FeatureQoS>) -> Option<Self> {
        qos_features.as_ref().map(|features| {
            let rtt_interval = features
                .rtt_interval
                .map(|x| Duration::from_secs(x.into()))
                .unwrap_or_else(|| Self::DEFAULT_RTT_COLLECT_INTERVAL);

            let rtt_tries = features.rtt_tries.unwrap_or(Self::DEFAULT_RTT_TRIES);

            let rtt_types = features
                .rtt_types
                .as_ref()
                .map(|types| {
                    let mut v = Vec::new();

                    for ty in types {
                        if let Ok(t) = serde_json::from_str::<RttType>(ty) {
                            v.push(t);
                        }
                    }

                    if v.is_empty() {
                        vec![RttType::Ping]
                    } else {
                        v
                    }
                })
                .unwrap_or_else(|| vec![RttType::Ping]);

            let buckets = features.buckets.unwrap_or(Self::DEFAULT_BUCKETS);

            Self {
                rtt_interval,
                rtt_tries,
                rtt_types,
                buckets,
            }
        })
    }
}

impl Default for QoSConfig {
    fn default() -> Self {
        Self {
            rtt_interval: Self::DEFAULT_RTT_COLLECT_INTERVAL,
            rtt_tries: Self::DEFAULT_RTT_TRIES,
            rtt_types: vec![RttType::Ping],
            buckets: Self::DEFAULT_BUCKETS,
        }
    }
}
