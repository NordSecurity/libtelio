use std::collections::BTreeSet;
use telio_crypto::PublicKey;
use telio_model::config::Config;

/// Information about a heartbeat, for analytics.
#[derive(Default)]
pub struct HeartbeatInfo {
    /// The id of the meshnet
    pub meshnet_id: String,
    /// String with comma-separated list of fingerprints of all internal nodes
    pub fingerprints: String,
    /// Connectivity matrix of the meshnet
    pub connectivity_matrix: String,
    /// Public keys of internal nodes
    pub internal_sorted_public_keys: BTreeSet<PublicKey>,
    /// Public keys of external nodes
    pub external_sorted_public_keys: BTreeSet<PublicKey>,
    /// How often to send heartbeats
    pub heartbeat_interval: i32,
    /// String with comma-separated list of `meshnet_id:fingerprint:connection_state` for all external nodes
    pub external_links: String,
}

/// Analytics data
pub enum AnalyticsMessage {
    /// Heartbeat analytics message
    Heartbeat {
        /// Info about a heartbeat
        heartbeat_info: HeartbeatInfo,
    },
}

/// Represents an update to the meshnet config
#[derive(Clone, Default)]
pub struct MeshConfigUpdateEvent {
    /// All local nodes from the config passed to telio library.
    pub local_nodes: Vec<PublicKey>,
}

impl From<&Config> for MeshConfigUpdateEvent {
    fn from(config: &Config) -> Self {
        if let Some(peers) = &config.peers {
            let local_nodes = peers
                .iter()
                .filter(|p| p.is_local)
                .map(|p| p.public_key)
                .collect::<Vec<_>>();
            MeshConfigUpdateEvent { local_nodes }
        } else {
            MeshConfigUpdateEvent::default()
        }
    }
}
