use std::collections::{BTreeSet, HashMap};
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
    /// NAT type of the derp server
    pub nat_type: String,
    /// List of nat types as Strings of all connected peers
    pub peer_nat_types: Vec<String>,
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
    /// All the nodes (public_key, is_local) from the config passed to telio library.
    pub nodes: HashMap<PublicKey, bool>,
}

impl From<&Config> for MeshConfigUpdateEvent {
    fn from(config: &Config) -> Self {
        if let Some(peers) = &config.peers {
            let nodes = peers
                .iter()
                .map(|p| (p.public_key, p.is_local))
                .collect::<HashMap<_, _>>();
            MeshConfigUpdateEvent { nodes }
        } else {
            MeshConfigUpdateEvent::default()
        }
    }
}
