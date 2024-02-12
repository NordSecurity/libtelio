use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use serde::{ser::SerializeTuple, Serialize, Serializer};

use telio_crypto::PublicKey;
use telio_model::{api_config::FeatureNurse, HashMap};
use telio_utils::telio_log_warn;
use telio_wg::{uapi::AnalyticsEvent, WireGuard};

// Possible endpoint connection types
// Their combinations give us strategies number to 15
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum EndpointType {
    Relay = 0,
    Local = 1,
    Stun = 2,
    UPnP = 3,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum RelayConnectionState {
    Connecting = 16,
    Connected = 17,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct RelayConnectionData {
    state: RelayConnectionState,
    reason: RelayConnectionChangeReason,
}

// Possible disconnection reasons
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum RelayConnectionChangeReason {
    // 1XX reason numbers for configuration changes
    DisabledByUser = 101,

    // 2XX reason numbers for network problems
    ConnectionTimeout = 201,
    ConnectionTerminatedByServer = 202,
    NetworkError = 203,
}

// Possible connectivity state changes
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum ConnectionState {
    Relay(RelayConnectionState, RelayConnectionChangeReason),
    Peer(EndpointType, EndpointType),
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerConnectionData {
    initiator_ep_type: EndpointType,
    reciever_ep_type: EndpointType,
    rx_bytes: u64,
    tx_bytes: u64,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum ConnectionData {
    Relay(RelayConnectionData),
    Peer(PeerConnectionData),
}

impl Serialize for ConnectionData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ConnectionData::Relay(conn_data) => {
                let mut seq = serializer.serialize_tuple(2)?;
                seq.serialize_element(&(conn_data.state as u64))?;
                seq.serialize_element(&(conn_data.reason as u64))?;
                seq.end()
            }
            ConnectionData::Peer(conn_data) => {
                let strategy_id =
                    (conn_data.initiator_ep_type as u64) * 4 + (conn_data.reciever_ep_type as u64);
                let mut seq = serializer.serialize_tuple(3)?;
                seq.serialize_element(&strategy_id)?;
                seq.serialize_element(&conn_data.rx_bytes)?;
                seq.serialize_element(&conn_data.tx_bytes)?;
                seq.end()
            }
        }
    }
}

// Event containing info about changed connection quality to a certain peer
#[derive(Copy, Clone, Debug)]
pub struct ExtAnalyticsEvent {
    event: AnalyticsEvent,
    state: ConnectionState,
}

impl ExtAnalyticsEvent {
    pub fn is_relay(&self) -> bool {
        matches!(self.state, ConnectionState::Relay(..))
    }

    pub fn is_nat_traversal(&self) -> bool {
        matches!(self.state, ConnectionState::Peer(..))
    }
}

// Ready to send data about some period of the
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionSegmentData {
    node: PublicKey,
    start: Instant, // to ensure the segments are unique
    length_in_ms: u128,
    connection_data: ConnectionData,
}

// A container to store the connectivity data for our meshnet peers
pub struct ConnectivityDataAggregator<W: WireGuard> {
    current_peers_events: RwLock<HashMap<PublicKey, ExtAnalyticsEvent>>,
    unacknowledged_segments: RwLock<HashSet<ConnectionSegmentData>>,

    aggregate_relay_events: bool,
    aggregate_nat_traversal_events: bool,

    wg_interface: W,
}

impl<W: WireGuard> ConnectivityDataAggregator<W> {
    // Create a new DataConnectivityAggregator instance
    pub fn new(nurse_features: &FeatureNurse, wg_interface: W) -> ConnectivityDataAggregator<W> {
        ConnectivityDataAggregator {
            current_peers_events: parking_lot::RwLock::new(HashMap::new()),
            unacknowledged_segments: parking_lot::RwLock::new(HashSet::new()),
            aggregate_relay_events: nurse_features.enable_relay_conn_data,
            aggregate_nat_traversal_events: nurse_features.enable_nat_traversal_conn_data,
            wg_interface,
        }
    }

    pub fn add_state_change(&mut self, event: ExtAnalyticsEvent) {
        if (event.is_relay() && !self.aggregate_relay_events)
            || (event.is_nat_traversal() && !self.aggregate_nat_traversal_events)
        {
            return;
        }

        let mut events_guard = self.current_peers_events.write();

        match events_guard.entry(event.event.public_key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let old_event = entry.get();

                let connection_data = match old_event.state {
                    ConnectionState::Relay(state, reason) => {
                        ConnectionData::Relay(RelayConnectionData { state, reason })
                    }
                    ConnectionState::Peer(ep1, ep2) => ConnectionData::Peer(PeerConnectionData {
                        initiator_ep_type: ep1,
                        reciever_ep_type: ep2,
                        rx_bytes: event.event.rx_bytes - old_event.event.rx_bytes,
                        tx_bytes: event.event.tx_bytes - old_event.event.tx_bytes,
                    }),
                };

                let length_in_ms = (event.event.timestamp - old_event.event.timestamp).as_millis();

                // Just create a new segment here
                self.unacknowledged_segments
                    .write()
                    .insert(ConnectionSegmentData {
                        node: event.event.public_key,
                        start: old_event.event.timestamp,
                        length_in_ms,
                        connection_data,
                    });

                entry.insert(event);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(event);
            }
        };
    }

    pub fn collect_unacknowledged_segments(&self) -> Vec<ConnectionSegmentData> {
        self.unacknowledged_segments
            .read()
            .clone()
            .into_iter()
            .collect()
    }

    async fn acknowledge_segments_transmission<T>(&mut self, info_key_set: T)
    where
        T: IntoIterator<Item = ConnectionSegmentData>,
    {
        if let Ok(wg_peers) = self.wg_interface.get_interface().await.map(|wgi| wgi.peers) {
            let current_timestamp = Instant::now();

            for peer_event in self.current_peers_events.write().values_mut() {
                if current_timestamp - peer_event.event.timestamp
                    > Duration::from_secs(60 * 60 * 24)
                {
                    match peer_event.state {
                        ConnectionState::Relay(state, reason) => {
                            Some(ConnectionData::Relay(RelayConnectionData { state, reason }))
                        }
                        ConnectionState::Peer(initiator_ep_type, reciever_ep_type) => wg_peers
                            .get(&peer_event.event.public_key)
                            .and_then(|wg_peer| wg_peer.rx_bytes.zip(wg_peer.tx_bytes))
                            .map(|(rx_bytes, tx_bytes)| {
                                peer_event.event.rx_bytes = rx_bytes;
                                peer_event.event.tx_bytes = tx_bytes;
                                ConnectionData::Peer(PeerConnectionData {
                                    initiator_ep_type,
                                    reciever_ep_type,
                                    rx_bytes: rx_bytes - peer_event.event.rx_bytes,
                                    tx_bytes: tx_bytes - peer_event.event.tx_bytes,
                                })
                            }),
                    }
                    .map_or_else(
                        || {
                            telio_log_warn!("Unable to get transfer data for peer");
                        },
                        |connection_data| {
                            let length_in_ms =
                                (current_timestamp - peer_event.event.timestamp).as_millis();
                            self.unacknowledged_segments
                                .write()
                                .insert(ConnectionSegmentData {
                                    node: peer_event.event.public_key,
                                    start: peer_event.event.timestamp,
                                    length_in_ms,
                                    connection_data,
                                });
                            peer_event.event.timestamp = current_timestamp;
                        },
                    );
                }
            }
        } else {
            telio_log_warn!("Getting wireguard interfaces failed");
        }

        let mut storage_guard = self.unacknowledged_segments.write();
        info_key_set.into_iter().for_each(|segment| {
            if !storage_guard.remove(&segment) {
                telio_log_warn!("Connectivity event for the given peer and timestamp not found");
            }
        })
    }
}
