use std::{collections::HashSet, time::Duration};

use tokio::time::Instant;

use parking_lot::RwLock;
use serde::{ser::SerializeTuple, Serialize, Serializer};

use telio_crypto::PublicKey;
use telio_model::{
    api_config::{EndpointProvider, FeatureNurse},
    HashMap,
};
use telio_utils::telio_log_warn;
use telio_wg::{
    uapi::{AnalyticsEvent, PeerState},
    WireGuard,
};

// Possible endpoint connection types
// Their combinations give us strategies number to 15
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum EndpointType {
    #[allow(dead_code)]
    Relay = 0,
    Local = 1,
    Stun = 2,
    UPnP = 3,
}

impl From<EndpointProvider> for EndpointType {
    fn from(value: EndpointProvider) -> Self {
        match value {
            EndpointProvider::Local => EndpointType::Local,
            EndpointProvider::Stun => EndpointType::Stun,
            EndpointProvider::Upnp => EndpointType::UPnP,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum RelayConnectionState {
    Connecting = 16,
    Connected = 17,
}

impl From<PeerState> for RelayConnectionState {
    fn from(value: PeerState) -> Self {
        if let PeerState::Connected = value {
            RelayConnectionState::Connected
        } else {
            if let PeerState::Disconnected = value {
                telio_log_warn!("Got disconnected state for Relay server");
            }
            RelayConnectionState::Connecting
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct RelayConnectionData {
    state: RelayConnectionState,
    reason: RelayConnectionChangeReason,
}

// Possible disconnection reasons
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[allow(dead_code)]
pub enum RelayConnectionChangeReason {
    // 1XX reason numbers for configuration changes
    ConfigurationChange = 101,
    DisabledByUser = 102,

    // 2XX reason numbers for network problems
    ConnectionTimeout = 201,
    ConnectionTerminatedByServer = 202,
    NetworkError = 203,
}

// Possible connectivity state changes
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub enum ConnectionState {
    Relay(RelayConnectionChangeReason),
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
#[allow(dead_code)]
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

// Ready to send data about some period of the
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionSegmentData {
    node: PublicKey,
    start: Instant, // to ensure the segments are unique
    length: Duration,
    connection_data: ConnectionData,
}

// A container to store the connectivity data for our meshnet peers
#[allow(dead_code)]
pub struct ConnectivityDataAggregator<W: WireGuard> {
    current_events: RwLock<HashMap<PublicKey, (AnalyticsEvent, ConnectionState)>>,
    unacknowledged_segments: RwLock<HashSet<ConnectionSegmentData>>,

    aggregate_relay_events: bool,
    aggregate_nat_traversal_events: bool,

    wg_interface: W,
}

impl<W: WireGuard> ConnectivityDataAggregator<W> {
    // Create a new DataConnectivityAggregator instance
    #[allow(dead_code)]
    pub fn new(nurse_features: &FeatureNurse, wg_interface: W) -> ConnectivityDataAggregator<W> {
        ConnectivityDataAggregator {
            current_events: parking_lot::RwLock::new(HashMap::new()),
            unacknowledged_segments: parking_lot::RwLock::new(HashSet::new()),
            aggregate_relay_events: nurse_features.enable_relay_conn_data,
            aggregate_nat_traversal_events: nurse_features.enable_nat_traversal_conn_data,
            wg_interface,
        }
    }

    #[allow(dead_code)]
    pub fn change_peer_state_direct(
        &mut self,
        event: AnalyticsEvent,
        initiator_ep: EndpointProvider,
        responder_ep: EndpointProvider,
    ) {
        self.change_peer_state_common(event, initiator_ep.into(), responder_ep.into())
    }

    #[allow(dead_code)]
    pub fn change_peer_state_relayed(&mut self, event: AnalyticsEvent) {
        self.change_peer_state_common(event, EndpointType::Relay, EndpointType::Relay)
    }

    fn change_peer_state_common(
        &mut self,
        event: AnalyticsEvent,
        initiator_ep: EndpointType,
        responder_ep: EndpointType,
    ) {
        if !self.aggregate_nat_traversal_events {
            return;
        }

        match self.current_events.write().entry(event.public_key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let (old_event, old_state) = entry.get();

                let connection_data = match old_state {
                    ConnectionState::Relay(_) => {
                        telio_log_warn!("Peer event for the relay server pubkey - discarding");
                        return;
                    }
                    ConnectionState::Peer(ep1, ep2) => {
                        if old_event.peer_state == event.peer_state
                            && *ep1 == initiator_ep
                            && *ep2 == responder_ep
                        {
                            // Peers state remains unchanged - skipping the segment addition
                            return;
                        }
                        ConnectionData::Peer(PeerConnectionData {
                            initiator_ep_type: *ep1,
                            reciever_ep_type: *ep2,
                            rx_bytes: event.rx_bytes - old_event.rx_bytes,
                            tx_bytes: event.tx_bytes - old_event.tx_bytes,
                        })
                    }
                };

                // Just create a new segment here
                self.unacknowledged_segments
                    .write()
                    .insert(ConnectionSegmentData {
                        node: event.public_key,
                        start: old_event.timestamp.into(),
                        length: event.timestamp - old_event.timestamp,
                        connection_data,
                    });

                if event.peer_state == PeerState::Connected {
                    entry.insert((event, ConnectionState::Peer(initiator_ep, responder_ep)));
                } else {
                    entry.remove();
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if event.peer_state == PeerState::Connected {
                    entry.insert((event, ConnectionState::Peer(initiator_ep, responder_ep)));
                }
            }
        };
    }

    #[allow(dead_code)]
    pub fn change_relay_state(
        &mut self,
        event: AnalyticsEvent,
        reason: RelayConnectionChangeReason,
    ) {
        if !self.aggregate_relay_events {
            return;
        }

        match self.current_events.write().entry(event.public_key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let (old_event, old_state) = entry.get();

                let segment_connection_data = match old_state {
                    ConnectionState::Relay(reason) => {
                        if old_event.peer_state == event.peer_state {
                            // The state remains unchanged
                            return;
                        }
                        ConnectionData::Relay(RelayConnectionData {
                            state: old_event.peer_state.into(),
                            reason: *reason,
                        })
                    }
                    ConnectionState::Peer(_, _) => {
                        telio_log_warn!("Relay event for the meshnet node pubkey - discarding");
                        return;
                    }
                };

                // Just create a new segment here
                self.unacknowledged_segments
                    .write()
                    .insert(ConnectionSegmentData {
                        node: event.public_key,
                        start: old_event.timestamp.into(),
                        length: event.timestamp - old_event.timestamp,
                        connection_data: segment_connection_data,
                    });

                entry.insert((event, ConnectionState::Relay(reason)));
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((event, ConnectionState::Relay(reason)));
            }
        };
    }

    #[allow(dead_code)]
    pub async fn collect_unacknowledged_segments(&self) -> Vec<ConnectionSegmentData> {
        if let Ok(wg_peers) = self.wg_interface.get_interface().await.map(|wgi| wgi.peers) {
            let current_timestamp = Instant::now();

            for (peer_event, peer_state) in self.current_events.write().values_mut() {
                if current_timestamp - Instant::from_std(peer_event.timestamp)
                    > Duration::from_secs(60 * 60 * 24)
                {
                    match peer_state {
                        ConnectionState::Relay(reason) => {
                            Some(ConnectionData::Relay(RelayConnectionData {
                                state: peer_event.peer_state.into(),
                                reason: *reason,
                            }))
                        }
                        ConnectionState::Peer(initiator_ep_type, reciever_ep_type) => wg_peers
                            .get(&peer_event.public_key)
                            .and_then(|wg_peer| wg_peer.rx_bytes.zip(wg_peer.tx_bytes))
                            .map(|(rx_bytes, tx_bytes)| {
                                let d_rx_bytes = rx_bytes - peer_event.rx_bytes;
                                let d_tx_bytes = tx_bytes - peer_event.tx_bytes;
                                peer_event.rx_bytes = rx_bytes;
                                peer_event.tx_bytes = tx_bytes;
                                ConnectionData::Peer(PeerConnectionData {
                                    initiator_ep_type: *initiator_ep_type,
                                    reciever_ep_type: *reciever_ep_type,
                                    rx_bytes: d_rx_bytes,
                                    tx_bytes: d_tx_bytes,
                                })
                            }),
                    }
                    .map_or_else(
                        || {
                            telio_log_warn!("Unable to get transfer data for peer");
                        },
                        |connection_data| {
                            self.unacknowledged_segments
                                .write()
                                .insert(ConnectionSegmentData {
                                    node: peer_event.public_key,
                                    start: peer_event.timestamp.into(),
                                    length: current_timestamp
                                        - Instant::from_std(peer_event.timestamp),
                                    connection_data,
                                });
                            peer_event.timestamp = current_timestamp.into();
                        },
                    );
                }
            }
        } else {
            telio_log_warn!("Getting wireguard interfaces failed");
        }

        self.unacknowledged_segments
            .read()
            .clone()
            .into_iter()
            .collect()
    }

    #[allow(dead_code)]
    pub fn acknowledge_segments_transmission<T>(&mut self, segment_set: T)
    where
        T: IntoIterator<Item = ConnectionSegmentData>,
    {
        let mut storage_guard = self.unacknowledged_segments.write();
        segment_set.into_iter().for_each(|segment| {
            if !storage_guard.remove(&segment) {
                telio_log_warn!("Connectivity event for the given peer and timestamp not found");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use telio_utils::DualTarget;
    use telio_wg::{
        uapi::{Interface, Peer, PeerState},
        MockWireGuard,
    };
    use tokio::time;

    use super::*;

    async fn create_aggregator(
        enable_relay_conn_data: bool,
        enable_nat_traversal_conn_data: bool,
        wg_interface: MockWireGuard,
    ) -> ConnectivityDataAggregator<MockWireGuard> {
        let nurse_features = FeatureNurse {
            fingerprint: String::from("fingerprint_test"),
            heartbeat_interval: None,
            initial_heartbeat_interval: None,
            qos: None,
            enable_nat_type_collection: None,
            enable_relay_conn_data,
            enable_nat_traversal_conn_data,
        };

        ConnectivityDataAggregator::new(&nurse_features, wg_interface)
    }

    fn create_basic_event(n: u8) -> AnalyticsEvent {
        AnalyticsEvent {
            public_key: PublicKey(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            endpoint: DualTarget::new((Some(Ipv4Addr::from([n, n, n, n])), None)).unwrap(), // Whatever
            tx_bytes: 0, // We don't need them for Relay event
            rx_bytes: 0,
            peer_state: PeerState::Connected, // This should be the same as in the
            timestamp: Instant::now().into(),
        }
    }

    #[tokio::test]
    async fn test_aggregator_basic_scenario_relay() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let mut aggregator = create_aggregator(true, false, wg_interface).await;

        // Initial event
        let mut current_relay_event = create_basic_event(1);
        let segment_start = current_relay_event.timestamp;
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::ConfigurationChange,
        );

        // And after 60 seconds some disconnect due to network error
        current_relay_event.timestamp += Duration::from_secs(60);
        current_relay_event.peer_state = PeerState::Connecting;
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::NetworkError,
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_relay_event.public_key,
                start: segment_start.into(),
                length: Duration::from_secs(60),
                connection_data: ConnectionData::Relay(RelayConnectionData {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                })
            }
        );

        aggregator.acknowledge_segments_transmission(segments);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_aggregator_basic_scenario_peer_relayed() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let mut aggregator = create_aggregator(false, true, wg_interface).await;

        // Initial event
        let mut current_peer_event = create_basic_event(1);
        let segment_start = current_peer_event.timestamp;
        aggregator.change_peer_state_relayed(current_peer_event);

        // And after 60 seconds some disconnect due to network error
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.peer_state = PeerState::Connecting;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator.change_peer_state_relayed(current_peer_event);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_peer_event.public_key,
                start: segment_start.into(),
                length: Duration::from_secs(60),
                connection_data: ConnectionData::Peer(PeerConnectionData {
                    initiator_ep_type: EndpointType::Relay,
                    reciever_ep_type: EndpointType::Relay,
                    rx_bytes: 1000,
                    tx_bytes: 2000
                })
            }
        );

        aggregator.acknowledge_segments_transmission(segments);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_aggregator_basic_scenario_peer_direct() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let mut aggregator = create_aggregator(false, true, wg_interface).await;

        // Initial event
        let mut current_peer_event = create_basic_event(1);
        let segment_start = current_peer_event.timestamp;
        aggregator.change_peer_state_direct(
            current_peer_event,
            EndpointProvider::Upnp,
            EndpointProvider::Local,
        );

        // And after 60 seconds some disconnect due to network error
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator.change_peer_state_relayed(current_peer_event);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_peer_event.public_key,
                start: segment_start.into(),
                length: Duration::from_secs(60),
                connection_data: ConnectionData::Peer(PeerConnectionData {
                    initiator_ep_type: EndpointType::UPnP,
                    reciever_ep_type: EndpointType::Local,
                    rx_bytes: 1000,
                    tx_bytes: 2000
                })
            }
        );

        aggregator.acknowledge_segments_transmission(segments);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_aggregator_disabled() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let mut aggregator = create_aggregator(false, false, wg_interface).await;

        // Initial event
        let mut current_peer_event = create_basic_event(1);
        aggregator.change_peer_state_direct(
            current_peer_event,
            EndpointProvider::Upnp,
            EndpointProvider::Local,
        );

        // And after 60 seconds some disconnect due to network error
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.peer_state = PeerState::Connecting;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator.change_peer_state_relayed(current_peer_event);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_aggregator_multiple_events_single_segment() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let mut aggregator = create_aggregator(false, true, wg_interface).await;

        // Initial event
        let mut current_peer_event = create_basic_event(1);
        let segment_start = current_peer_event.timestamp;
        aggregator.change_peer_state_direct(
            current_peer_event,
            EndpointProvider::Upnp,
            EndpointProvider::Local,
        );

        // Send one more event with the same state
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator.change_peer_state_direct(
            current_peer_event,
            EndpointProvider::Upnp,
            EndpointProvider::Local,
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);

        // And after 60 seconds some disconnect
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.peer_state = PeerState::Connecting;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator.change_peer_state_relayed(current_peer_event);

        // And after 60 seconds connect again
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.peer_state = PeerState::Connected;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator.change_peer_state_relayed(current_peer_event);

        // We don't gather periods of time when peer is disconnected, so we should have here only one segment
        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_peer_event.public_key,
                start: segment_start.into(),
                length: Duration::from_secs(120),
                connection_data: ConnectionData::Peer(PeerConnectionData {
                    initiator_ep_type: EndpointType::UPnP,
                    reciever_ep_type: EndpointType::Local,
                    rx_bytes: 2000,
                    tx_bytes: 4000
                })
            }
        );

        aggregator.acknowledge_segments_transmission(segments);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_aggregator_12h_segment() {
        // Initial event
        let current_peer_event = create_basic_event(1);
        let segment_start = current_peer_event.timestamp;

        let mut wg_interface = MockWireGuard::new();
        let lambda_pk = current_peer_event.public_key;
        wg_interface.expect_get_interface().returning(move || {
            Ok(Interface {
                peers: vec![(
                    lambda_pk,
                    Peer {
                        public_key: lambda_pk,
                        endpoint: None,
                        rx_bytes: Some(3333),
                        tx_bytes: Some(1111),
                        ..Default::default()
                    },
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            })
        });
        let mut aggregator = create_aggregator(false, true, wg_interface).await;

        // Insert the first event
        aggregator.change_peer_state_relayed(current_peer_event);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);

        time::advance(Duration::from_secs(24 * 60 * 60 + 1)).await;

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_peer_event.public_key,
                start: segment_start.into(),
                length: Duration::from_secs(24 * 60 * 60 + 1),
                connection_data: ConnectionData::Peer(PeerConnectionData {
                    initiator_ep_type: EndpointType::Relay,
                    reciever_ep_type: EndpointType::Relay,
                    rx_bytes: 3333,
                    tx_bytes: 1111
                })
            }
        );

        aggregator.acknowledge_segments_transmission(segments);

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }
}
