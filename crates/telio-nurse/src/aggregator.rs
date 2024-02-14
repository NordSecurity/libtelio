use std::{borrow::Borrow, collections::hash_map::Entry, mem, time::Duration};

use tokio::time::Instant;

use parking_lot::RwLock;

use serde::{ser::SerializeTuple, Serialize};

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

const DAY_DURATION: Duration = Duration::from_secs(60 * 60 * 24);

// Possible Relay connection states - because all of the first 8 bit combinations
// are reserved for relay states, they need to have the 9th bit on
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum RelayConnectionState {
    Connecting = 256,
    Connected = 257,
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

// Possible disconnection reasons
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
#[repr(u16)]
pub enum RelayConnectionChangeReason {
    // Numbers smaller than 200 for configuration changes
    ConfigurationChange = 101,
    DisabledByUser = 102,

    // Numbers larger than 200 for network problems
    ConnectionTimeout = 201,
    ConnectionTerminatedByServer = 202,
    NetworkError = 203,
}

// Possible endpoint connection types
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

// Possible connectivity state changes
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub struct PeerEndpointTypes {
    initiator_ep: EndpointType,
    responder_ep: EndpointType,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub enum ConnectionData {
    Relay {
        state: RelayConnectionState,
        reason: RelayConnectionChangeReason,
    },
    Peer {
        endpoints: PeerEndpointTypes,
        rx_bytes: u64,
        tx_bytes: u64,
    },
}

const ENDPOINT_BIT_FIELD_WIDTH: u16 = 4;
const RELAY_TUPLE_LEN: usize = 2;
const PEER_TUPLE_LEN: usize = 3;

impl Serialize for ConnectionData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ConnectionData::Relay { state, reason } => {
                let mut seq = serializer.serialize_tuple(RELAY_TUPLE_LEN)?;
                seq.serialize_element(&(*state as u64))?;
                seq.serialize_element(&(*reason as u64))?;
                seq.end()
            }
            ConnectionData::Peer {
                endpoints,
                rx_bytes,
                tx_bytes,
            } => {
                let initiator_repr = endpoints.initiator_ep as u16;
                let responder_repr = endpoints.responder_ep as u16;
                let strategy_id = (initiator_repr << ENDPOINT_BIT_FIELD_WIDTH) + responder_repr;
                let mut seq = serializer.serialize_tuple(PEER_TUPLE_LEN)?;
                seq.serialize_element(&strategy_id)?;
                seq.serialize_element(&rx_bytes)?;
                seq.serialize_element(&tx_bytes)?;
                seq.end()
            }
        }
    }
}

// Ready to send connection data for some period of time
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionSegmentData {
    node: PublicKey,
    start: Instant, // to ensure the segments are unique
    duration: Duration,
    connection_data: ConnectionData,
}

impl ConnectionSegmentData {
    pub fn new_relay(relay_event: &RelayEvent, target_timestamp: Instant) -> Self {
        ConnectionSegmentData {
            node: relay_event.public_key,
            start: relay_event.timestamp,
            duration: target_timestamp.duration_since(relay_event.timestamp),
            connection_data: ConnectionData::Relay {
                state: relay_event.peer_state.into(),
                reason: relay_event.reason,
            },
        }
    }

    pub fn new_peer(
        peer_event: &AnalyticsEvent,
        endpoints: PeerEndpointTypes,
        target_timestamp: Instant,
        target_rx_bytes: u64,
        target_tx_bytes: u64,
    ) -> Self {
        ConnectionSegmentData {
            node: peer_event.public_key,
            start: peer_event.timestamp.into(),
            duration: target_timestamp.duration_since(peer_event.timestamp.into()),
            connection_data: ConnectionData::Peer {
                endpoints,
                rx_bytes: target_rx_bytes - peer_event.rx_bytes,
                tx_bytes: target_tx_bytes - peer_event.tx_bytes,
            },
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RelayEvent {
    public_key: PublicKey,
    peer_state: PeerState,
    timestamp: Instant,
    reason: RelayConnectionChangeReason,
}

struct AggregatorData {
    current_relay_event: Option<RelayEvent>,
    current_peer_events: HashMap<PublicKey, (AnalyticsEvent, PeerEndpointTypes)>,
    unacknowledged_segments: Vec<ConnectionSegmentData>,
}

// A container to store the connectivity data for our meshnet peers
#[allow(dead_code)]
pub struct ConnectivityDataAggregator<W: WireGuard> {
    data: RwLock<AggregatorData>,

    aggregate_relay_events: bool,
    aggregate_nat_traversal_events: bool,

    wg_interface: W,
}

impl<W: WireGuard> ConnectivityDataAggregator<W> {
    // Create a new DataConnectivityAggregator instance
    #[allow(dead_code)]
    pub fn new(nurse_features: &FeatureNurse, wg_interface: W) -> ConnectivityDataAggregator<W> {
        ConnectivityDataAggregator {
            data: parking_lot::RwLock::new(AggregatorData {
                current_relay_event: None,
                current_peer_events: HashMap::new(),
                unacknowledged_segments: Vec::new(),
            }),
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
        self.change_peer_state_common(
            event,
            PeerEndpointTypes {
                initiator_ep: initiator_ep.into(),
                responder_ep: responder_ep.into(),
            },
        )
    }

    #[allow(dead_code)]
    pub fn change_peer_state_relayed(&mut self, event: AnalyticsEvent) {
        self.change_peer_state_common(
            event,
            PeerEndpointTypes {
                initiator_ep: EndpointType::Relay,
                responder_ep: EndpointType::Relay,
            },
        )
    }

    fn change_peer_state_common(&mut self, event: AnalyticsEvent, endpoints: PeerEndpointTypes) {
        if !self.aggregate_nat_traversal_events {
            return;
        }

        let mut data_guard = self.data.write();
        let event_entry = data_guard.current_peer_events.entry(event.public_key);
        let new_segment = match event_entry.borrow() {
            Entry::Occupied(entry)
                if entry.get().0.peer_state != event.peer_state || entry.get().1 != endpoints =>
            {
                Some(ConnectionSegmentData::new_peer(
                    &entry.get().0,
                    entry.get().1,
                    event.timestamp.into(),
                    event.rx_bytes,
                    event.tx_bytes,
                ))
            }
            _ => None,
        };

        if event.peer_state != PeerState::Connected {
            if let Entry::Occupied(entry) = event_entry {
                entry.remove();
            }
        } else if let Entry::Vacant(entry) = event_entry {
            entry.insert((event, endpoints));
        }

        data_guard.unacknowledged_segments.extend(new_segment);
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

        let mut data_guard = self.data.write();

        let new_segment = data_guard
            .current_relay_event
            .as_ref()
            .filter(|old_event| {
                old_event.public_key != event.public_key || old_event.peer_state != event.peer_state
            })
            .map(|old_event| ConnectionSegmentData::new_relay(old_event, event.timestamp.into()));

        if let Some(segment) = new_segment {
            data_guard.unacknowledged_segments.push(segment);
        }

        if new_segment.is_some() || data_guard.current_relay_event.is_none() {
            data_guard.current_relay_event = Some(RelayEvent {
                public_key: event.public_key,
                peer_state: event.peer_state,
                timestamp: event.timestamp.into(),
                reason,
            })
        }
    }

    #[allow(dead_code)]
    pub async fn collect_unacknowledged_segments(&self) -> Vec<ConnectionSegmentData> {
        // Getting wg_interface is first, so it won't await while mutex is locked
        let wg_interface = self.wg_interface.get_interface().await;
        let mut data_guard = self.data.write();

        let current_timestamp = Instant::now();
        let mut new_segments = Vec::new();

        // Handle long-lasting relay events
        if let Some(event) = data_guard
            .current_relay_event
            .as_mut()
            .filter(|relay_event| {
                current_timestamp.duration_since(relay_event.timestamp) > DAY_DURATION
            })
        {
            new_segments.push(ConnectionSegmentData::new_relay(event, current_timestamp));
            event.timestamp = current_timestamp;
        }

        // Handle long-lasting peer events
        if let Ok(wg_peers) = wg_interface.map(|wgi| wgi.peers) {
            for (peer_event, peer_state) in data_guard.current_peer_events.values_mut() {
                let since_last_event =
                    current_timestamp.duration_since(Instant::from_std(peer_event.timestamp));
                if since_last_event > DAY_DURATION {
                    wg_peers
                        .get(&peer_event.public_key)
                        .and_then(|wg_peer| wg_peer.rx_bytes.zip(wg_peer.tx_bytes))
                        .map_or_else(
                            || {
                                telio_log_warn!("Unable to get transfer data for peer");
                            },
                            |(rx_bytes, tx_bytes)| {
                                new_segments.push(ConnectionSegmentData::new_peer(
                                    peer_event,
                                    *peer_state,
                                    current_timestamp,
                                    rx_bytes,
                                    tx_bytes,
                                ));
                                peer_event.rx_bytes = rx_bytes;
                                peer_event.tx_bytes = tx_bytes;
                                peer_event.timestamp = current_timestamp.into();
                            },
                        );
                }
            }
        } else {
            telio_log_warn!("Getting wireguard interfaces failed");
        }

        data_guard
            .unacknowledged_segments
            .extend(new_segments.into_iter());

        mem::take(&mut data_guard.unacknowledged_segments)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use csv::WriterBuilder;
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
            tx_bytes: 0, // Just start with no data sent
            rx_bytes: 0,
            peer_state: PeerState::Connected,
            timestamp: Instant::now().into(),
        }
    }

    #[tokio::test]
    async fn test_aggregator_relay_multiple_servers() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let mut aggregator = create_aggregator(true, false, wg_interface).await;

        // Initial event
        let mut current_relay_event = create_basic_event(1);
        let first_pubkey = current_relay_event.public_key;
        let second_pubkey = PublicKey(*b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        let segment_start = current_relay_event.timestamp;
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::ConfigurationChange,
        );

        // Repeated state after some time
        current_relay_event.timestamp += Duration::from_secs(60);
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::ConfigurationChange,
        );

        // Change server event
        current_relay_event.timestamp += Duration::from_secs(60);
        let second_segment_start = current_relay_event.timestamp;
        current_relay_event.public_key = second_pubkey;
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::ConfigurationChange,
        );

        // And after 60 seconds some disconnect due to network error
        current_relay_event.timestamp += Duration::from_secs(60);
        let third_segment_start = current_relay_event.timestamp;
        current_relay_event.peer_state = PeerState::Connecting;
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::NetworkError,
        );

        // We want to see also the connecting period, so let's make it connect in the end
        current_relay_event.timestamp += Duration::from_secs(60);
        let fourth_segment_start = current_relay_event.timestamp;
        current_relay_event.peer_state = PeerState::Connected;
        current_relay_event.public_key = first_pubkey;
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::ConfigurationChange,
        );

        // And let's add one more segment with the old pubkey
        current_relay_event.timestamp += Duration::from_secs(30);
        current_relay_event.peer_state = PeerState::Disconnected;
        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::NetworkError,
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 4);

        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: first_pubkey,
                start: segment_start.into(),
                duration: Duration::from_secs(120),
                connection_data: ConnectionData::Relay {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );
        assert_eq!(
            segments[1],
            ConnectionSegmentData {
                node: second_pubkey,
                start: second_segment_start.into(),
                duration: Duration::from_secs(60),
                connection_data: ConnectionData::Relay {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );
        assert_eq!(
            segments[2],
            ConnectionSegmentData {
                node: second_pubkey,
                start: third_segment_start.into(),
                duration: Duration::from_secs(60),
                connection_data: ConnectionData::Relay {
                    state: RelayConnectionState::Connecting,
                    reason: RelayConnectionChangeReason::NetworkError
                }
            }
        );
        assert_eq!(
            segments[3],
            ConnectionSegmentData {
                node: first_pubkey,
                start: fourth_segment_start.into(),
                duration: Duration::from_secs(30),
                connection_data: ConnectionData::Relay {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );

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
                duration: Duration::from_secs(120),
                connection_data: ConnectionData::Peer {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::UPnP,
                        responder_ep: EndpointType::Local,
                    },
                    rx_bytes: 2000,
                    tx_bytes: 4000
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_aggregator_24h_segment_peer() {
        // Initial event
        let current_peer_event = create_basic_event(1);
        let segment_start = current_peer_event.timestamp;
        let expected_first_segment_duration = DAY_DURATION + Duration::from_secs(1);
        let expected_second_segment_duration = DAY_DURATION + Duration::from_secs(2);

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

        time::advance(expected_first_segment_duration).await;

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_peer_event.public_key,
                start: segment_start.into(),
                duration: expected_first_segment_duration,
                connection_data: ConnectionData::Peer {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::Relay,
                        responder_ep: EndpointType::Relay,
                    },
                    rx_bytes: 3333,
                    tx_bytes: 1111
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);

        time::advance(expected_second_segment_duration).await;

        let expected_second_segment_start = segment_start + expected_first_segment_duration;
        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_peer_event.public_key,
                start: expected_second_segment_start.into(),
                duration: expected_second_segment_duration,
                connection_data: ConnectionData::Peer {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::Relay,
                        responder_ep: EndpointType::Relay,
                    },
                    rx_bytes: 0,
                    tx_bytes: 0
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_aggregator_24h_segment_relay() {
        let current_relay_event = create_basic_event(1);
        let segment_start = current_relay_event.timestamp;
        let expected_first_segment_duration = DAY_DURATION + Duration::from_secs(1);
        let expected_second_segment_duration = DAY_DURATION + Duration::from_secs(2);

        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(move || Ok(Default::default()));
        let mut aggregator = create_aggregator(true, false, wg_interface).await;

        aggregator.change_relay_state(
            current_relay_event,
            RelayConnectionChangeReason::ConfigurationChange,
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);

        time::advance(expected_first_segment_duration).await;

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_relay_event.public_key,
                start: segment_start.into(),
                duration: expected_first_segment_duration,
                connection_data: ConnectionData::Relay {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );

        // Let's make a second round to see if the first one left a valid state
        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);

        time::advance(expected_second_segment_duration).await;

        let expected_second_segment_start = segment_start + expected_first_segment_duration;
        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            ConnectionSegmentData {
                node: current_relay_event.public_key,
                start: expected_second_segment_start.into(),
                duration: expected_second_segment_duration,
                connection_data: ConnectionData::Relay {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_conn_data_serialization() {
        let mut writer = WriterBuilder::new()
            .flexible(true)
            .delimiter(b':')
            .terminator(csv::Terminator::Any(b','))
            .from_writer(vec![]);

        let conn_datas = vec![
            ConnectionData::Relay {
                state: RelayConnectionState::Connected,
                reason: RelayConnectionChangeReason::ConfigurationChange,
            },
            ConnectionData::Peer {
                endpoints: PeerEndpointTypes {
                    initiator_ep: EndpointType::UPnP,
                    responder_ep: EndpointType::Local,
                },
                rx_bytes: 1000,
                tx_bytes: 500,
            },
        ];

        for conn_data in conn_datas {
            writer.serialize(("prefix", conn_data)).unwrap();
        }

        let str_result = String::from_utf8(writer.into_inner().unwrap()).unwrap();

        assert_eq!(str_result, "prefix:257:101,prefix:49:1000:500,");
    }
}
