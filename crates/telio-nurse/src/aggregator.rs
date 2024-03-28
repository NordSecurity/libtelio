use std::{collections::hash_map::Entry, mem, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{sync::Mutex, time::Instant};

use serde::{ser::SerializeTuple, Serialize};

use telio_crypto::PublicKey;
use telio_model::{
    config::{DerpAnalyticsEvent, RelayConnectionChangeReason, RelayState},
    features::{EndpointProvider, FeatureNurse},
    HashMap,
};
use telio_utils::telio_log_warn;
use telio_wg::{
    uapi::{AnalyticsEvent, PeerState},
    WireGuard,
};

#[cfg(feature = "mockall")]
use mockall::automock;

const DAY_DURATION: Duration = Duration::from_secs(60 * 60 * 24);

// Possible Relay connection states - because all of the first 8 bit combinations
// are reserved for relay states, they need to have the 9th bit on
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub(crate) enum RelayConnectionState {
    Connecting = 256,
    Connected = 257,
}

impl From<RelayState> for RelayConnectionState {
    fn from(value: RelayState) -> Self {
        if let RelayState::Connected = value {
            RelayConnectionState::Connected
        } else {
            RelayConnectionState::Connecting
        }
    }
}

// Possible endpoint connection types
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum EndpointType {
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
pub(crate) struct PeerEndpointTypes {
    initiator_ep: EndpointType,
    responder_ep: EndpointType,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PeerConnectionData {
    endpoints: PeerEndpointTypes,
    rx_bytes: u64,
    tx_bytes: u64,
}

const ENDPOINT_BIT_FIELD_WIDTH: u16 = 4;
const RELAY_TUPLE_LEN: usize = 2;
const PEER_TUPLE_LEN: usize = 3;

impl Serialize for PeerConnectionData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let PeerConnectionData {
            endpoints,
            rx_bytes,
            tx_bytes,
        } = self;
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

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RelayConnectionData {
    state: RelayConnectionState,
    reason: RelayConnectionChangeReason,
}

impl Serialize for RelayConnectionData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let RelayConnectionData { state, reason } = self;
        let mut seq = serializer.serialize_tuple(RELAY_TUPLE_LEN)?;
        seq.serialize_element(&(*state as u64))?;
        seq.serialize_element::<u64>(&(Into::into(*reason)))?;
        seq.end()
    }
}

// Ready to send connection data for some period of time
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RelayConnDataSegment {
    server_address: SocketAddr,
    start: Instant, // to ensure the segments are unique
    duration: Duration,
    connection_data: RelayConnectionData,
}

impl RelayConnDataSegment {
    fn new(event: &DerpAnalyticsEvent, target_timestamp: Instant) -> Self {
        RelayConnDataSegment {
            server_address: event.server_address,
            start: event.timestamp,
            duration: target_timestamp.duration_since(event.timestamp),
            connection_data: RelayConnectionData {
                state: event.state.into(),
                reason: event.reason,
            },
        }
    }
}

// Ready to send connection data for some period of time
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PeerConnDataSegment {
    node: PublicKey,
    start: Instant, // to ensure the segments are unique
    duration: Duration,
    connection_data: PeerConnectionData,
}

impl PeerConnDataSegment {
    fn new(
        peer_event: &AnalyticsEvent,
        endpoints: PeerEndpointTypes,
        target_timestamp: Instant,
        target_rx_bytes: u64,
        target_tx_bytes: u64,
    ) -> Self {
        PeerConnDataSegment {
            node: peer_event.public_key,
            start: peer_event.timestamp.into(),
            duration: target_timestamp.duration_since(peer_event.timestamp.into()),
            connection_data: PeerConnectionData {
                endpoints,
                rx_bytes: target_rx_bytes - peer_event.rx_bytes,
                tx_bytes: target_tx_bytes - peer_event.tx_bytes,
            },
        }
    }
}

struct AggregatorData {
    current_relay_event: Option<DerpAnalyticsEvent>,
    current_peer_events: HashMap<PublicKey, (AnalyticsEvent, PeerEndpointTypes)>,
    peer_segments: Vec<PeerConnDataSegment>,
    relay_segments: Vec<RelayConnDataSegment>,
}

/// A container to store the connectivity data for the Meshnet peers used by Nurse
#[allow(dead_code)]
pub struct ConnectivityDataAggregator {
    data: Mutex<AggregatorData>,

    aggregate_relay_events: bool,
    aggregate_nat_traversal_events: bool,

    wg_interface: Arc<dyn WireGuard>,
}

// Internal Nurse structure for prepared segment data collection
#[allow(dead_code)]
pub(crate) struct AggregatorCollectedSegments {
    pub(crate) relay: Vec<RelayConnDataSegment>,
    pub(crate) peer: Vec<PeerConnDataSegment>,
}

#[allow(dead_code)]
#[cfg_attr(feature = "mockall", automock)]
impl ConnectivityDataAggregator {
    /// Create a new DataConnectivityAggregator instance
    pub fn new(
        nurse_features: Option<FeatureNurse>,
        wg_interface: Arc<dyn WireGuard>,
    ) -> ConnectivityDataAggregator {
        ConnectivityDataAggregator {
            data: Mutex::new(AggregatorData {
                current_relay_event: None,
                current_peer_events: HashMap::new(),
                peer_segments: Vec::new(),
                relay_segments: Vec::new(),
            }),
            aggregate_relay_events: nurse_features
                .as_ref()
                .map(|features| features.enable_relay_conn_data)
                .unwrap_or(false),
            aggregate_nat_traversal_events: nurse_features
                .map(|features| features.enable_nat_traversal_conn_data)
                .unwrap_or(false),
            wg_interface,
        }
    }

    /// Record a direct Meshnet peer state change
    ///
    /// # Arguments
    ///
    /// * `event` - Analytic event with the current direct peer state.
    /// * `initiator_ep` - Endpoint provider used by the direct connection initiator.
    /// * `responder_ep` - Endpoint provider used by the direct connection responder.
    pub(crate) async fn change_peer_state_direct(
        &self,
        event: &AnalyticsEvent,
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
        .await
    }

    /// Record a relayed Meshnet peer state change
    ///
    /// # Arguments
    ///
    /// * `event` - Analytic event with the current relayed peer state.
    pub(crate) async fn change_peer_state_relayed(&self, event: &AnalyticsEvent) {
        self.change_peer_state_common(
            event,
            PeerEndpointTypes {
                initiator_ep: EndpointType::Relay,
                responder_ep: EndpointType::Relay,
            },
        )
        .await
    }

    async fn change_peer_state_common(&self, event: &AnalyticsEvent, endpoints: PeerEndpointTypes) {
        if !self.aggregate_nat_traversal_events {
            return;
        }

        let mut data_guard = self.data.lock().await;
        let new_segment = match data_guard.current_peer_events.entry(event.public_key) {
            Entry::Occupied(mut entry)
                if entry.get().0.peer_state != event.peer_state || entry.get().1 != endpoints =>
            {
                let new_segment = PeerConnDataSegment::new(
                    &entry.get().0,
                    entry.get().1,
                    event.timestamp.into(),
                    event.rx_bytes,
                    event.tx_bytes,
                );

                if event.peer_state != PeerState::Connected {
                    entry.remove();
                } else {
                    entry.insert((event.clone(), endpoints));
                }

                Some(new_segment)
            }
            Entry::Vacant(entry) if event.peer_state == PeerState::Connected => {
                entry.insert((event.clone(), endpoints));
                None
            }
            _ => None,
        };

        data_guard.peer_segments.extend(new_segment);
    }

    /// Record a relay server state change
    ///
    /// # Arguments
    ///
    /// * `server_state` - Current derp server state.
    /// * `reason` - Reason of the state change.
    pub async fn change_relay_state(&self, event: DerpAnalyticsEvent) {
        if !self.aggregate_relay_events {
            return;
        }

        let mut data_guard = self.data.lock().await;

        let new_segment = data_guard
            .current_relay_event
            .as_ref()
            .filter(|old_event| {
                old_event.server_address != event.server_address || old_event.state != event.state
            })
            .map(|old_event| RelayConnDataSegment::new(old_event, event.timestamp));

        if let Some(segment) = new_segment {
            data_guard.relay_segments.push(segment);
        }

        if new_segment.is_some() || data_guard.current_relay_event.is_none() {
            data_guard.current_relay_event = Some(event)
        }
    }

    /// Clear current peer and relay monitoring segments
    pub async fn clear_ongoinging_segments(&self) {
        let mut data_guard = self.data.lock().await;
        data_guard.current_peer_events.clear();
        data_guard.current_relay_event.take();
    }

    /// Force saves unacknowledged segments
    pub async fn force_save_unacknowledged_segments(&self) {
        self.save_unacknowledged_segments(true).await;
    }

    /// Saves unacknowledged segments in a buffer
    ///
    /// # Arguments
    ///
    /// * `force_save` - Whether to force save current events
    async fn save_unacknowledged_segments(&self, force_save: bool) {
        // Getting wg_interface is first, so it won't await while mutex is locked
        let wg_interface = self.wg_interface.get_interface().await;
        let mut data_guard = self.data.lock().await;

        let current_timestamp = Instant::now();

        // Handle long-lasting relay events
        let mut new_relay_segments = Vec::new();
        if let Some(event) = data_guard
            .current_relay_event
            .as_mut()
            .filter(|relay_event| {
                current_timestamp.duration_since(relay_event.timestamp) > DAY_DURATION || force_save
            })
        {
            new_relay_segments.push(RelayConnDataSegment::new(event, current_timestamp));
            event.timestamp = current_timestamp;
        }

        // Handle long-lasting peer events
        let mut new_peer_segments = Vec::new();
        if let Ok(wg_peers) = wg_interface.map(|wgi| wgi.peers) {
            for (peer_event, peer_state) in data_guard.current_peer_events.values_mut() {
                let since_last_event =
                    current_timestamp.duration_since(Instant::from_std(peer_event.timestamp));
                if since_last_event > DAY_DURATION || force_save {
                    wg_peers
                        .get(&peer_event.public_key)
                        .and_then(|wg_peer| wg_peer.rx_bytes.zip(wg_peer.tx_bytes))
                        .map_or_else(
                            || {
                                telio_log_warn!("Unable to get transfer data for peer");
                            },
                            |(rx_bytes, tx_bytes)| {
                                new_peer_segments.push(PeerConnDataSegment::new(
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

        if force_save {
            data_guard.current_relay_event.take();
            data_guard.current_peer_events.clear();
        }

        data_guard.relay_segments.extend(new_relay_segments);
        data_guard
            .relay_segments
            .sort_by(|a, b| a.start.cmp(&b.start));
        data_guard
            .peer_segments
            .extend(new_peer_segments.into_iter());
        data_guard
            .peer_segments
            .sort_by(|a, b| a.start.cmp(&b.start));
    }

    /// Collects unacknowledged segments
    #[allow(dead_code)]
    pub(crate) async fn collect_unacknowledged_segments(&self) -> AggregatorCollectedSegments {
        self.save_unacknowledged_segments(false).await;
        let mut data_guard = self.data.lock().await;
        AggregatorCollectedSegments {
            relay: mem::take(&mut data_guard.relay_segments),
            peer: mem::take(&mut data_guard.peer_segments),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        net::{IpAddr, Ipv4Addr},
    };

    use csv::WriterBuilder;
    use telio_model::config::Server;
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
        wg_interface: Arc<dyn WireGuard>,
    ) -> ConnectivityDataAggregator {
        let nurse_features = FeatureNurse {
            enable_relay_conn_data: enable_relay_conn_data,
            enable_nat_traversal_conn_data: enable_nat_traversal_conn_data,
            ..Default::default()
        };

        ConnectivityDataAggregator::new(Some(nurse_features), wg_interface)
    }

    fn create_basic_peer_event(n: u8) -> AnalyticsEvent {
        AnalyticsEvent {
            public_key: PublicKey(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            dual_ip_addresses: vec![
                DualTarget::new((Some(Ipv4Addr::from([n, n, n, n])), None)).unwrap()
            ], // Whatever
            tx_bytes: 0, // Just start with no data sent
            rx_bytes: 0,
            peer_state: PeerState::Connected,
            timestamp: Instant::now().into(),
        }
    }

    fn create_basic_relay_event() -> DerpAnalyticsEvent {
        DerpAnalyticsEvent::new(
            &Server {
                public_key: PublicKey(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                conn_state: RelayState::Connected,
                ipv4: Ipv4Addr::new(1, 1, 1, 1),
                relay_port: 1111,
                ..Default::default()
            },
            RelayConnectionChangeReason::ConfigurationChange,
        )
    }

    #[tokio::test]
    async fn test_aggregator_relay_multiple_servers() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let aggregator = create_aggregator(true, false, Arc::new(wg_interface)).await;

        // Expected segment lengths
        let first_segment_length1 = Duration::from_secs(30);
        let first_segment_length2 = Duration::from_secs(30);
        let second_segment_length = Duration::from_secs(50);
        let third_segment_lenght = Duration::from_secs(70);
        let fourth_segment_length = Duration::from_secs(80);

        // Initial event
        let mut current_relay_event = create_basic_relay_event();
        let first_serv_addr = current_relay_event.server_address;
        let second_serv_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 2222);
        let segment_start = current_relay_event.timestamp;
        aggregator
            .change_relay_state(current_relay_event.clone())
            .await;

        // Repeated state after some time
        current_relay_event.timestamp += first_segment_length1;
        aggregator
            .change_relay_state(current_relay_event.clone())
            .await;

        // Change server event
        current_relay_event.timestamp += first_segment_length2;
        let second_segment_start = current_relay_event.timestamp;
        current_relay_event.server_address = second_serv_addr;
        aggregator
            .change_relay_state(current_relay_event.clone())
            .await;

        // And after 50 seconds some disconnect due to network error
        current_relay_event.timestamp += second_segment_length;
        let third_segment_start = current_relay_event.timestamp;
        current_relay_event.reason = RelayConnectionChangeReason::IoError(ErrorKind::BrokenPipe);
        current_relay_event.state = RelayState::Connecting;
        aggregator
            .change_relay_state(current_relay_event.clone())
            .await;

        // We want to see also the connecting period, so let's make it connect in the end
        current_relay_event.timestamp += third_segment_lenght;
        let fourth_segment_start = current_relay_event.timestamp;
        current_relay_event.reason = RelayConnectionChangeReason::ConfigurationChange;
        current_relay_event.state = RelayState::Connected;
        current_relay_event.server_address = first_serv_addr;
        aggregator
            .change_relay_state(current_relay_event.clone())
            .await;

        // And let's add one more segment with the old pubkey
        current_relay_event.timestamp += fourth_segment_length;
        current_relay_event.reason = RelayConnectionChangeReason::IoError(ErrorKind::TimedOut);
        current_relay_event.state = RelayState::Disconnected;
        aggregator.change_relay_state(current_relay_event).await;

        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 4);

        assert_eq!(
            segments[0],
            RelayConnDataSegment {
                server_address: first_serv_addr,
                start: segment_start,
                duration: first_segment_length1 + first_segment_length2,
                connection_data: RelayConnectionData {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );
        assert_eq!(
            segments[1],
            RelayConnDataSegment {
                server_address: second_serv_addr,
                start: second_segment_start,
                duration: second_segment_length,
                connection_data: RelayConnectionData {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );
        assert_eq!(
            segments[2],
            RelayConnDataSegment {
                server_address: second_serv_addr,
                start: third_segment_start,
                duration: third_segment_lenght,
                connection_data: RelayConnectionData {
                    state: RelayConnectionState::Connecting,
                    reason: RelayConnectionChangeReason::IoError(ErrorKind::BrokenPipe)
                }
            }
        );
        assert_eq!(
            segments[3],
            RelayConnDataSegment {
                server_address: first_serv_addr,
                start: fourth_segment_start,
                duration: fourth_segment_length,
                connection_data: RelayConnectionData {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_aggregator_disabled() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let aggregator = create_aggregator(false, false, Arc::new(wg_interface)).await;

        // Initial event
        let mut current_peer_event = create_basic_peer_event(1);
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Local,
            )
            .await;

        // And after 60 seconds some disconnect due to network error
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.peer_state = PeerState::Connecting;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator
            .change_peer_state_relayed(&current_peer_event)
            .await;

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_aggregator_multiple_events_single_segment() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let aggregator = create_aggregator(false, true, Arc::new(wg_interface)).await;

        // Initial event
        let mut current_peer_event = create_basic_peer_event(1);
        let segment_start = current_peer_event.timestamp;
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Local,
            )
            .await;

        // Send one more event with the same state
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Local,
            )
            .await;

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 0);

        // And after 60 seconds some disconnect
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.peer_state = PeerState::Connecting;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator
            .change_peer_state_relayed(&current_peer_event)
            .await;

        // And after 60 seconds connect again
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.peer_state = PeerState::Connected;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator
            .change_peer_state_relayed(&current_peer_event)
            .await;

        // We don't gather periods of time when peer is disconnected, so we should have here only one segment
        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: segment_start.into(),
                duration: Duration::from_secs(120),
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::UPnP,
                        responder_ep: EndpointType::Local,
                    },
                    rx_bytes: 2000,
                    tx_bytes: 4000
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test]
    async fn test_aggregator_multiple_events_multiple_segments() {
        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(|| Ok(Default::default()));
        let aggregator = create_aggregator(false, true, Arc::new(wg_interface)).await;

        // Initial event
        let mut current_peer_event = create_basic_peer_event(1);
        let first_segment_start = current_peer_event.timestamp;
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Local,
            )
            .await;

        // Send one more event with the different state
        current_peer_event.timestamp += Duration::from_secs(60);
        let second_segment_start = current_peer_event.timestamp;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Upnp,
            )
            .await;

        // Change state again
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.rx_bytes += 2000;
        current_peer_event.tx_bytes += 4000;
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Local,
                EndpointProvider::Upnp,
            )
            .await;

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 2);
        assert_eq!(
            segments[0],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: first_segment_start.into(),
                duration: Duration::from_secs(60),
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::UPnP,
                        responder_ep: EndpointType::Local,
                    },
                    rx_bytes: 1000,
                    tx_bytes: 2000
                }
            }
        );
        assert_eq!(
            segments[1],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: second_segment_start.into(),
                duration: Duration::from_secs(60),
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::UPnP,
                        responder_ep: EndpointType::UPnP,
                    },
                    rx_bytes: 2000,
                    tx_bytes: 4000
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_aggregator_24h_segment_peer() {
        // Initial event
        let current_peer_event = create_basic_peer_event(1);
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
        let aggregator = create_aggregator(false, true, Arc::new(wg_interface)).await;

        // Insert the first event
        aggregator
            .change_peer_state_relayed(&current_peer_event)
            .await;

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 0);

        time::advance(expected_first_segment_duration).await;

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: segment_start.into(),
                duration: expected_first_segment_duration,
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::Relay,
                        responder_ep: EndpointType::Relay,
                    },
                    rx_bytes: 3333,
                    tx_bytes: 1111
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 0);

        time::advance(expected_second_segment_duration).await;

        let expected_second_segment_start = segment_start + expected_first_segment_duration;
        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: expected_second_segment_start.into(),
                duration: expected_second_segment_duration,
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::Relay,
                        responder_ep: EndpointType::Relay,
                    },
                    rx_bytes: 0,
                    tx_bytes: 0
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_aggregator_24h_segment_relay() {
        let current_relay_event = create_basic_relay_event();
        let segment_start = Instant::now();
        let expected_first_segment_duration = DAY_DURATION + Duration::from_secs(1);
        let expected_second_segment_duration = DAY_DURATION + Duration::from_secs(2);

        let mut wg_interface = MockWireGuard::new();
        wg_interface
            .expect_get_interface()
            .returning(move || Ok(Default::default()));
        let aggregator = create_aggregator(true, false, Arc::new(wg_interface)).await;

        aggregator
            .change_relay_state(current_relay_event.clone())
            .await;

        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 0);

        time::advance(expected_first_segment_duration).await;

        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            RelayConnDataSegment {
                server_address: current_relay_event.server_address,
                start: segment_start,
                duration: expected_first_segment_duration,
                connection_data: RelayConnectionData {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );

        // Let's make a second round to see if the first one left a valid state
        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 0);

        time::advance(expected_second_segment_duration).await;

        let expected_second_segment_start = segment_start + expected_first_segment_duration;
        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            RelayConnDataSegment {
                server_address: current_relay_event.server_address,
                start: expected_second_segment_start,
                duration: expected_second_segment_duration,
                connection_data: RelayConnectionData {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            }
        );

        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_aggregator_force_close() {
        let state_start_difference = Duration::from_secs(5);
        let expected_segment_duration = Duration::from_secs(721);
        let expected_second_segment_duration = DAY_DURATION + Duration::from_secs(2);

        let current_relay_event = create_basic_relay_event();
        let relay_segment_start = Instant::now();

        let mut wg_interface = MockWireGuard::new();
        let lambda_pk = create_basic_peer_event(2).public_key;
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
        let aggregator = create_aggregator(true, true, Arc::new(wg_interface)).await;

        aggregator
            .change_relay_state(current_relay_event.clone())
            .await;

        aggregator.collect_unacknowledged_segments().await;

        // Just to make sure the order will be correct
        time::advance(state_start_difference).await;

        let current_peer_event = create_basic_peer_event(2);

        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Stun,
            )
            .await;

        time::advance(expected_segment_duration).await;

        aggregator.save_unacknowledged_segments(true).await;

        let AggregatorCollectedSegments {
            relay: relay_segments,
            peer: peer_segments,
        } = aggregator.collect_unacknowledged_segments().await;
        assert_eq!(relay_segments.len(), 1);
        assert_eq!(
            relay_segments[0],
            RelayConnDataSegment {
                server_address: current_relay_event.server_address,
                start: relay_segment_start,
                duration: state_start_difference + expected_segment_duration,
                connection_data: RelayConnectionData {
                    state: RelayConnectionState::Connected,
                    reason: RelayConnectionChangeReason::ConfigurationChange
                }
            },
        );
        assert_eq!(peer_segments.len(), 1);
        assert_eq!(
            peer_segments[0],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: current_peer_event.timestamp.into(),
                duration: expected_segment_duration,
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::UPnP,
                        responder_ep: EndpointType::Stun,
                    },
                    rx_bytes: 3333,
                    tx_bytes: 1111
                }
            }
        );

        // Now let's move forward by more than one day to make sure that there are no events left
        time::advance(expected_second_segment_duration).await;

        // Make sure that the state was cleaned up
        let segments = aggregator.collect_unacknowledged_segments().await.relay;
        assert_eq!(segments.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_aggregator_sleep_wakeup() {
        let mut current_peer_event = create_basic_peer_event(1);
        let mut wg_interface = MockWireGuard::new();
        let lambda_pk = current_peer_event.public_key;
        wg_interface.expect_get_interface().returning(move || {
            Ok(Interface {
                peers: vec![(
                    lambda_pk,
                    Peer {
                        public_key: lambda_pk,
                        endpoint: None,
                        rx_bytes: Some(2000),
                        tx_bytes: Some(4000),
                        ..Default::default()
                    },
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            })
        });
        let aggregator = create_aggregator(false, true, Arc::new(wg_interface)).await;

        // Initial event
        let first_segment_start = current_peer_event.timestamp;
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Local,
            )
            .await;

        current_peer_event.timestamp += Duration::from_secs(600);
        let second_segment_start = current_peer_event.timestamp;
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Upnp,
                EndpointProvider::Upnp,
            )
            .await;

        time::advance(Duration::from_secs(800)).await;

        // Sleep is called
        aggregator.save_unacknowledged_segments(true).await;

        let segments = aggregator.collect_unacknowledged_segments().await.peer;
        assert_eq!(segments.len(), 2);
        assert_eq!(
            segments[0],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: first_segment_start.into(),
                duration: Duration::from_secs(600),
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::UPnP,
                        responder_ep: EndpointType::Local,
                    },
                    rx_bytes: 1000,
                    tx_bytes: 2000
                }
            }
        );
        assert_eq!(
            segments[1],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: second_segment_start.into(),
                duration: Duration::from_secs(200),
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::UPnP,
                        responder_ep: EndpointType::UPnP,
                    },
                    rx_bytes: 1000,
                    tx_bytes: 2000
                }
            }
        );

        // Wakeup is called
        aggregator.clear_ongoinging_segments().await;

        aggregator
            .change_peer_state_direct(
                &current_peer_event,
                EndpointProvider::Local,
                EndpointProvider::Upnp,
            )
            .await;

        current_peer_event.peer_state = PeerState::Connecting;
        current_peer_event.timestamp += Duration::from_secs(60);
        current_peer_event.rx_bytes += 1000;
        current_peer_event.tx_bytes += 2000;
        aggregator
            .change_peer_state_relayed(&current_peer_event)
            .await;

        let segments = aggregator.collect_unacknowledged_segments().await.peer;

        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0],
            PeerConnDataSegment {
                node: current_peer_event.public_key,
                start: second_segment_start.into(),
                duration: Duration::from_secs(60),
                connection_data: PeerConnectionData {
                    endpoints: PeerEndpointTypes {
                        initiator_ep: EndpointType::Local,
                        responder_ep: EndpointType::UPnP,
                    },
                    rx_bytes: 1000,
                    tx_bytes: 2000
                }
            }
        );
    }

    #[tokio::test]
    async fn test_relay_conn_data_serialization() {
        let mut writer = WriterBuilder::new()
            .flexible(true)
            .delimiter(b':')
            .terminator(csv::Terminator::Any(b','))
            .from_writer(vec![]);

        let conn_datas = vec![
            RelayConnectionData {
                state: RelayConnectionState::Connected,
                reason: RelayConnectionChangeReason::ConfigurationChange,
            },
            RelayConnectionData {
                state: RelayConnectionState::Connecting,
                reason: RelayConnectionChangeReason::IoError(ErrorKind::TimedOut),
            },
        ];

        for conn_data in conn_datas {
            writer.serialize(("prefix", conn_data)).unwrap();
        }

        let str_result = String::from_utf8(writer.into_inner().unwrap()).unwrap();

        assert_eq!(str_result, "prefix:257:0,prefix:256:222,");
    }

    #[tokio::test]
    async fn test_peer_conn_data_serialization() {
        let mut writer = WriterBuilder::new()
            .flexible(true)
            .delimiter(b':')
            .terminator(csv::Terminator::Any(b','))
            .from_writer(vec![]);

        let conn_datas = vec![
            PeerConnectionData {
                endpoints: PeerEndpointTypes {
                    initiator_ep: EndpointType::Local,
                    responder_ep: EndpointType::Stun,
                },
                rx_bytes: 1500,
                tx_bytes: 700,
            },
            PeerConnectionData {
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

        assert_eq!(str_result, "prefix:18:1500:700,prefix:49:1000:500,");
    }
}
