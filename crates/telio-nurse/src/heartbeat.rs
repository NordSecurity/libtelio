use async_trait::async_trait;
use bitflags::bitflags;
use futures::FutureExt;
use nat_detect::NatType;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    hash::Hash,
    pin::Pin,
};
use telio_crypto::{PublicKey, SecretKey};
use telio_model::config::{RelayState, Server};
use telio_model::{
    event::Event,
    mesh::{get_ip_stack, IpStack, NodeState},
};
use telio_nat_detect::nat_detection::{retrieve_single_nat, NatData};
use telio_proto::{HeartbeatMessage, HeartbeatNatType, HeartbeatStatus, HeartbeatType};
use telio_relay::multiplexer::Multiplexer;
use telio_relay::DerpRelay;
use telio_task::{
    io::{chan, mc_chan, Chan},
    Runtime, RuntimeExt, WaitResponse,
};
use telio_utils::{map_enum, telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};
use telio_wg::uapi::PeerState;
use tokio::time::{interval_at, sleep, Duration, Instant, Interval, MissedTickBehavior, Sleep};
use uuid::Uuid;

use crate::config::HeartbeatConfig;
use crate::data::{AnalyticsMessage, HeartbeatInfo, MeshConfigUpdateEvent};

/// Approximately 30 years worth of time, used to pause timers and periods
const FAR_FUTURE: Duration = Duration::from_secs(86400 * 365 * 30);

#[derive(PartialEq, Eq, Debug)]
enum RuntimeState {
    Monitoring,
    Collecting,
    Aggregating,
}

bitflags! {
    struct MeshConnectionState: u32 {
        const DERP      = 0b00000001;
        const WG        = 0b00000010;
        const IPV4      = 0b00000100;
        const IPV6      = 0b00001000;
        const IPV4V6    = Self::IPV4.bits
                        | Self::IPV6.bits;
    }
}

trait From<T> {
    fn from(t: T) -> Self;
}

map_enum! {
    NatType <=> HeartbeatNatType,
    UdpBlocked = UdpBlocked,
    FullCone = FullCone,
    RestrictedCone = RestrictedCone,
    OpenInternet = OpenInternet,
    PortRestrictedCone = PortRestrictedCone,
    Symmetric = Symmetric,
    SymmetricUdpFirewall = SymmetricUdpFirewall,
    Unknown = Unknown,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MeshLink {
    pub connection_state: MeshConnectionState,
}

impl Default for MeshLink {
    fn default() -> Self {
        MeshLink {
            connection_state: MeshConnectionState::empty(),
        }
    }
}

/// Input/output channel for Heartbeat
pub struct Io {
    /// Channel sending and receiving heartbeat data
    pub chan: Option<Chan<(PublicKey, HeartbeatMessage)>>,
    /// Event channel to gather derp events
    pub derp_event_channel: Option<mc_chan::Rx<Box<Server>>>,
    /// Event channel to gather wg events
    pub wg_event_channel: mc_chan::Rx<Box<Event>>,
    /// Event channel to gather local nodes from mesh config updates
    pub config_update_channel: mc_chan::Rx<Box<MeshConfigUpdateEvent>>,
    /// Channel for sending and receiving analytics data
    pub analytics_channel: chan::Tx<AnalyticsMessage>,
    /// Event channel to manual trigger a collection
    pub collection_trigger_channel: mc_chan::Rx<Box<()>>,
}

enum NodeInfo {
    Node {
        mesh_link: MeshLink,
        meshnet_id: Option<Uuid>,
    },
    Vpn {
        mesh_link: MeshLink,
        hostname: Option<String>,
    },
}

impl Default for NodeInfo {
    fn default() -> Self {
        NodeInfo::Node {
            mesh_link: MeshLink::default(),
            meshnet_id: None,
        }
    }
}

#[derive(Default)]
struct Collection {
    pub meshnet_ids: HashMap<PublicKey, Uuid>,
    pub fingerprints: HashMap<PublicKey, String>,
    pub links: HashMap<(PublicKey, PublicKey), MeshLink>,
    pub nat_type_peers: HashMap<PublicKey, NatType>,
}

impl Collection {
    pub fn add_default_link(&mut self, lpk: PublicKey, rpk: PublicKey) {
        self.links.entry((lpk, rpk)).or_default();
        self.links.entry((rpk, lpk)).or_default();
    }

    pub fn add_unidirectional_link(&mut self, lpk: PublicKey, rpk: PublicKey, link: MeshLink) {
        *self.links.entry((lpk, rpk)).or_default() = link;
    }

    pub fn add_meshnet_id(&mut self, pk: PublicKey, id: Uuid) {
        *self.meshnet_ids.entry(pk).or_default() = id;
    }

    pub fn add_fingerprint(&mut self, pk: PublicKey, fp: String) {
        *self.fingerprints.entry(pk).or_default() = fp;
    }

    pub fn add_peer_nat_type(&mut self, pk: PublicKey, nat_type: NatType) {
        self.nat_type_peers.insert(pk, nat_type);
    }

    /// Find meshnet ID that best represents our meshnet.
    ///
    /// This can be different than the meshnet_id we are starting with since it
    /// is based on all meshnet IDs reported by nodes during Collecting state.
    /// Among the collected meshnet IDs, we select the most common one and break
    /// the ties by selecting smallest (lexicographically) public keys' ID.
    ///
    /// The main point of doing it this way, is to prevent new nodes connecting
    /// from changing the reported ID - since all the old nodes will report old
    /// meshnet ID, the new node will also see the old meshnet ID as most common
    /// and will report it (instead of random one it generated at startup).
    pub fn resolve_current_meshnet_id(&self, config_local_nodes: &HashSet<PublicKey>) -> Uuid {
        // Figure out what meshnet id we should use, based on all of the collected data
        // Start off by generating a heatmap of the received ID's
        let mut id_heatmap: HashMap<Uuid, u32> = HashMap::new();
        self.meshnet_ids.iter().for_each(|(pk, id)| {
            if config_local_nodes.contains(pk) {
                *id_heatmap.entry(*id).or_default() += 1;
            }
        });

        // Then find the ids with the biggest amount of repetitions
        let max_value = id_heatmap
            .iter()
            .max_by(|l, r| l.1.cmp(r.1))
            .map(|(_, value)| value)
            .unwrap_or(&0);
        let maximal_ids = id_heatmap
            .iter()
            .filter(|(_, value)| max_value == *value)
            .map(|(id, _)| *id)
            .collect::<Vec<Uuid>>();

        // Since we can have more than one meshnet ID having the most amount of repetitions, we need to resolve this in a
        // predictable way, so we filter out the entries that share this maximum value and then sort them again by
        // the public key, from which the ID initially came from
        self.meshnet_ids
            .iter()
            .filter(|(_, id)| maximal_ids.contains(*id))
            .min_by(|l, r| l.0.cmp(r.0))
            .map(|(_, id)| *id)
            .unwrap_or_else(Uuid::new_v4)
    }

    pub fn clear(&mut self) {
        // Clear collected meshnet ids
        self.meshnet_ids.clear();
        // Clear collected fingerprints
        self.fingerprints.clear();
        // Clear collected links
        self.links.clear();
        // Clear collected member nat types
        self.nat_type_peers.clear();
    }
}

/// Heartbeat analytics contains:
/// * Task interval timer to know when the next send cycle is coming up
/// * Sleep timer that waits for a specified time after sending a report message to wait for responses
/// * Config that contains things like the collection intervals, timing windows and fingerprint of the node
/// * Io channel
/// * The id of the meshnet that the node is in
/// * Current runtime state of Nurse, is it currently collecting, aggregating or monitoring
/// * Cached meshnet config, used to defer link updating, in case we're not in the correct state for it at the time
/// * Cached private key, used to defer link updating, in case we're not in the correct state for it at the time
/// * Public key of the node
/// * Hashmaps of current nodes connection states, alongside connection states received from other nodes
/// * A hashmap of meshnet ID's that were received over one collection cycle, used to deduct the "winning" meshnet ID
/// * A hashmap containing the fingerprints of all of the nodes in the meshnet, indexed by the public keys of the nodes
/// * The state of DERP connection
pub struct Analytics {
    task_interval: Interval,
    collect_period: Pin<Box<Sleep>>,

    config: HeartbeatConfig,
    pub io: Io,

    meshnet_id: Uuid,
    state: RuntimeState,

    pub cached_private_key: Option<SecretKey>,
    cached_config: Option<MeshConfigUpdateEvent>,

    public_key: PublicKey,
    collection: Collection,

    // All the nodes we have a connection with according to wireguard
    local_nodes: HashMap<PublicKey, NodeInfo>,

    // All the nodes (public_key, is_local) according to config updates
    config_nodes: HashMap<PublicKey, bool>,

    // Fingerprint for each configured node
    fingerprints: HashMap<PublicKey, String>,

    derp_connection: bool,

    /// Was meshnet enabled for this device
    meshnet_enabled: bool,

    /// DERP Server instance
    pub derp: Option<Arc<DerpRelay>>,

    /// Our current IP stack
    ip_stack: Option<IpStack>,
}

#[async_trait]
impl Runtime for Analytics {
    const NAME: &'static str = "Nurse Heartbeat Analytics";

    type Err = ();

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        let derp_event_future = if let Some(channel) = self.io.derp_event_channel.as_mut() {
            channel.recv().left_future()
        } else {
            futures::future::pending().right_future()
        };

        let multiplexer_future = if let Some(channel) = self.io.chan.as_mut() {
            channel.rx.recv().left_future()
        } else {
            futures::future::pending().right_future()
        };

        tokio::select! {
            // wg event, only in the `Monitoring` state
            Ok(event) = self.io.wg_event_channel.recv(), if self.state == RuntimeState::Monitoring =>
                Self::guard(
                    async move {
                        self.handle_wg_event(*event).await;
                        telio_log_trace!("tokio::select! self.io.wg_event_channel.recv() branch");
                        Ok(())
                     }
                ),

            // Derp event, only in the `Monitoring` state
            Ok(event) = derp_event_future, if self.state == RuntimeState::Monitoring =>
                Self::guard(
                    async move {
                        self.handle_derp_event(*event).await;
                        telio_log_trace!("tokio::select! self.io.derp_event_channel.recv() branch");
                        Ok(())
                    }
                ),

            // MeshConfigUpdate event
            Ok(event) = self.io.config_update_channel.recv() =>
                Self::guard(
                    async move {
                        self.handle_config_update_event(*event).await;
                        telio_log_trace!("tokio::select! self.io.config_update_channel.recv() branch");
                        Ok(())
                    }
                ),

            // A collection event has been triggered from the outside, only in the `Monitoring` state
            Ok(_) = self.io.collection_trigger_channel.recv(), if self.state == RuntimeState::Monitoring =>
                Self::guard(
                    async move {
                        self.handle_collection().await;
                        telio_log_trace!("tokio::select! self.io.collection_trigger_channel.recv() branch");
                        Ok(())
                    }
                ),

            // Time to send a data request to other nodes, only update in the `Monitoring` state
            _ = self.task_interval.tick(), if self.state == RuntimeState::Monitoring =>
                Self::guard(
                    async move {
                        self.handle_collection().await;
                        telio_log_trace!("tokio::select! self.task_interval.tick() branch");
                        Ok(())
                    }
                ),

            // Received data from node, Should always listen for incoming data
            Some((pk, msg)) = multiplexer_future =>
                Self::guard(
                    async move {
                        self.message_handler((pk, msg)).await;
                        telio_log_trace!("tokio::select! self.io.chan.rx.recv() branch");
                        Ok(())
                    }
                ),

            // Time to aggregate collected data, only update when in the `Collecting` state
            _ = &mut self.collect_period, if self.state == RuntimeState::Collecting =>
                Self::guard(
                    async move {
                        self.handle_aggregation().await;
                        telio_log_trace!("tokio::select! self.collect_period branch");
                        Ok(())
                    }
                ),

            else => Self::next(),
        }
    }
}

/// Additional configuration for Nurse provided when meshnet is configured
pub struct MeshnetEntities {
    /// Pointer to DerpRelay service
    pub derp: Arc<DerpRelay>,

    /// Pointer to Multiplexer
    pub multiplexer: Arc<Multiplexer>,

    /// Derp event channel
    pub derp_event_channel: mc_chan::Tx<Box<Server>>,
}

impl Analytics {
    /// Create an empty Analytics instance.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key of the node.
    /// * `meshnet_id` - The ID of the meshnet the node is in.
    /// * `config` - Configuration for node heart beats.
    /// * `io` - A collection of channel to get different kinds of events.
    ///
    /// # Returns
    ///
    /// An empty Analytics instance with the given config
    pub fn new(public_key: PublicKey, meshnet_id: Uuid, config: HeartbeatConfig, io: Io) -> Self {
        let start_time = Instant::now() + config.initial_collect_interval;

        let mut interval: Interval = interval_at(start_time, config.collect_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut config_nodes = HashMap::new();
        // Add self in config_nodes hashset
        config_nodes.insert(public_key, true);

        Self {
            task_interval: interval,
            collect_period: Box::pin(sleep(FAR_FUTURE)),
            config,
            io,
            meshnet_id,
            state: RuntimeState::Monitoring,
            cached_private_key: None,
            cached_config: None,
            public_key,
            collection: Collection::default(),
            local_nodes: HashMap::new(),
            config_nodes,
            fingerprints: HashMap::new(),
            derp_connection: false,
            meshnet_enabled: false,
            derp: None,
            ip_stack: None,
        }
    }

    pub async fn configure_meshnet(&mut self, meshnet_entities: Option<MeshnetEntities>) {
        if let Some(MeshnetEntities {
            derp,
            multiplexer,
            derp_event_channel,
        }) = meshnet_entities
        {
            self.derp = Some(derp);
            self.io.chan = Some(
                multiplexer
                    .get_channel::<HeartbeatMessage>()
                    .await
                    .unwrap_or_default(),
            );
            self.io.derp_event_channel = Some(derp_event_channel.subscribe());

            telio_log_debug!("Meshnet analytics enabled");
        } else {
            self.derp = None;
            self.io.chan = None;
            self.io.derp_event_channel = None;

            telio_log_debug!("Meshnet analytics disabled");
        }
    }

    /// Update the public key of the node by getting the public key of `cached_private_key`.
    /// Since changing the key causes existing links to point to a key that no longer exists,
    /// this function also updates local and external links.
    ///
    /// Will only do something if the node is in a monitoring state.
    pub async fn update_public_key(&mut self) {
        // We should only update the state of the links if we're in the monitoring state
        if self.state == RuntimeState::Monitoring {
            if let Some(private_key) = self.cached_private_key.take() {
                let old_public_key = self.public_key;

                self.public_key = private_key.public();

                self.config_nodes.remove(&old_public_key);
                self.config_nodes.insert(self.public_key, true);
            }
        }
    }

    async fn update_config(&mut self) {
        if let Some(cached_config) = self.cached_config.take() {
            self.handle_config_update_event(cached_config).await;
        }
    }

    async fn handle_wg_event(&mut self, event: Event) {
        if let Event::Node { body: Some(node) } = event {
            if node.state == PeerState::Disconnected {
                let _ = self.local_nodes.remove(&node.public_key);
            } else {
                let mut mesh_link = MeshLink::default();
                mesh_link
                    .connection_state
                    .set(MeshConnectionState::WG, node.state == NodeState::Connected);

                if let (Some(our_stack), Ok(nodes_stack)) =
                    (self.ip_stack.clone(), get_ip_stack(&node.ip_addresses))
                {
                    mesh_link.connection_state.set(
                        match (our_stack, nodes_stack) {
                            (IpStack::IPv4, IpStack::IPv4) => MeshConnectionState::IPV4,
                            (IpStack::IPv4v6, IpStack::IPv4) => MeshConnectionState::IPV4,
                            (IpStack::IPv4, IpStack::IPv4v6) => MeshConnectionState::IPV4,
                            (IpStack::IPv6, IpStack::IPv6) => MeshConnectionState::IPV6,
                            (IpStack::IPv4v6, IpStack::IPv6) => MeshConnectionState::IPV6,
                            (IpStack::IPv6, IpStack::IPv4v6) => MeshConnectionState::IPV6,
                            (IpStack::IPv4v6, IpStack::IPv4v6) => MeshConnectionState::IPV4V6,
                            _ => MeshConnectionState::empty(),
                        },
                        true,
                    );
                }

                let node_info = if node.is_vpn {
                    NodeInfo::Vpn {
                        mesh_link,
                        hostname: node.hostname.as_ref().cloned().or_else(|| {
                            node.endpoint.map(|endpoint| {
                                format!("{:x}", md5::compute(endpoint.to_string().as_bytes()))
                            })
                        }),
                    }
                } else {
                    NodeInfo::Node {
                        mesh_link,
                        meshnet_id: None,
                    }
                };

                *self.local_nodes.entry(node.public_key).or_default() = node_info;
            }
        }
    }

    async fn handle_derp_event(&mut self, event: Server) {
        self.derp_connection = event.conn_state == RelayState::Connected;
    }

    async fn handle_config_update_event(&mut self, event: MeshConfigUpdateEvent) {
        if self.state == RuntimeState::Monitoring {
            self.meshnet_enabled = event.enabled;
            self.config_nodes = event.nodes;
            self.ip_stack = event.ip_stack;
            // Add self to config nodes
            self.config_nodes.insert(self.public_key, true);
        } else {
            self.cached_config = Some(event);
        }
    }

    async fn handle_collection(&mut self) {
        // Clear everything from the previous collection
        self.collection.clear();

        let mut requests_sent = false;

        if let Some(chan) = self.io.chan.as_ref() {
            for pk in self.local_nodes.keys() {
                let heartbeat = HeartbeatMessage::request();

                #[allow(mpsc_blocking_send)]
                if chan.tx.send((*pk, heartbeat)).await.is_err() {
                    telio_log_warn!(
                        "Failed to send Nurse mesh Heartbeat request to node :{:?}",
                        pk
                    );
                };

                requests_sent = true;
            }
        }

        // Check whether there are any responses to wait for
        let collection_deadline = if requests_sent {
            Instant::now() + self.config.collect_answer_timeout
        } else {
            Instant::now()
        };

        // Start collection timer before starting to aggregate the data
        self.collect_period.as_mut().reset(collection_deadline);

        // Transition to the collection state
        self.state = RuntimeState::Collecting;
    }

    async fn message_handler(&mut self, data: (PublicKey, HeartbeatMessage)) {
        let pk = data.0;

        // Since we already got a message from the other node, we can assume that the derp connection is functioning from them to us
        match self.local_nodes.entry(pk).or_default() {
            NodeInfo::Vpn { mesh_link, .. } | NodeInfo::Node { mesh_link, .. } => {
                mesh_link
                    .connection_state
                    .set(MeshConnectionState::DERP, true);

                self.collection
                    .add_unidirectional_link(pk, self.public_key, *mesh_link);
                self.collection
                    .add_unidirectional_link(self.public_key, pk, *mesh_link);
            }
        }

        let heartbeat_message = data.1;

        match heartbeat_message.get_message_type() {
            // We received a request to send data over
            HeartbeatType::REQUEST => {
                telio_log_trace!(
                    "Received heartbeat request message: {:?}",
                    heartbeat_message
                );
                self.handle_request_message(pk, &heartbeat_message).await;
            }

            // We received a response with data from node
            HeartbeatType::RESPONSE => {
                // If we are currently not expecting to receive any response packets, we drop them
                if self.state != RuntimeState::Collecting {
                    telio_log_debug!("Received a response message at an unexpected time, dropping");
                    return;
                }
                telio_log_trace!(
                    "Received heartbeat response message: {:?}",
                    heartbeat_message
                );
                self.handle_response_message(pk, &heartbeat_message).await;
            }
        }
    }

    async fn handle_request_message(&mut self, pk: PublicKey, _message: &HeartbeatMessage) {
        let mut links: Vec<HeartbeatStatus> = Vec::new();
        for link in self.local_nodes.iter() {
            let mut status = HeartbeatStatus::new();
            status.node = link.0.to_vec();
            status.connection_state = match link.1 {
                NodeInfo::Vpn { mesh_link, .. } | NodeInfo::Node { mesh_link, .. } => {
                    mesh_link.connection_state.bits()
                }
            };

            links.push(status);
        }

        let heartbeat = HeartbeatMessage::response(
            self.meshnet_id.into_bytes().to_vec(),
            self.config.fingerprint.clone(),
            &links,
            <telio_proto::HeartbeatNatType as crate::heartbeat::From<NatType>>::from(
                self.retrieve_nat().await,
            ),
        );

        #[allow(mpsc_blocking_send)]
        if let Some(chan) = self.io.chan.as_ref() {
            if chan.tx.send((pk, heartbeat)).await.is_err() {
                telio_log_warn!(
                    "Failed to send Nurse mesh heartbeat message to node :{:?}",
                    pk
                );
            };
        }
    }

    async fn handle_response_message(&mut self, pk: PublicKey, message: &HeartbeatMessage) {
        // Add the received fingerprint to the collection
        self.collection
            .add_fingerprint(pk, message.get_node_fingerprint().to_string());

        if let Ok(received_meshnet_id) = Uuid::from_slice(message.get_meshnet_id()) {
            // Add the received meshnet_id to the collection
            self.collection.add_meshnet_id(pk, received_meshnet_id);

            // Update node's meshnet_id
            match self.local_nodes.entry(pk).or_default() {
                NodeInfo::Node { meshnet_id, .. } => *meshnet_id = Some(received_meshnet_id),
                _ => telio_log_warn!("Received meshnet_id from a vpn node"),
            }
        } else {
            telio_log_warn!("Failed to parse meshnet ID from Heartbeat message");
        }

        self.collection.add_peer_nat_type(
            pk,
            <nat_detect::NatType as crate::heartbeat::From<HeartbeatNatType>>::from(
                message.get_nat_type(),
            ),
        );

        message.get_statuses().iter().for_each(|status| {
            let link_state = MeshConnectionState::from_bits(status.connection_state)
                .map(|connection_state| MeshLink { connection_state });

            let other_key = status.node.clone().try_into();

            if let Ok(other_key) = other_key {
                if let Some(link_state) = link_state {
                    self.collection
                        .add_unidirectional_link(pk, other_key, link_state);
                } else {
                    telio_log_warn!(
                        "Failed to parse Nurse mesh heartbeat connection state, invalid data"
                    );
                }
            } else {
                telio_log_debug!(
                    "Could not parse link public key ({:?}) from a node response message",
                    status.node
                );
            }
        });
    }

    async fn handle_aggregation(&mut self) {
        // Transition to the aggregation state
        self.state = RuntimeState::Aggregating;

        // Add our temporary meshnet_id to collection before we try to resolve it
        self.collection
            .add_meshnet_id(self.public_key, self.meshnet_id);
        let config_local_nodes = self
            .config_nodes
            .iter()
            .filter(|(_, is_local)| **is_local)
            .map(|(pk, _)| *pk)
            .collect::<HashSet<_>>();
        self.meshnet_id = self
            .collection
            .resolve_current_meshnet_id(&config_local_nodes);

        // All local nodes will have the same meshnet id
        for pk in config_local_nodes.iter() {
            if let NodeInfo::Node { meshnet_id, .. } = self.local_nodes.entry(*pk).or_default() {
                *meshnet_id = Some(self.meshnet_id);
            }
        }

        let mut heartbeat_info = HeartbeatInfo {
            meshnet_id: self.meshnet_id.to_string(),
            meshnet_enabled: self.meshnet_enabled,
            heartbeat_interval: i32::try_from(self.config.collect_interval.as_secs()).unwrap_or(0),
            ..Default::default()
        };

        self.collection
            .fingerprints
            .insert(self.public_key, self.config.fingerprint.clone());

        // Insert all the nodes from the config
        for (node, _) in self.config_nodes.iter() {
            self.collection
                .fingerprints
                .entry(*node)
                .or_insert_with(|| String::from("null"));
        }

        // Update stored fingerprints
        for (node, fp) in self.collection.fingerprints.iter() {
            self.fingerprints
                .entry(*node)
                .and_modify(|stored_fp| {
                    if *fp != "null" {
                        *stored_fp = fp.clone()
                    }
                })
                .or_insert_with(|| fp.clone());
        }

        // Drop nodes not present in the collection/config anymore
        let dropped_nodes: Vec<_> = self
            .fingerprints
            .iter()
            .filter(|(node, _)| !self.collection.fingerprints.contains_key(node))
            .map(|(node, _)| *node)
            .collect();
        for node in dropped_nodes {
            self.fingerprints.remove(&node);
        }

        // Use BTreeSet to sort out the public keys
        // We sort public keys, instead of sorting by fingerprints, since fingerprints can be empty or null, resulting in
        // multiple same values, which make having a consistent layout for each node awkward to implement
        let internal_sorted_public_keys = self
            .fingerprints
            .iter()
            .map(|x| *x.0)
            .filter(|pk| self.is_local(*pk))
            .collect::<BTreeSet<_>>();

        let mut external_sorted_public_keys = self
            .fingerprints
            .iter()
            .map(|x| *x.0)
            .filter(|pk| !self.is_local(*pk))
            .collect::<BTreeSet<_>>();

        self.local_nodes.iter().for_each(|(pk, node_info)| {
            if let NodeInfo::Vpn { .. } = node_info {
                external_sorted_public_keys.insert(*pk);
            }
        });

        heartbeat_info.internal_sorted_public_keys = internal_sorted_public_keys.clone();
        heartbeat_info.external_sorted_public_keys = external_sorted_public_keys.clone();

        // Map node public keys to indices for the connectivity matrix alonside creating a sorted fingerprint list
        let mut index_map: HashMap<PublicKey, u8> = HashMap::new();
        let mut internal_sorted_fingerprints: Vec<String> = Vec::new();

        for (i, pk) in internal_sorted_public_keys.iter().enumerate() {
            // Since the public key array is already sorted, we can just insert the index from the `enumerate` iterator here
            index_map.entry(*pk).or_insert(i as u8);

            // By the same token, we can just insert the respective fingerprint into the list of sorted fingerprints
            if let Some(fp) = self.fingerprints.get(pk).cloned() {
                internal_sorted_fingerprints.push(fp);
            }
        }

        // Construct a string containing all of the sorted fingerprints to send to moose
        heartbeat_info.fingerprints = internal_sorted_fingerprints
            .iter()
            .fold(String::new(), |o, t| o + t.as_str() + ",");
        heartbeat_info.fingerprints.pop();

        // Fill in the missing external links, in case we haven't gotten a response from some nodes
        for i in index_map.keys() {
            for j in index_map.keys() {
                if i != &self.public_key && i != j {
                    self.collection.add_default_link(*i, *j);
                }
            }
        }

        let mut connectivity_matrix = String::new();
        // Loop over all of the possible combinations of links, assuming that the directionality of the connection does not matter
        for i in index_map.iter() {
            for j in index_map.iter() {
                if i.1 >= j.1 {
                    continue;
                }

                // We take both directions of the link at the same time
                let link1 = self
                    .collection
                    .links
                    .get(&(*i.0, *j.0))
                    .cloned()
                    .unwrap_or_default();
                let link2 = self
                    .collection
                    .links
                    .get(&(*j.0, *i.0))
                    .cloned()
                    .unwrap_or_default();

                // And only output the minimum, or the worst reported connection from the pair as the representing connection
                let min = link1.min(link2);
                if min == MeshLink::default() {
                    continue;
                }

                // And if this state differs from the default state of the matrix, we add this to the final output
                write!(
                    connectivity_matrix,
                    "{}:{}:{},",
                    i.1, j.1, min.connection_state.bits
                )
                .expect("no");
            }
        }
        // Shave off the uneeded comma
        connectivity_matrix.pop();

        heartbeat_info.connectivity_matrix = connectivity_matrix;

        // External links
        let mut external_links = String::new();
        for key in external_sorted_public_keys.iter() {
            let node = self.local_nodes.entry(*key).or_default();

            let (meshnet_id, fingerprint, connection_state) = match node {
                NodeInfo::Vpn {
                    mesh_link,
                    hostname,
                } => (
                    String::from("vpn"),
                    hostname.clone().unwrap_or_else(|| {
                        telio_log_warn!("Node with pk: {:?} has no fingerprint", key);
                        String::from("null")
                    }),
                    mesh_link.connection_state.bits,
                ),

                NodeInfo::Node {
                    mesh_link,
                    meshnet_id,
                    ..
                } => (
                    meshnet_id.map(|uuid| uuid.to_string()).unwrap_or_else(|| {
                        telio_log_warn!("Node with pk: {:?} has no meshnet id", key);
                        String::from("no-mesh-id")
                    }),
                    self.collection
                        .fingerprints
                        .get(key)
                        .cloned()
                        .unwrap_or_else(|| {
                            telio_log_warn!("Node with pk: {:?} has no fingerprint", key);
                            String::from("null")
                        }),
                    mesh_link.connection_state.bits,
                ),
            };

            if write!(
                external_links,
                "{meshnet_id}:{fingerprint}:{connection_state},"
            )
            .is_err()
            {
                telio_log_error!("Failed to write in external_links string");
            }
        }
        external_links.pop();
        heartbeat_info.external_links = external_links;

        // Collect NAT type
        heartbeat_info.nat_type = format!("{:?}", self.retrieve_nat().await);
        // Collect peer NAT types
        self.copy_nat_type(
            &mut heartbeat_info.peer_nat_types,
            internal_sorted_public_keys,
        );
        self.copy_nat_type(
            &mut heartbeat_info.peer_nat_types,
            external_sorted_public_keys,
        );

        // Send heartbeat info to Nurse
        #[allow(mpsc_blocking_send)]
        if self
            .io
            .analytics_channel
            .send(AnalyticsMessage::Heartbeat { heartbeat_info })
            .await
            .is_err()
        {
            telio_log_warn!("Failed to send Heartbeat message to Nurse");
        }

        // Shamelessly stolen from tokio's far_future(), we set the timer to timeout in the far future, effectively pausing it until needed again
        self.collect_period
            .as_mut()
            .reset(Instant::now() + FAR_FUTURE);

        // Transition back to the monitoring state afterwards
        self.state = RuntimeState::Monitoring;

        // In case we got a config update while aggregating data, attempt to update the state
        self.update_public_key().await;
        self.update_config().await;
    }

    fn copy_nat_type(&self, nat_types: &mut Vec<String>, sorted_pk: BTreeSet<PublicKey>) {
        for pk in sorted_pk.iter() {
            if let Some(nat_type) = self.collection.nat_type_peers.get(pk) {
                nat_types.push(format!("{:?}", nat_type));
            };
        }
    }

    async fn retrieve_nat(&mut self) -> NatType {
        if self.config.is_nat_type_collection_enabled {
            if let Some(server) = if let Some(derp_ptr) = self.derp.as_ref() {
                derp_ptr.get_connected_server().await
            } else {
                None
            } {
                retrieve_single_nat(SocketAddr::new(IpAddr::V4(server.ipv4), server.stun_port))
                    .await
                    .unwrap_or(NatData {
                        public_ip: SocketAddr::from(([0, 0, 0, 0], 80)),
                        nat_type: NatType::Unknown,
                    })
                    .nat_type
            } else {
                telio_log_error!("Unable to get a connected derp server");
                NatType::Unknown
            }
        } else {
            NatType::Unknown
        }
    }

    fn is_local(&self, pk: PublicKey) -> bool {
        if self.public_key == pk {
            return true;
        }

        if let Some(is_local) = self.config_nodes.get(&pk) {
            if *is_local {
                return true;
            }
        }

        match self.local_nodes.get(&pk) {
            Some(NodeInfo::Node { meshnet_id, .. }) => meshnet_id
                .as_ref()
                .map(|meshnet_id| *meshnet_id == self.meshnet_id)
                .unwrap_or(false),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use telio_model::{features::FeatureNurse, mesh::Node};
    use telio_sockets::{native::NativeSocket, Protector};
    use telio_task::{io::McChan, Task};
    use telio_utils::sync::mpsc::Receiver;
    use tokio::time::timeout;

    use super::*;

    struct FakeProtector;

    impl Protector for FakeProtector {
        fn make_external(&self, _: NativeSocket) -> std::io::Result<()> {
            Ok(())
        }

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
        fn make_internal(&self, _socket: NativeSocket) -> std::io::Result<()> {
            Ok(())
        }

        fn clean(&self, _: NativeSocket) {}

        #[cfg(target_os = "linux")]
        fn set_fwmark(&self, _fwmark: u32) {}

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos", windows))]
        fn set_tunnel_interface(&self, _interface: u64) {}
    }

    struct State {
        public_key: PublicKey,
        meshnet_id: Uuid,
        analytics_channel: Receiver<AnalyticsMessage>,
        analytics: Analytics,
    }

    fn setup(collect_interval: Option<Duration>) -> State {
        let sk = SecretKey::gen();
        let pk = sk.public();
        let meshnet_id = Uuid::new_v4();
        let mut config = HeartbeatConfig::new(&FeatureNurse::default());
        if let Some(interval) = collect_interval {
            config.collect_interval = interval;
        }

        let analytics_channel = Chan::new(1);
        let io = Io {
            chan: None,
            derp_event_channel: None,
            wg_event_channel: McChan::new(1).rx,
            config_update_channel: McChan::new(1).rx,
            analytics_channel: analytics_channel.tx,
            collection_trigger_channel: McChan::new(1).rx,
        };
        let analytics = Analytics::new(pk, meshnet_id, config, io);
        State {
            public_key: pk,
            meshnet_id,
            analytics_channel: analytics_channel.rx,
            analytics,
        }
    }

    async fn setup_local_nodes(
        analytics: &mut Analytics,
        enabled: bool,
        nodes: impl IntoIterator<Item = SecretKey>,
    ) {
        let is_local = true;
        let mesh_config_update_event = MeshConfigUpdateEvent {
            enabled,
            nodes: nodes
                .into_iter()
                .map(|sk| (sk.public(), is_local))
                .collect(),
            ip_stack: None,
        };
        analytics
            .handle_config_update_event(mesh_config_update_event)
            .await;
    }

    async fn send_heartbeat_response(
        analytics: &mut Analytics,
        peer_sk: SecretKey,
        meshnet_id: Uuid,
    ) {
        let heartbeat_response = HeartbeatMessage::response(
            meshnet_id.into_bytes().to_vec(),
            "fingerprint".to_owned(),
            &[HeartbeatStatus::new()],
            HeartbeatNatType::Unknown,
        );
        analytics
            .message_handler((peer_sk.public(), heartbeat_response))
            .await;
    }

    async fn receive_heartbeat(analytics_channel: &mut Receiver<AnalyticsMessage>) -> Uuid {
        let heartbeat = match analytics_channel.recv().await {
            Some(AnalyticsMessage::Heartbeat { heartbeat_info }) => heartbeat_info,
            None => unreachable!(),
        };
        heartbeat.meshnet_id.parse().unwrap()
    }

    #[tokio::test]
    async fn test_analytics_reports_locally_generated_meshnet_id_if_no_other_nodes_are_present() {
        let State {
            meshnet_id,
            mut analytics_channel,
            mut analytics,
            ..
        } = setup(None);

        analytics.handle_aggregation().await;

        assert_eq!(meshnet_id, receive_heartbeat(&mut analytics_channel).await);
    }

    #[tokio::test]
    async fn test_analytics_reports_locally_generated_meshnet_id_if_majority_of_peers_also_have_it()
    {
        let State {
            mut analytics_channel,
            mut analytics,
            meshnet_id,
            ..
        } = setup(None);

        let peer_sk_1 = SecretKey::gen();
        let peer_sk_2 = SecretKey::gen();

        setup_local_nodes(&mut analytics, true, [peer_sk_1, peer_sk_2]).await;

        analytics.handle_collection().await;
        assert_eq!(RuntimeState::Collecting, analytics.state);

        let other_meshnet_id = Uuid::new_v4();
        send_heartbeat_response(&mut analytics, peer_sk_1, other_meshnet_id).await;
        send_heartbeat_response(&mut analytics, peer_sk_2, meshnet_id).await;

        analytics.handle_aggregation().await;

        assert_eq!(meshnet_id, receive_heartbeat(&mut analytics_channel).await);
    }

    #[tokio::test]
    async fn test_analytics_overrides_local_meshnet_id_when_other_peers_report_different_in_greater_number(
    ) {
        let State {
            mut analytics_channel,
            mut analytics,
            ..
        } = setup(None);
        let peer_sk_1 = SecretKey::gen();
        let peer_sk_2 = SecretKey::gen();

        setup_local_nodes(&mut analytics, true, [peer_sk_1, peer_sk_2]).await;

        analytics.handle_collection().await;
        assert_eq!(RuntimeState::Collecting, analytics.state);

        let other_meshnet_id = Uuid::new_v4();
        send_heartbeat_response(&mut analytics, peer_sk_1, other_meshnet_id).await;
        send_heartbeat_response(&mut analytics, peer_sk_2, other_meshnet_id).await;

        analytics.handle_aggregation().await;

        assert_eq!(
            other_meshnet_id,
            receive_heartbeat(&mut analytics_channel).await
        );
    }

    #[tokio::test]
    async fn test_analytics_reports_meshnet_id_of_peer_with_lexicographically_smallest_public_key()
    {
        let State {
            public_key,
            mut analytics_channel,
            mut analytics,
            meshnet_id,
        } = setup(None);

        let peer_sk = SecretKey::gen();

        setup_local_nodes(&mut analytics, true, [peer_sk]).await;

        analytics.handle_collection().await;
        assert_eq!(RuntimeState::Collecting, analytics.state);

        let other_meshnet_id = Uuid::new_v4();
        send_heartbeat_response(&mut analytics, peer_sk, other_meshnet_id).await;

        analytics.handle_aggregation().await;

        let meshnet_id_of_smaller_pk = if public_key < peer_sk.public() {
            meshnet_id
        } else {
            other_meshnet_id
        };

        assert_eq!(
            meshnet_id_of_smaller_pk,
            receive_heartbeat(&mut analytics_channel).await
        );
    }

    #[tokio::test]
    async fn test_analytics_reports_vpn_information_then_meshnet_is_disabled() {
        let State {
            mut analytics_channel,
            mut analytics,
            ..
        } = setup(None);

        let vpn_pk = SecretKey::gen().public();

        setup_local_nodes(&mut analytics, false, []).await;

        analytics
            .handle_wg_event(Event::Node {
                body: Some(Node {
                    public_key: vpn_pk,
                    is_vpn: true,
                    state: NodeState::Connected,
                    endpoint: Some(([1, 2, 3, 4], 5678).into()),
                    ..Default::default()
                }),
            })
            .await;

        analytics.handle_collection().await;
        assert_eq!(RuntimeState::Collecting, analytics.state);

        analytics.handle_aggregation().await;

        let AnalyticsMessage::Heartbeat {
            heartbeat_info:
                HeartbeatInfo {
                    meshnet_enabled,
                    external_links,
                    ..
                },
        } = analytics_channel.recv().await.expect("message");

        assert_eq!(false, meshnet_enabled);
        assert_eq!("vpn:7600617f9f9db5691a8c2768bd9d8110:2", external_links);
    }

    #[tokio::test]
    async fn test_analytics_reports_vpn_information_then_meshnet_is_enabled() {
        let State {
            mut analytics_channel,
            mut analytics,
            ..
        } = setup(None);

        let vpn_pk = SecretKey::gen().public();

        setup_local_nodes(&mut analytics, true, []).await;

        analytics
            .handle_wg_event(Event::Node {
                body: Some(Node {
                    public_key: vpn_pk,
                    is_vpn: true,
                    state: NodeState::Connected,
                    endpoint: Some(([1, 2, 3, 4], 5678).into()),
                    ..Default::default()
                }),
            })
            .await;

        analytics.handle_collection().await;
        assert_eq!(RuntimeState::Collecting, analytics.state);

        analytics.handle_aggregation().await;

        let AnalyticsMessage::Heartbeat {
            heartbeat_info:
                HeartbeatInfo {
                    meshnet_enabled,
                    external_links,
                    ..
                },
        } = analytics_channel.recv().await.expect("message");

        assert_eq!(true, meshnet_enabled);
        assert_eq!("vpn:7600617f9f9db5691a8c2768bd9d8110:2", external_links);
    }

    #[tokio::test]
    // After a pause libtelio should send only one analytic even
    // if it missed more than one analytic interval.
    async fn test_send_analytics_report_once_on_skipped_ticks() {
        let State {
            mut analytics_channel,
            mut analytics,
            ..
        } = setup(Some(Duration::from_secs(5)));

        // Reset analytic timer 25s in the past
        analytics
            .task_interval
            .reset_at(Instant::now() - Duration::from_secs(25));

        // Set analytic collect interval 200 ms
        analytics.config.collect_answer_timeout = Duration::from_millis(200);

        let rt = Task::start(analytics);

        // Should succeed to get one analytic meesage
        assert_eq!(
            true,
            timeout(Duration::from_secs(1), analytics_channel.recv())
                .await
                .is_ok()
        );

        // Should timeout trying to get second analytic message
        assert_eq!(
            false,
            timeout(Duration::from_secs(1), analytics_channel.recv())
                .await
                .is_ok()
        );

        rt.stop().await;
    }
}
