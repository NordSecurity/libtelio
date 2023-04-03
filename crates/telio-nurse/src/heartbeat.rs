use async_trait::async_trait;
use bitflags::bitflags;
use std::fmt::Write;
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    hash::Hash,
    pin::Pin,
};
use telio_crypto::{PublicKey, SecretKey};
use telio_model::{event::Event, mesh::NodeState};
use telio_proto::{HeartbeatMessage, HeartbeatStatus, HeartbeatType};
use telio_relay::{RelayState, Server};
use telio_task::{
    io::{chan, mc_chan, Chan},
    Runtime, RuntimeExt, WaitResponse,
};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};
use tokio::time::{interval_at, sleep, Duration, Instant, Interval, Sleep};
use uuid::Uuid;

use crate::config::HeartbeatConfig;
use crate::data::{AnalyticsMessage, HeartbeatInfo, MeshConfigUpdateEvent};

/// Approximately 30 years worth of time, used to pause timers and periods
const FAR_FUTURE: Duration = Duration::from_secs(86400 * 365 * 30);

const DEFAULT_NODE_FINGERPRINT: &str = "null";

#[derive(PartialEq, Eq)]
enum RuntimeState {
    Monitoring,
    Collecting,
    Aggregating,
}

bitflags! {
    struct MeshConnectionState: u32 {
        const NONE = 0b00000000;
        const DERP = 0b00000001;
        const WG = 0b00000010;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MeshLink {
    pub connection_state: MeshConnectionState,
}

impl Default for MeshLink {
    fn default() -> Self {
        MeshLink {
            connection_state: MeshConnectionState::NONE,
        }
    }
}

/// Input/output channel for Heartbeat
pub struct Io {
    /// Channel sending and receiving heartbeat data
    pub chan: Chan<(PublicKey, HeartbeatMessage)>,
    /// Event channel to gather derp events
    pub derp_event_channel: mc_chan::Rx<Box<Server>>,
    /// Event channel to gather wg events
    pub wg_event_channel: mc_chan::Rx<Box<Event>>,
    /// Event channel to gather local nodes from mesh config updates
    pub config_update_channel: mc_chan::Rx<Box<MeshConfigUpdateEvent>>,
    /// Channel for sending and receiving analytics data
    pub analytics_channel: chan::Tx<AnalyticsMessage>,
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

impl NodeInfo {
    fn mesh_link(&self) -> MeshLink {
        match self {
            NodeInfo::Vpn { mesh_link, .. } | NodeInfo::Node { mesh_link, .. } => mesh_link.clone(),
        }
    }
}

impl Default for NodeInfo {
    fn default() -> Self {
        NodeInfo::Node {
            mesh_link: MeshLink::default(),
            meshnet_id: None,
        }
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
    io: Io,

    meshnet_id: Uuid,
    state: RuntimeState,

    pub cached_config: Option<(HashSet<PublicKey>, HashSet<PublicKey>)>,
    pub cached_private_key: Option<SecretKey>,

    public_key: PublicKey,
    external_links: HashMap<(PublicKey, PublicKey), MeshLink>,
    collected_meshnet_ids: HashMap<PublicKey, Uuid>,
    node_fingerprints: HashMap<PublicKey, String>,

    // All the nodes we have a connection with according to wireguard
    local_nodes: HashMap<PublicKey, NodeInfo>,

    // All the local nodes according to config updates
    config_local_nodes: HashSet<PublicKey>,

    derp_connection: bool,
}

#[async_trait]
impl Runtime for Analytics {
    const NAME: &'static str = "Nurse Heartbeat Analytics";

    type Err = ();

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        tokio::select! {
            // wg event, only in the `Monitoring` state
            Ok(event) = self.io.wg_event_channel.recv(), if self.state == RuntimeState::Monitoring =>
                Self::guard(async move { self.handle_wg_event(*event).await; telio_log_trace!("tokio::select! self.io.wg_event_channel.recv() branch");Ok(()) }),

            // Derp event, only in the `Monitoring` state
            Ok(event) = self.io.derp_event_channel.recv(), if self.state == RuntimeState::Monitoring =>
                Self::guard(async move { self.handle_derp_event(*event).await; telio_log_trace!("tokio::select! self.io.derp_event_channel.recv() branch");Ok(()) }),

            // MeshConfigUpdate event, only in the `Monitoring` state
            Ok(event) = self.io.config_update_channel.recv(), if self.state == RuntimeState::Monitoring =>
                Self::guard(async move { self.handle_config_update_event(*event).await; telio_log_trace!("tokio::select! self.io.config_update_channel.recv() branch");Ok(()) }),

            // Time to send a data request to other nodes, only update in the `Monitoring` state
            _ = self.task_interval.tick(), if self.state == RuntimeState::Monitoring =>
                Self::guard(async move { self.handle_collection().await; telio_log_trace!("tokio::select! self.task_interval.tick() branch");Ok(()) }),

            // Received data from node, Should always listen for incoming data
            Some((pk, msg)) = self.io.chan.rx.recv() =>
                Self::guard(async move { self.handle_receive((pk, msg)).await; telio_log_trace!("tokio::select! self.io.chan.rx.recv() branch");Ok(()) }),

            // Time to aggregate collected data, only update when in the `Collecting` state
            _ = &mut self.collect_period, if self.state == RuntimeState::Collecting =>
                Self::guard(async move { self.handle_aggregation().await; telio_log_trace!("tokio::select! self.collect_period branch");Ok(()) }),

            else => Self::next(),
        }
    }
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
        let start_time = if let Some(initial_timeout) = config.initial_collect_interval {
            Instant::now() + initial_timeout
        } else {
            Instant::now() + config.collect_interval
        };

        let mut config_local_nodes = HashSet::new();
        // Add self in config_local_nodes hashset
        config_local_nodes.insert(public_key);

        Self {
            task_interval: interval_at(start_time, config.collect_interval),
            collect_period: Box::pin(sleep(FAR_FUTURE)),
            config,
            io,
            meshnet_id,
            state: RuntimeState::Monitoring,
            cached_config: None,
            cached_private_key: None,
            public_key,
            external_links: HashMap::new(),
            collected_meshnet_ids: HashMap::new(),
            node_fingerprints: HashMap::new(),
            local_nodes: HashMap::new(),
            config_local_nodes,
            derp_connection: false,
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

                self.config_local_nodes.remove(&old_public_key);
                self.config_local_nodes.insert(self.public_key);

                // Since the private key and therefore the public key changes, we need to update the
                // external links, since they will be pointing to a public key that no longer exists

                // It's a slightly more involved process with the external links, as we only need to update the entries
                // that reference this node directly
                self.external_links = self
                    .external_links
                    .iter()
                    .map(|e| {
                        // If the connection references this node, we need to update it,
                        // otherwise we leave it untouched
                        if e.0 .1 == old_public_key {
                            ((e.0 .0, self.public_key), e.1.clone())
                        } else {
                            (*e.0, e.1.clone())
                        }
                    })
                    .collect();
            }
        }
    }

    /// Update the nodes with added and removed nodes from `cached_config`.
    ///
    /// Will only do something if the node is in a monitoring state.
    pub async fn update_nodes(&mut self) {
        // We should only update the state of the links if we're in the monitoring state
        if self.state == RuntimeState::Monitoring {
            if let Some((new_nodes, removed_nodes)) = &self.cached_config.take() {
                // First clear the nodes that were removed from the meshnet from all of the containers
                for node in removed_nodes {
                    self.external_links
                        .retain(|&k, _| (*node != k.0 && *node != k.1));

                    // Also remove the node from the fingerprint map, we don't need to worry about `meshnet_id`'s, since they get cleared on each collection cycle
                    self.node_fingerprints.remove_entry(node);

                    // Remove local node
                    self.local_nodes.remove(node);
                }

                // Then insert all of the new nodes in the local links
                for node in new_nodes {
                    self.local_nodes.entry(*node).or_default();
                }
            }
        }
    }

    async fn handle_wg_event(&mut self, event: Event) {
        if let Event::Node { body: Some(node) } = event {
            if let Some(state) = node.state {
                let mut mesh_link = MeshLink::default();
                mesh_link
                    .connection_state
                    .set(MeshConnectionState::WG, state == NodeState::Connected);

                let node_info = if node.is_vpn {
                    NodeInfo::Vpn {
                        mesh_link,
                        hostname: node.hostname,
                    }
                } else {
                    NodeInfo::Node {
                        mesh_link,
                        meshnet_id: None,
                    }
                };

                self.local_nodes.entry(node.public_key).or_insert(node_info);
            }
        }
    }

    async fn handle_derp_event(&mut self, event: Server) {
        self.derp_connection = event.conn_state == RelayState::Connected;
    }

    async fn handle_config_update_event(&mut self, event: MeshConfigUpdateEvent) {
        for node in &event.local_nodes {
            if !self.config_local_nodes.contains(node) {
                self.config_local_nodes.insert(*node);
            }
        }
    }

    async fn handle_collection(&mut self) {
        // Clear all of the external links before sending, to get rid of the stale links in case we don't get any data back from a node that previously was online
        self.external_links.clear();

        // Also clear the previous cycles collected meshnet ID's and push own current key in to simplify the resolution
        self.collected_meshnet_ids.clear();
        self.collected_meshnet_ids
            .insert(self.public_key, self.meshnet_id);

        for pk in self.local_nodes.keys() {
            // Insert an empty fingerprint entry, if it doesn't exist yet,
            // we'll set the the actual fingerprints when and if we receive a message from the node
            self.node_fingerprints
                .entry(*pk)
                .or_insert_with(|| DEFAULT_NODE_FINGERPRINT.to_string());

            let heartbeat = HeartbeatMessage::request();

            #[allow(mpsc_blocking_send)]
            if self.io.chan.tx.send((*pk, heartbeat)).await.is_err() {
                telio_log_warn!(
                    "Failed to send Nurse mesh Heartbeat request to node :{:?}",
                    pk
                );
            };
        }

        // Start collection timer before starting to aggregate the data
        self.collect_period
            .as_mut()
            .reset(Instant::now() + self.config.collect_answer_timeout);

        // Transition to the collection state
        self.state = RuntimeState::Collecting;
    }

    async fn handle_receive(&mut self, data: (PublicKey, HeartbeatMessage)) {
        let pk = data.0;

        // Since we already got a message from the other node, we can assume that the derp connection is functioning from them to us
        self.external_links
            .entry((pk, self.public_key))
            .or_default()
            .connection_state
            .set(MeshConnectionState::DERP, true);

        // By the same token, if we got a message from the node, we can also assume that the connection is working as it should
        match self.local_nodes.entry(pk).or_default() {
            NodeInfo::Vpn { mesh_link, .. } | NodeInfo::Node { mesh_link, .. } => mesh_link
                .connection_state
                .set(MeshConnectionState::DERP, true),
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
        );

        #[allow(mpsc_blocking_send)]
        if self.io.chan.tx.send((pk, heartbeat)).await.is_err() {
            telio_log_warn!(
                "Failed to send Nurse mesh heartbeat message to node :{:?}",
                pk
            );
        };
    }

    async fn handle_response_message(&mut self, pk: PublicKey, message: &HeartbeatMessage) {
        if let Ok(received_meshnet_id) = Uuid::from_slice(message.get_meshnet_id()) {
            // Add the received key to the list of keys
            self.collected_meshnet_ids
                .entry(pk)
                .or_insert(received_meshnet_id);

            // Update node's meshnet_id
            match self.local_nodes.entry(pk).or_default() {
                NodeInfo::Node { meshnet_id, .. } => *meshnet_id = Some(received_meshnet_id),
                _ => telio_log_warn!("Received meshnet_id from a vpn node"),
            }
        } else {
            telio_log_warn!("Failed to parse meshnet ID from Heartbeat message");
        }

        // Once we get a repose message from the node, update the fingerprint under the given public key
        *self
            .node_fingerprints
            .entry(pk)
            .or_insert_with(|| "".to_string()) = message.get_node_fingerprint().to_string();

        let connections: Vec<(PublicKey, PublicKey, MeshLink)> = message
            .get_statuses()
            .iter()
            .filter_map(|status| {
                let connection_state;
                if let Some(state) = MeshConnectionState::from_bits(status.connection_state) {
                    connection_state = state;
                } else {
                    telio_log_warn!(
                        "Failed to parse Nurse mesh heartbeat connection state, invalid data"
                    );
                    return None;
                }

                let other_key;
                if let Ok(key) = status.node.clone().try_into() {
                    other_key = key;
                } else {
                    telio_log_debug!(
                        "Could not parse link public key ({:?}) from a node response message",
                        status.node
                    );
                    return None;
                }

                let link = MeshLink { connection_state };

                Some((pk, other_key, link))
            })
            .collect();

        for connection in connections {
            let entry = self
                .external_links
                .entry((connection.0, connection.1))
                .or_default();
            *entry = connection.2;
        }
    }

    async fn handle_aggregation(&mut self) {
        // Transition to the aggregation state
        self.state = RuntimeState::Aggregating;

        // Figure out what meshnet id we should use, based on all of the collected data
        // Start off by generating a heatmap of the received ID's
        let mut id_heatmap: HashMap<Uuid, u32> = HashMap::new();
        for (pk, mesh_id) in &self.collected_meshnet_ids {
            // Consider only local nodes according to mesh config and self
            // self.config_local_nodes will always contain at least current node's public key
            if self.config_local_nodes.contains(pk) {
                *id_heatmap.entry(*mesh_id).or_default() += 1;
            }
        }

        self.meshnet_id = {
            // Then find the value with the biggest amount of repetitions
            // This cannot fail as we are guaranteed to have at least one element in the map at the time of checking
            let id_with_max_value = match id_heatmap.iter().max_by(|o, t| o.1.cmp(t.1)) {
                Some((o, _)) => o,
                None => {
                    telio_log_warn!("id_heatmap empty");
                    return;
                }
            };

            // Since we can have more than one meshnet ID having the most amount of repetitions, we need to resolve this in a
            // predictable way, so we filter out the entries that share this maximum value and then sort them again by
            // the public key, from which the ID initially came from
            match self
                .collected_meshnet_ids
                .iter()
                .filter(|(_k, v)| id_with_max_value == *v)
                .max_by(|o, t| o.0.cmp(t.0))
            {
                Some((_, t)) => *t,
                None => {
                    telio_log_warn!("collected_meshnet_ids is missing {}", id_with_max_value);
                    return;
                }
            }
        };

        let mut heartbeat_info = HeartbeatInfo {
            meshnet_id: self.meshnet_id.to_string(),
            heartbeat_interval: i32::try_from(self.config.collect_interval.as_secs()).unwrap_or(0),
            ..Default::default()
        };

        // Update the local link DERP connection state with current derp connection state, in case something changed from the last time we recieved a node message
        // or in case we didn't get a message from another node, even though our DERP connection is active
        let state_of_derp_connection = self.derp_connection;
        self.local_nodes
            .iter_mut()
            .for_each(|(_key, node)| match node {
                NodeInfo::Vpn { mesh_link, .. } | NodeInfo::Node { mesh_link, .. } => mesh_link
                    .connection_state
                    .set(MeshConnectionState::DERP, state_of_derp_connection),
            });

        // Include own fingerprint in the fingerprint map, in case it wasn't there before
        let fingerprint = self.config.fingerprint.clone();
        self.node_fingerprints
            .entry(self.public_key)
            .or_insert_with(|| fingerprint);

        let internal_sorted_public_keys = self
            .node_fingerprints
            .iter()
            .map(|x| *x.0)
            .collect::<Vec<_>>();

        let external_sorted_public_keys = internal_sorted_public_keys.clone();

        let mut internal_sorted_public_keys = internal_sorted_public_keys
            .iter()
            .filter(|&&key| match self.local_nodes.entry(key).or_default() {
                NodeInfo::Node { meshnet_id, .. } => meshnet_id
                    .map(|meshnet_id| meshnet_id == self.meshnet_id)
                    .unwrap_or(false),
                _ => false,
            })
            .collect::<Vec<_>>();

        let mut external_sorted_public_keys = external_sorted_public_keys
            .iter()
            .filter(|&&key| match self.local_nodes.entry(key).or_default() {
                NodeInfo::Node { meshnet_id, .. } => meshnet_id
                    .map(|meshnet_id| meshnet_id != self.meshnet_id)
                    .unwrap_or(true),
                _ => true,
            })
            .collect::<Vec<_>>();

        // Sort out the public keys, according to Rust docs "Strings are ordered lexicographically by their byte values."
        // we sort public keys, instead of sorting by fingerprints, since fingerprints can be empty or null, resulting in
        // multiple same values, which make having a consistent layout for each node awkward to implement
        internal_sorted_public_keys.sort();
        external_sorted_public_keys.sort();

        // TODO: Make it better
        external_sorted_public_keys.iter().for_each(|&&key| {
            heartbeat_info.external_sorted_public_keys.push(key);
        });

        // Map node public keys to indices for the connectivity matrix alonside creating a sorted fingerprint list
        let mut index_map: HashMap<PublicKey, u8> = HashMap::new();
        let mut internal_sorted_fingerprints: Vec<String> = Vec::new();
        for (i, pk) in internal_sorted_public_keys.iter().enumerate() {
            // Since the public key array is already sorted, we can just insert the index from the `enumerate` iterator here
            index_map.entry(**pk).or_insert(i as u8);

            // By the same token, we can just insert the respective fingerprint into the list of sorted fingerprints
            internal_sorted_fingerprints.push(self.node_fingerprints[pk].clone());
            heartbeat_info.internal_sorted_public_keys.push(**pk);
        }

        // Construct a string containing all of the sorted fingerprints to send to moose
        let mut fingerprints_string = internal_sorted_fingerprints
            .iter()
            .fold(String::new(), |o, t| o + t.as_str() + ",");
        fingerprints_string.pop();

        heartbeat_info.fingerprints = fingerprints_string;

        // Fill in the missing external links, in case we haven't gotten a response from some nodes
        for i in index_map.keys() {
            for j in index_map.keys() {
                if i != &self.public_key && i != j {
                    self.external_links.entry((*i, *j)).or_default();
                }
            }
        }

        let local_links = internal_sorted_public_keys
            .iter()
            .map(|&&key| {
                let node = self.local_nodes.entry(key).or_default();

                ((self.public_key, key), node.mesh_link())
            })
            .collect::<HashMap<_, _>>();

        let combined_map: HashMap<&(PublicKey, PublicKey), &MeshLink> = local_links
            .iter()
            .chain(self.external_links.iter())
            .collect();

        telio_log_trace!(
            "ID heatmap: {:?}\nnominated ID: {:?}",
            id_heatmap,
            self.meshnet_id
        );

        let mut connectivity_matrix = String::new();
        let default_state = MeshConnectionState::WG | MeshConnectionState::DERP;
        // Loop over all of the possible combinations of links, assuming that the directionality of the connection does not matter
        for i in index_map.iter() {
            for j in index_map.iter() {
                if i.1 > j.1 {
                    break;
                }

                if i.1 != j.1 {
                    // We take both directions of the link at the same time
                    let link1 = combined_map[&(*i.0, *j.0)];
                    let link2 = combined_map[&(*j.0, *i.0)];

                    // And only output the minimum, or the worst reported connection from the pair as the representing connection
                    let min = link1.min(link2);

                    // And if this state differs from the default state of the matrix, we add this to the final output
                    if min.connection_state != default_state {
                        write!(
                            connectivity_matrix,
                            "{}:{}:{},",
                            i.1, j.1, min.connection_state.bits
                        )
                        .expect("no");
                    }
                }
            }
        }

        // Shave off the uneeded comma, if we have anything in the matrix to begin with
        if !connectivity_matrix.is_empty() {
            connectivity_matrix.pop();
        }

        heartbeat_info.connectivity_matrix = connectivity_matrix;

        // External links
        let mut external_links = String::new();
        for key in external_sorted_public_keys {
            let node = self.local_nodes.entry(*key).or_default();

            let (meshnet_id, fingerprint, connection_state) = match node {
                NodeInfo::Vpn {
                    mesh_link,
                    hostname,
                } => (
                    String::from("vpn"),
                    hostname.clone().unwrap_or_else(|| {
                        telio_log_warn!("Node with pk: {:?} has no fingerprint", key);
                        String::from("no-fingerprint")
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
                    self.node_fingerprints.get(key).cloned().unwrap_or_else(|| {
                        telio_log_warn!("Node with pk: {:?} has no fingerprint", key);
                        String::from("no-fingerprint")
                    }),
                    mesh_link.connection_state.bits,
                ),
            };

            if write!(
                external_links,
                "{}:{}:{},",
                meshnet_id, fingerprint, connection_state
            )
            .is_err()
            {
                telio_log_error!("Failed to write in external_links string");
            }
        }
        external_links.pop();
        heartbeat_info.external_links = external_links;

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
        self.update_nodes().await;
    }
}
