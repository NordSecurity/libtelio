use telio_crypto::{PublicKey, SecretKey};
use telio_task::io::chan;
use telio_wg::DynamicWg;
use telio_wg::{self as wg, uapi::Event as PeerEvent, WireGuard};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    task::JoinHandle,
    time::{sleep, Duration},
};

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

//debug tools
use telio_utils::{telio_err_with_log, telio_log_debug, telio_log_trace, telio_log_warn};

use super::{Error, Result};
use telio_model::{
    api_config::PathType,
    mesh::{Node, NodeState},
};

/// Mapping from meshnet domain into WG domain
pub(super) struct Meshnet {
    pub driver: Arc<wg::DynamicWg>,
    node_events: JoinHandle<()>,
    state: Arc<Mutex<State>>,
}

struct State {
    private_key: Option<SecretKey>,
    nodes: HashMap<PublicKey, Node>,
    event_ignore_list: HashSet<PublicKey>,
    #[cfg(target_os = "linux")]
    fwmark: u32,
    events_sender: broadcast::Sender<Box<Node>>,
}

impl Meshnet {
    pub(super) fn new(
        mut path_changes: mpsc::Receiver<(PublicKey, PathType)>,
        driver: Arc<DynamicWg>,
        chan_rx: chan::Rx<Box<PeerEvent>>,
    ) -> Result<(Self, broadcast::Receiver<Box<Node>>)> {
        let (tx, rx) = broadcast::channel(256);
        let state = Arc::new(Mutex::new(State {
            private_key: None,
            nodes: HashMap::new(),
            event_ignore_list: HashSet::new(),
            #[cfg(target_os = "linux")]
            fwmark: 0,
            events_sender: tx,
        }));

        let s = state.clone();
        let mut event_rx = chan_rx;
        let node_events = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(event) = event_rx.recv() => {
                        s.lock().await.upsert_peer_event(*event).await;
                    },
                    Some(event) = path_changes.recv()  =>{
                        s.lock().await.peer_pathchange_event(event).await;
                    },
                }
            }
        });

        Ok((
            Self {
                driver,
                node_events,
                state,
            },
            rx,
        ))
    }

    pub(super) async fn stop(self) {
        self.node_events.abort();
        // The driver will be stopped by device::Runtime::stop
    }

    pub(super) async fn port(&self) -> Result<u16> {
        // Attempt few times to resolve if adapter takes some extra time to setup.
        let mut range = 1..8;
        loop {
            if let Some(port) = self
                .driver
                .get_interface()
                .await
                .and_then(|i| i.listen_port)
            {
                if port > 0 {
                    telio_log_trace!("Wireguard using port:{:?}", &port.to_string());
                    break Ok(port);
                }
            }

            if let Some(pow) = range.next() {
                sleep(Duration::from_millis(2u64.pow(pow))).await;
            } else {
                break telio_err_with_log!(Error::AdapterConfig(
                    "Adapter does not have port".to_owned()
                ));
            }
        }
    }

    pub(super) async fn nodes(&self) -> Vec<Node> {
        self.state.lock().await.nodes.values().cloned().collect()
    }

    /// this retrieves all nodes which are not in ignore list
    pub(super) async fn external_nodes(&self) -> Vec<Node> {
        let nodes = self.nodes().await;
        let state = self.state.lock().await;
        nodes
            .into_iter()
            .filter(|node| !state.event_ignore_list.contains(&node.public_key))
            .collect()
    }

    pub(super) async fn set_private_key(&self, key: &SecretKey) {
        let mut state = self.state.lock().await;

        if state.private_key.as_ref() != Some(key) {
            self.driver.set_secret_key(*key).await;
            state.private_key = Some(*key);
        }
    }

    pub(super) async fn get_adapter_luid(&self) -> u64 {
        self.driver.get_adapter_luid().await
    }

    pub(super) async fn drop_connected_sockets(&self) {
        self.driver.drop_connected_sockets().await
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn set_fwmark(&self, fwmark: u32) -> bool {
        if !self.driver.set_fwmark(fwmark).await {
            return false;
        }
        self.state.lock().await.fwmark = fwmark;
        telio_log_trace!("set_fwmark sucessfull : {:?}", fwmark);
        true
    }

    pub(super) async fn get_node(&self, key: &PublicKey) -> Option<Node> {
        let state = self.state.lock().await.nodes.get(key).cloned();
        telio_log_debug!("state: {:?}", state);
        state
    }

    pub(super) async fn upsert_node(&self, node: &Node) -> Result {
        let mut state = self.state.lock().await;

        let update = state.nodes.contains_key(&node.public_key);

        if !node.is_exit && node.is_vpn {
            return telio_err_with_log!(Error::InvalidNode);
        }

        if self.allowed_ips_duplicate(node).await {
            telio_log_debug!("node : {:?}", node);
            return telio_err_with_log!(Error::BadAllowedIps);
        }

        // Forbid multiple exit nodes
        if !update && node.is_exit && state.nodes.values().any(|n| n.is_exit) {
            telio_log_debug!("node: {:?}", node);
            return telio_err_with_log!(Error::DuplicateExitNode);
        }

        if let Some(node) = state.upsert_node(node.clone()).await {
            telio_log_debug!("upsert_node : {:?}", node);
            self.driver.add_peer({ &node }.into()).await;
        }

        telio_log_debug!("Upsert_node_ignored succesfull: {:?}", node);
        Ok(())
    }

    pub(super) async fn upsert_node_ignored(&self, node: &Node) -> Result {
        {
            let mut state = self.state.lock().await;
            state.event_ignore_list.insert(node.public_key);
        }

        if let Err(error) = self.upsert_node(node).await {
            let mut state = self.state.lock().await;
            state.event_ignore_list.remove(&node.public_key);
            return telio_err_with_log!(error);
        }

        telio_log_trace!("Upsert_node_ignored succesfull: {:?}", node);
        Ok(())
    }

    pub(super) async fn del_node(&self, key: &PublicKey) -> Result {
        let mut state = self.state.lock().await;
        if let Some(mut node) = state.nodes.remove(key) {
            node.state = Some(NodeState::Disconnected);
            state.report(node).await;
            state.event_ignore_list.remove(key);
            self.driver.del_peer(*key).await;
            telio_log_trace!("Node removed sucessfully: {:?}", key);
            return Ok(());
        }

        telio_err_with_log!(Error::InvalidDelete)
    }

    async fn allowed_ips_duplicate(&self, node: &Node) -> bool {
        if let Some(interface) = self.driver.get_interface().await {
            telio_log_trace!("There is a interface (allowed_ips_duplicate)");
            interface
                .peers
                .values()
                .filter(|peer| peer.public_key != node.public_key)
                .any(|peer| {
                    node.allowed_ips
                        .iter()
                        .any(|candidate_allowed_ip| peer.allowed_ips.contains(candidate_allowed_ip))
                })
        } else {
            telio_log_debug!("allowed_ips_duplicate: {:?}", node);
            false
        }
    }
}

impl State {
    async fn peer_pathchange_event(&mut self, event: (PublicKey, PathType)) {
        let (pk, pt) = event;
        if let Some(mut node) = self.nodes.get(&pk).cloned() {
            node.path = pt;
            telio_log_debug!("node at peer_pathchange_event:{:?}", node);
            self.upsert_node(node).await;
        }
    }

    /// Sync WG -> telio
    async fn upsert_peer_event(&mut self, peer_event: PeerEvent) -> Option<Node> {
        if let Some(mut node) = self.nodes.get(&peer_event.peer.public_key).cloned() {
            // Just keep important info from WG
            node.state = Some(peer_event.state);
            node.endpoints = peer_event
                .peer
                .endpoint
                .map(|e| vec![(e, true).into()])
                .unwrap_or_default();

            telio_log_debug!("node at upsert_peer_event:{:?}", node);
            self.upsert_node(node).await
        } else {
            telio_log_warn!("upsert_peer_even with null node");
            None
        }
    }

    /// Sync telio -> WG
    async fn upsert_node(&mut self, mut node: Node) -> Option<Node> {
        match self.nodes.get_mut(&node.public_key) {
            Some(old_node) => {
                // Merge optional values
                if node.state.is_none() {
                    node.state = old_node.state;
                }
                if node.hostname.is_none() {
                    node.hostname = old_node.hostname.clone();
                }

                // Check for changes
                if old_node != &node {
                    *old_node = node.clone();
                    self.report(node.clone()).await;
                    Some(node)
                } else {
                    telio_log_debug!("new_node and old_node are the same");
                    None
                }
            }
            None if node.state != Some(NodeState::Disconnected) => {
                node.state = Some(NodeState::Connecting);
                self.nodes.insert(node.public_key, node.clone());
                self.report(node.clone()).await;
                Some(node)
            }
            _ => {
                telio_log_debug!("Node state not disconnected");
                None
            }
        }
    }

    async fn report(&self, node: Node) {
        if !self.event_ignore_list.contains(&node.public_key) {
            let _ = self.events_sender.send(Box::new(node));
        } else {
            telio_log_debug!("self.report: {:?}", node);
        }
    }
}
