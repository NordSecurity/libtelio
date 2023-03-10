pub mod relay;
mod set;
mod set_builder;
mod udp_hole_punch;

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures::{
    future::{pending, select_all},
    Future, FutureExt,
};
use strum::EnumCount;
use telio_crypto::PublicKey;
use telio_model::api_config::{FeaturePaths, PathType};
use telio_proto::{DataMsg, Generation};
use telio_task::{
    io::{
        chan::{Rx, Tx},
        wait_for_tx, Chan,
    },
    task_exec, BoxAction, Runtime, Task,
};
use telio_utils::{
    map::MapExt, sleep::PinnedSleep, telio_log_debug, telio_log_info, telio_log_trace,
};
use tokio::time::Duration;

use super::route_type::RouteType;
use crate::route::{Configure, Route};
use crate::{Config, Error};

pub use self::{
    set::PathSet,
    set_builder::{PathSetBuilder, PathSetBuilderDefault, PathSetIo},
};

pub const CONN_UPGRADE_TIMEOUT: Duration = Duration::from_secs(30);

pub type ConnectionTimer = Option<PinnedSleep<PublicKey>>;

pub struct Paths {
    task: Task<State>,
}

pub struct State {
    events: Tx<(PublicKey, PathType)>,
    data: Chan<(PublicKey, DataMsg)>,

    pathset: PathSet,

    connections: HashMap<PublicKey, Connection>,
    // When transition from Data to GenData happens, this timer ensure,
    // that we drop any following Data packets and process only GenData.
    // After timer expires, The received Data packet indicaates a connection reset
    conns_upg_wait: HashMap<PublicKey, ConnectionTimer>,
}

pub struct Path {
    pub route: RouteType,
    pub channel: Chan<(PublicKey, DataMsg)>,
    pub changes: Option<Rx<(PublicKey, bool)>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionState {
    // Connection is in start stage, Data packets are sent
    Init,
    // Connection received GenData packets, starts to drop Data packets
    Transition,
    // Connection receives GenData packets, if Data packet is receieved - connection is reset
    Upgraded,
    // Connection needs to be reset to Init
    Broken,
}

#[derive(Debug)]
pub struct Connection {
    path: Option<PathType>,
    generation: Option<Generation>,
    active: HashSet<PathType>,
    state: ConnectionState,
}

pub struct Io {
    pub data: Chan<(PublicKey, DataMsg)>,
    pub events: Tx<(PublicKey, PathType)>,
}

impl Paths {
    pub fn start(features: FeaturePaths, io: Io, set_io: PathSetIo) -> Result<Self, Error> {
        Self::start_with(io, PathSetBuilderDefault::new(set_io, features.paths()))
    }
}

impl Paths {
    pub fn start_with<B: PathSetBuilder>(io: Io, build_path_set: B) -> Result<Self, Error> {
        Ok(Self {
            task: Task::start(State {
                data: io.data,
                events: io.events,
                pathset: build_path_set.build()?,
                connections: HashMap::new(),
                conns_upg_wait: HashMap::new(),
            }),
        })
    }

    pub async fn configure(&self, config: Config) -> Result<(), Error> {
        task_exec!(&self.task, async move |s| Ok(s.configure(config).await)).await?
    }

    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

impl State {
    async fn configure(&mut self, config: Config) -> Result<(), Error> {
        // Update connections and timers with new peers
        self.connections
            .update(config.peers.clone(), |_| Connection::new());

        self.conns_upg_wait.update(config.peers.clone(), |_| None);

        let (conns, routes) = (&mut self.connections, routes(&self.pathset));

        conns.iter_mut().for_each(|(_, c)| {
            c.path = None;
            c.state = ConnectionState::Init;
            c.active.clear();
            c.generation = None;
        });

        for (pt, route) in routes.iter() {
            route.configure(config.derp.clone()).await;
            route.update_nodes(conns.keys().cloned().collect()).await?;
            // ACT: [ ] Use FuturesOrdered
            for (p, c) in conns.iter_mut() {
                if route.is_reachable(*p).await {
                    telio_log_trace!("({}) Reaching peer ({:?}) via {:?}", Self::NAME, &p, &pt);
                    c.active.insert(*pt);
                }
            }
        }

        conns.iter_mut().for_each(|(pk, c)| {
            c.select_best_path(routes.iter().map(|(pt, _)| *pt), pk);
        });

        Ok(())
    }

    async fn check_conns(
        conns: &mut HashMap<PublicKey, Connection>,
        conns_wait: &mut HashMap<PublicKey, ConnectionTimer>,
        pathset: &mut PathSet,
    ) {
        // Check upgraded connections and launch or remove timers
        for (pk, c) in conns.iter_mut() {
            match c.state {
                ConnectionState::Init => {
                    if let Some(ops) = conns_wait.get_mut(pk) {
                        if ops.is_some() {
                            telio_log_trace!(
                                "({}) Peer ({:?}) remove connection upgrade timer, state: {:?}",
                                Self::NAME,
                                &pk,
                                ConnectionState::Init,
                            );
                            *ops = None;
                        }
                    };
                }
                ConnectionState::Transition => {
                    if let Some(ops) = conns_wait.get_mut(pk) {
                        if ops.is_none() {
                            telio_log_trace!(
                                "({}) Peer ({:?}) set connection upgrade timer to {}s",
                                Self::NAME,
                                &pk,
                                CONN_UPGRADE_TIMEOUT.as_secs(),
                            );
                            *ops = Some(PinnedSleep::new(CONN_UPGRADE_TIMEOUT, *pk));
                        }
                    };
                }
                ConnectionState::Upgraded => {
                    if let Some(ops) = conns_wait.get_mut(pk) {
                        if ops.is_some() {
                            telio_log_trace!(
                                "({}) Peer ({:?}) remove connection upgrade timer, state: {:?}",
                                Self::NAME,
                                &pk,
                                ConnectionState::Upgraded,
                            );
                            *ops = None;
                        }
                    };
                }
                ConnectionState::Broken => {
                    let _ = c.reset(pathset, pk).await;
                }
            }
        }
    }

    async fn join_pathset_data(&mut self) -> Result<(), ()> {
        let (pathset, data_tx, data_rx, conns, conns_upg_wait, path_events) = (
            &mut self.pathset,
            &self.data.tx,
            &mut self.data.rx,
            &mut self.connections,
            &mut self.conns_upg_wait,
            &mut self.events,
        );

        Self::check_conns(conns, conns_upg_wait, pathset).await;

        // Select all conn upg timers to wait in select further
        let upg_wait = {
            let flattened = conns_upg_wait.iter_mut().flat_map(|(_, ops)| ops);

            if flattened.count() > 0 {
                select_all(
                    conns_upg_wait
                        .iter_mut()
                        .flat_map(|(_, ops)| ops)
                        .map(|ps| ps.boxed()),
                )
                .left_future()
            } else {
                pending().right_future()
            }
        };

        let paths_recv = select_all(
            pathset
                .paths
                .iter_mut()
                .map(|(pt, p)| async move { Some((*pt, p.channel.rx.recv().await?)) }.boxed()),
        );

        tokio::select! {
            // Tx side
            Some((pk, mut msg)) = pathset.permits.ready_all().then(|_| data_rx.recv()) => {
                if let Some(con) = conns.get(&pk) {
                    if let Some(path) = con.path {
                        if let Some(gen) = con.generation {
                            msg.set_generation(gen);
                        }

                        telio_log_trace!("({}) Peer ({:?}) Data ({}) --> {:?}", Self::NAME, &pk, msg, path);
                        pathset.permits.send(path, (pk, msg));
                    } else {
                        telio_log_debug!("({}) Peer ({:?}) Data ({}) --> <no path>", Self::NAME, &pk, msg);
                    }
                } else {
                    telio_log_debug!("({}) Peer Tx to {:?} - no connection", Self::NAME, &pk);
                }
                Ok(())
            }
            // Rx side
            Some((permit, (Some((path_type, (pk, msg))), ..))) = wait_for_tx(data_tx, paths_recv) => {
                if let Some(con) = conns.get_mut(&pk) {
                    if con.check_against_rx(&msg, path_type, &pk).await {
                        telio_log_trace!("({}) Peer ({:?}) Data ({}) <-- {:?}", Self::NAME, &pk, msg, path_type);
                        let _ = permit.send((pk, msg));
                    }
                } else {
                    telio_log_debug!("({}) Peer Rx from {:?} - no connection", Self::NAME, &pk);
                }
                Ok(())
            }
            // Path update
            Some((path_type, pk, connected)) = pathset.changes.recv() => {
                if let Some(con) = conns.get_mut(&pk) {
                    telio_log_debug!("({}) Peer ({:?}) path {:?} connected: {}", Self::NAME, &pk, path_type, connected);

                    if connected {
                        con.active.insert(path_type);
                    } else {
                        con.active.remove(&path_type);
                    }

                    let old_path = con.path;
                    if con.select_best_path(pathset.prio.iter().cloned(), &pk) {
                        telio_log_debug!(
                            "({}) Peer ({:?}) udpate {:?} -> {:?}",
                            Self::NAME,
                            &pk,
                            old_path,
                            con.path,
                        );
                    }
                    let _ = path_events.send((pk, con.path.unwrap_or(PathType::Relay))).await;
                }
                Ok(())
            }
            // Path upgrade timeout
            (pk, _, _) = upg_wait => {
                if let Some(con) = conns.get_mut(&pk) {
                    telio_log_debug!(
                        "({}) Peer ({:?}) update connection state {:?} -> {:?}",
                        Self::NAME,
                        &pk,
                        con.state,
                        ConnectionState::Upgraded,
                    );
                    con.state = ConnectionState::Upgraded;
                }
                Ok(())
            }
        }
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "PathSelector";

    type Err = ();

    async fn wait_with_update<F>(&mut self, updated: F) -> Result<(), Self::Err>
    where
        F: Future<Output = BoxAction<Self, Result<(), Self::Err>>> + Send,
    {
        // View tuple, avoid &mut collision
        tokio::select! {
            res = self.join_pathset_data() => res,
            update = updated => { update(self).await },
        }
    }

    async fn stop(mut self) {
        for pt in self.pathset.prio.iter() {
            if let Some(path) = self.pathset.paths.remove(pt) {
                path.route.stop().await;
            }
        }
    }
}

impl Connection {
    fn new() -> Self {
        Self {
            path: None,
            generation: None,
            active: HashSet::with_capacity(PathType::COUNT),
            state: ConnectionState::Init,
        }
    }

    async fn reset(&mut self, pathset: &PathSet, pk: &PublicKey) -> Result<(), Error> {
        telio_log_debug!("Peer ({:?}) reset connection", &pk);

        self.path = None;
        self.active.clear();
        self.state = ConnectionState::Init;
        self.generation = None;

        for (pt, route) in routes(pathset) {
            route.reset_nodes(vec![*pk]).await?;

            if route.is_reachable(*pk).await {
                telio_log_debug!("Reaching peer ({:?}) via {:?}", pk, pt);
                self.active.insert(pt);
            }
        }

        self.select_best_path(routes(pathset).iter().map(|(pt, _)| *pt), pk);

        Ok(())
    }

    async fn check_against_rx(
        &mut self,
        msg: &DataMsg,
        path_type: PathType,
        pk: &PublicKey,
    ) -> bool {
        let new_gen = msg.get_generation();

        match self.state {
            ConnectionState::Init => {
                // Start connection upgrade
                if new_gen.is_some() {
                    telio_log_debug!(
                        "Peer ({:?}) update connection state {:?} -> {:?}",
                        &pk,
                        self.state,
                        ConnectionState::Transition,
                    );
                    self.state = ConnectionState::Transition;
                }
            }
            ConnectionState::Transition => {
                // Received late packet, drop it
                if new_gen.is_none() {
                    telio_log_trace!(
                        "Peer ({:?}) got packet without Generation, during {:?} phase",
                        &pk,
                        ConnectionState::Transition,
                    );
                    return false;
                }
            }
            ConnectionState::Upgraded => {
                // The connection needs to be restarted
                if new_gen.is_none() {
                    telio_log_debug!(
                        "Peer ({:?}) update connection.state {:?} -> {:?}",
                        &pk,
                        self.state,
                        ConnectionState::Broken,
                    );
                    self.state = ConnectionState::Broken;
                    return false;
                }
            }
            ConnectionState::Broken => {
                // Shouldn't get there
                return false;
            }
        }

        let now_gen = self.generation.unwrap_or_default();
        let new_gen = new_gen.unwrap_or_default();

        if now_gen < new_gen {
            telio_log_debug!(
                "Peer ({:?}) update path to: {:?}, {:?} < {:?}",
                &pk,
                path_type,
                now_gen,
                new_gen
            );

            // Assume new path is automatically active
            // May have strange usability here ?
            self.active.insert(path_type);
            self.path = Some(path_type);
            self.generation = Some(new_gen);
        }

        true
    }

    /// Select best active path. returns true if changes, false - otherwise
    fn select_best_path(
        &mut self,
        prio: impl DoubleEndedIterator<Item = PathType>,
        pk: &PublicKey,
    ) -> bool {
        // self.path == None -> Reconfiguration  =>  self.state = Init, path = Some(new_path), generation = None // e.g.: Some(Relay), (possible stop timer)
        // self.path is Some, self.generation is None, self.state == None, new_path() > path  =>  self.state = Transition, self.generation = Some(1), self.path = new_path  // First stable connection (typicaly Relay)
        // self.path is Some, self.generation is Some  =>  Some upadated path.

        let prio: Vec<_> = prio.collect();
        let new_path = prio
            .iter()
            .copied()
            .rev()
            .find(|pt| self.active.contains(pt));

        if new_path.is_none() || self.path == new_path {
            return false;
        }

        match self.path {
            Some(_) => {
                if self.generation.is_none() && self.state == ConnectionState::Init {
                    // First stable connection
                    self.state = ConnectionState::Transition;
                    self.generation = Some(Generation::default().next());
                } else if let Some(gen) = self.generation {
                    // Ordinary path update
                    self.generation = Some(gen.next());
                } else {
                    telio_log_info!("Peer {:?} has invalid state: {:?}", pk, self,);
                    return false;
                }
            }
            // Complete reconfiguration
            None => {
                self.state = ConnectionState::Init;
                self.generation = None;
            }
        }

        self.path = new_path;

        telio_log_info!(
            "For peer {:?} found path {:?} out of {:?}",
            pk,
            &new_path,
            &prio
        );

        true
    }
}

fn routes(pathset: &PathSet) -> Vec<(PathType, &RouteType)> {
    pathset
        .prio
        .iter()
        .map(|pt| (*pt, &pathset.paths[pt].route))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::RouteResult;
    use telio_crypto::SecretKey;
    use telio_model::api_config::PathType::*;
    use tokio::{sync::Mutex, time::timeout};

    use super::*;
    use crate::router::ConfigBuilder;

    #[tokio::test]
    async fn with_single_paths() {
        let util::Env {
            peers,
            mut mock,
            mut proxy,
            paths,
            ..
        } = util::init(2, &[(Relay, false)]);

        let mut relay = mock.get_mut(&Relay).unwrap();

        relay.set_peers(peers.clone()).await;
        paths
            .configure(
                ConfigBuilder::default()
                    .peers(peers.iter().cloned().collect())
                    .build()
                    .expect("build config"),
            )
            .await
            .expect("configure");

        // Proxy first

        util::check_proxy2mock(
            &proxy,
            &mut relay,
            peers[0],
            DataMsg::new(b"a"),
            DataMsg::new(b"a"),
        )
        .await;

        util::check_mock2proxy(
            &relay,
            &mut proxy,
            peers[0],
            DataMsg::new(b"aa"),
            DataMsg::new(b"aa"),
        )
        .await;

        // Relay first
        util::check_mock2proxy(
            &relay,
            &mut proxy,
            peers[1],
            DataMsg::new(b"b"),
            DataMsg::new(b"b"),
        )
        .await;
        util::check_proxy2mock(
            &proxy,
            &mut relay,
            peers[1],
            DataMsg::new(b"bb"),
            DataMsg::new(b"bb"),
        )
        .await;

        paths.stop().await;
    }

    mod util {
        use crate::paths::relay::Default;
        use crate::Configure;

        use super::*;

        pub fn init(peers: usize, paths: &[(PathType, bool)]) -> Env {
            // Useful to see trace logs on failures.
            let _ = env_logger::builder().is_test(true).try_init();

            let peer: Vec<_> = (0..peers).map(|_| SecretKey::gen().public()).collect();
            let (build_paths, path_mock) = MockPaths::new(paths);
            let (lproxy, proxy) = Chan::pipe();
            let Chan {
                tx: events_tx,
                rx: events,
            } = Chan::default();

            let paths = Paths::start_with(
                Io {
                    data: lproxy,
                    events: events_tx,
                },
                build_paths,
            )
            .unwrap();

            Env {
                peers: peer,
                mock: path_mock,
                proxy,
                paths,
                events,
            }
        }

        pub type Msg = (PublicKey, DataMsg);
        pub type Proxy = Chan<Msg>;
        pub async fn check_mock2proxy(
            mock: &MockPathEnd,
            proxy: &mut Proxy,
            pk: PublicKey,
            tx: DataMsg,
            rx: DataMsg,
        ) {
            mock.send((pk, tx)).await;
            assert_eq!(
                timeout(Duration::from_millis(500), proxy.rx.recv())
                    .await
                    .unwrap(),
                Some((pk, rx))
            );
        }

        pub async fn check_proxy2mock(
            proxy: &Proxy,
            mock: &mut MockPathEnd,
            pk: PublicKey,
            tx: DataMsg,
            rx: DataMsg,
        ) {
            proxy.tx.send((pk, tx)).await.expect("proxy send");
            assert_eq!(
                timeout(Duration::from_millis(500), mock.recv(),)
                    .await
                    .unwrap(),
                Some((pk, rx))
            );
        }

        pub struct Env {
            pub peers: Vec<PublicKey>,
            pub mock: HashMap<PathType, MockPathEnd>,
            pub proxy: Chan<(PublicKey, DataMsg)>,
            pub paths: Paths,
            pub events: Rx<(PublicKey, PathType)>,
        }

        #[derive(Clone, Default)]
        pub struct MockRoute(pub Arc<Mutex<HashMap<PublicKey, bool>>>);

        pub struct MockPathEnd {
            pub route: MockRoute,
            pub send: Option<Tx<(PublicKey, bool)>>,
            pub data: Chan<(PublicKey, DataMsg)>,
        }

        pub struct MockPaths(HashMap<PathType, Path>);

        #[async_trait]
        impl Configure for MockRoute {
            async fn configure(&self, _config: telio_relay::Config) {}
        }

        #[async_trait]
        impl Route for MockRoute {
            /// Set nodes to natter's database, for them to be traversed
            async fn set_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
                assert_eq!(
                    nodes.into_iter().collect::<HashSet<_>>(),
                    self.0.lock().await.keys().cloned().collect::<HashSet<_>>()
                );
                Ok(())
            }

            /// update nodes to natter's database, for them to be traversed
            async fn update_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
                self.set_nodes(nodes).await
            }

            /// Reset nodes state
            async fn reset_nodes(&self, nodes: Vec<PublicKey>) -> RouteResult<()> {
                self.set_nodes(nodes).await
            }

            /// Check, if a peer has an active path through natter
            async fn is_reachable(&self, node: PublicKey) -> bool {
                self.0.lock().await[&node]
            }

            /// Check peer's path metric
            async fn rtt(&self, _node: PublicKey) -> RouteResult<Duration> {
                unimplemented!("not used")
            }
        }

        impl MockPathEnd {
            pub async fn set_peers(&self, peers: Vec<PublicKey>) {
                self.route
                    .0
                    .lock()
                    .await
                    .extend(peers.into_iter().map(|pk| (pk, self.send.is_none())));
            }

            #[allow(dead_code)]
            pub async fn change(&self, pk: PublicKey, con: bool) {
                if let Some(send) = &self.send {
                    self.route.0.lock().await.insert(pk, con);
                    let _ = send.send((pk, con)).await.expect("notify");
                }
            }

            pub async fn send(&self, msg: (PublicKey, DataMsg)) {
                let _ = self.data.tx.send(msg).await.expect("relay send");
            }

            pub async fn recv(&mut self) -> Option<(PublicKey, DataMsg)> {
                self.data.rx.recv().await
            }
        }

        impl MockPaths {
            pub fn new(fake: &[(PathType, bool)]) -> (Self, HashMap<PathType, MockPathEnd>) {
                let mut mocks = HashMap::new();
                let mut paths = HashMap::new();
                for (pt, change) in fake {
                    let route = MockRoute::default();
                    let (ldata, rdata) = Chan::pipe();
                    let mut mock = MockPathEnd {
                        route: route.clone(),
                        data: ldata,
                        send: None,
                    };
                    let mut path = Path {
                        route: RouteType::Relay { relay: Default },
                        channel: rdata,
                        changes: None,
                    };
                    if *change {
                        let ev = Chan::default();
                        mock.send = Some(ev.tx);
                        path.changes = Some(ev.rx);
                    }
                    mocks.insert(*pt, mock);
                    paths.insert(*pt, path);
                }
                (Self(paths), mocks)
            }
        }

        impl PathSetBuilder for MockPaths {
            // build fake path builder, with conditional change handler
            fn build(self) -> Result<PathSet, Error> {
                let mut set = PathSet::new();
                for (pt, p) in self.0.into_iter() {
                    set.add_next(pt, p);
                }
                return Ok(set);
            }
        }
    }
}
