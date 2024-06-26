use enhanced_detection::EnhancedDetection;
use std::{collections::HashMap, default, net::IpAddr, time::Duration};
use tokio::time::Instant;

use telio_crypto::PublicKey;
use telio_model::{
    features::FeatureLinkDetection,
    mesh::{LinkState, NodeState},
};
use telio_task::io::{chan, Chan};
use telio_utils::{telio_err_with_log, telio_log_debug, telio_log_trace, telio_log_warn};

mod enhanced_detection;

/// Default wireguard keepalive duration
const WG_KEEPALIVE: Duration = Duration::from_secs(10);
/// Keepalive packets size
const KEEPALIVE_PACKET_SIZE: u64 = 32;

pub enum LinkDetection {
    Enabled(LinkDetectionEnabled),
    Disabled(LinkDetectionDisabled),
}

impl LinkDetection {
    pub fn new(features: Option<FeatureLinkDetection>) -> Self {
        match features {
            None => LinkDetection::Disabled(LinkDetectionDisabled::default()),
            Some(features) => LinkDetection::Enabled(LinkDetectionEnabled::new(
                Duration::from_secs(features.rtt_seconds),
                features.no_of_pings,
            )),
        }
    }

    pub fn time_since_last_rx(&self, public_key: &PublicKey) -> Option<Duration> {
        match self {
            LinkDetection::Enabled(l) => l.time_since_last_rx(public_key),
            LinkDetection::Disabled(l) => l.time_since_last_rx(public_key),
        }
    }

    pub fn insert(
        &mut self,
        public_key: &PublicKey,
        rx_bytes: Option<u64>,
        tx_bytes: Option<u64>,
        node_state: NodeState,
    ) {
        match self {
            LinkDetection::Enabled(l) => l.insert(public_key, rx_bytes, tx_bytes, node_state),
            LinkDetection::Disabled(l) => l.insert(public_key, rx_bytes),
        }
    }

    pub async fn update(
        &mut self,
        public_key: &PublicKey,
        rx_bytes: Option<u64>,
        tx_bytes: Option<u64>,
        node_state: NodeState,
        node_addresses: Vec<IpAddr>,
        push: bool,
    ) -> LinkDetectionUpdateResult {
        match self {
            LinkDetection::Enabled(l) => {
                l.update(
                    public_key,
                    rx_bytes,
                    tx_bytes,
                    node_state,
                    node_addresses,
                    push,
                )
                .await
            }
            LinkDetection::Disabled(l) => l.update(public_key, rx_bytes, push).await,
        }
    }

    pub fn remove(&mut self, public_key: &PublicKey) {
        match self {
            LinkDetection::Enabled(l) => l.remove(public_key),
            LinkDetection::Disabled(l) => l.remove(public_key),
        }
    }

    pub fn is_disabled(&self) -> bool {
        matches!(self, LinkDetection::Disabled(_))
    }

    pub async fn stop(self) {
        match self {
            LinkDetection::Enabled(l) => l.stop().await,
            LinkDetection::Disabled(_) => (),
        }
    }
}

pub struct LinkDetectionEnabled {
    rtt: Duration,
    enhanced_detection: Option<EnhancedDetection>,
    ping_channel: chan::Tx<Vec<IpAddr>>,
    peers: HashMap<PublicKey, State>,
}

impl LinkDetectionEnabled {
    fn new(rtt: Duration, no_of_pings: u32) -> Self {
        let ping_channel = Chan::default();
        let enhanced_detection = if no_of_pings != 0 {
            EnhancedDetection::start_with(ping_channel.rx, no_of_pings).ok()
        } else {
            None
        };

        LinkDetectionEnabled {
            rtt,
            enhanced_detection,
            ping_channel: ping_channel.tx,
            peers: HashMap::default(),
        }
    }

    fn insert(
        &mut self,
        public_key: &PublicKey,
        rx_bytes: Option<u64>,
        tx_bytes: Option<u64>,
        node_state: NodeState,
    ) {
        self.peers
            .insert(*public_key, State::new(rx_bytes, tx_bytes, node_state));
    }

    async fn update(
        &mut self,
        public_key: &PublicKey,
        rx_bytes: Option<u64>,
        tx_bytes: Option<u64>,
        node_state: NodeState,
        node_addresses: Vec<IpAddr>,
        push: bool,
    ) -> LinkDetectionUpdateResult {
        // We want to update info only on pull
        if push {
            return self.push_update(public_key, node_state);
        }

        if let Some(state) = self.peers.get_mut(public_key) {
            let ping_enabled = self.enhanced_detection.is_some();
            let result = state.update(rx_bytes, tx_bytes, node_state, self.rtt, ping_enabled);

            if ping_enabled && result.should_ping {
                if let Err(e) = self.ping_channel.send(node_addresses).await {
                    telio_log_warn!("Failed to trigger ping to {:?} {:?}", public_key, e);
                }
            }

            result.link_detection_update_result
        } else {
            // Somehow we missed the node when it was new. We should recover from it.
            // To be less intrusive and to not disturb direct connections insert it.
            self.insert(public_key, rx_bytes, tx_bytes, node_state);

            let link_state = if matches!(node_state, NodeState::Connected) {
                LinkState::Up
            } else {
                LinkState::Down
            };

            // No notification. We try to recover.
            LinkDetectionUpdateResult {
                should_notify: false,
                link_state: Some(link_state),
            }
        }
    }

    fn remove(&mut self, public_key: &PublicKey) {
        self.peers.remove(public_key);
    }

    fn time_since_last_rx(&self, public_key: &PublicKey) -> Option<Duration> {
        self.peers
            .get(public_key)
            .and_then(|p| p.time_since_last_rx())
    }

    async fn stop(self) {
        if let Some(ed) = self.enhanced_detection {
            ed.stop().await;
        }
    }

    fn push_update(
        &self,
        public_key: &PublicKey,
        node_state: NodeState,
    ) -> LinkDetectionUpdateResult {
        let link_state = if matches!(node_state, NodeState::Connected) {
            self.peers
                .get(public_key)
                .map(|p| p.current_link_state())
                .unwrap_or(LinkState::Down)
        } else {
            LinkState::Down
        };

        LinkDetectionUpdateResult {
            should_notify: false,
            link_state: Some(link_state),
        }
    }
}

#[derive(Default)]
pub struct LinkDetectionDisabled {
    last_rx_info: HashMap<PublicKey, (u64, Instant)>,
}

// Old time since last rx logic
impl LinkDetectionDisabled {
    fn time_since_last_rx(&self, public_key: &PublicKey) -> Option<Duration> {
        self.last_rx_info.get(public_key).map(|n| n.1.elapsed())
    }

    fn insert(&mut self, public_key: &PublicKey, rx_bytes: Option<u64>) {
        if let Some(rx_bytes) = rx_bytes {
            if rx_bytes > 0 {
                self.last_rx_info
                    .insert(*public_key, (rx_bytes, Instant::now()));
            }
        }
    }

    async fn update(
        &mut self,
        public_key: &PublicKey,
        rx_bytes: Option<u64>,
        push: bool,
    ) -> LinkDetectionUpdateResult {
        // We want to update info only on pull
        if !push {
            self.update_last_rx_info(public_key, rx_bytes);
        }

        LinkDetectionUpdateResult::default()
    }

    fn remove(&mut self, public_key: &PublicKey) {
        self.last_rx_info.remove(public_key);
    }

    fn update_last_rx_info(&mut self, public_key: &PublicKey, rx_bytes: Option<u64>) {
        if let Some((old_rx, _old_ts)) = self.last_rx_info.get(public_key) {
            if let Some(new_rx) = rx_bytes {
                if *old_rx != new_rx && new_rx > 0 {
                    self.last_rx_info
                        .insert(*public_key, (new_rx, Instant::now()));
                }
            }
        } else {
            // Somehow we missed the node when it was new. We should recover from it.
            self.insert(public_key, rx_bytes);
        }
    }
}

#[derive(Default)]
pub struct LinkDetectionUpdateResult {
    pub should_notify: bool,
    pub link_state: Option<LinkState>,
}

// +--------------+
// |      Down    |---------------------+
// +--------------+                     |
//         |                +----------------------+
//         |                |     PossibleDown     |
//         |                +----------------------+
//         |                            |
//  +--------------+                    |
//  |     Up       |--------------------+
//  +--------------+
// NodeState != Connected should act as a reset "button" on the fsm
// Whenever it is detected, it will reset the fsm into StateVariant::Down
// Transitions to StateVariant::Up are straight forward, when the is_link_up condition is true
// Transition from StateVariant::Up to StateVariant::Down is made through an additional state
// StateVariant::PossibleDown which introduces a little delay of 3 seconds until we report link state Down
enum StateVariant {
    Down,
    PossibleDown { deadline: Instant },
    Up,
}

struct StateUpdateResult {
    should_ping: bool,
    link_detection_update_result: LinkDetectionUpdateResult,
}

enum StateDecision {
    NoAction,
    Notify,
    Ping,
}

impl StateDecision {
    fn should_notify(&self) -> bool {
        matches!(self, StateDecision::Notify)
    }

    fn should_ping(&self) -> bool {
        matches!(self, StateDecision::Ping)
    }
}

struct State {
    stats: BytesAndTimestamps,
    variant: StateVariant,
}

impl State {
    const POSSIBLE_DOWN_DELAY: Duration = Duration::from_secs(3);

    fn new(rx_bytes: Option<u64>, tx_bytes: Option<u64>, node_state: NodeState) -> Self {
        let stats = BytesAndTimestamps::new(rx_bytes, tx_bytes);
        if matches!(node_state, NodeState::Connected) {
            State {
                stats,
                variant: StateVariant::Up,
            }
        } else {
            State {
                stats,
                variant: StateVariant::Down,
            }
        }
    }

    fn update(
        &mut self,
        rx_bytes: Option<u64>,
        tx_bytes: Option<u64>,
        node_state: NodeState,
        rtt: Duration,
        ping_enabled: bool,
    ) -> StateUpdateResult {
        // Guard if node_state is not connected
        // self -> new with down and return
        if !matches!(node_state, NodeState::Connected) {
            *self = State::new(rx_bytes, tx_bytes, node_state);
            return Self::build_result(StateDecision::NoAction, LinkState::Down);
        }

        let new_rx = rx_bytes.unwrap_or_default();
        let new_tx = tx_bytes.unwrap_or_default();
        self.stats.update(new_rx, new_tx);

        let is_link_up = self.stats.is_link_up(rtt);

        match &mut self.variant {
            StateVariant::Down => {
                if is_link_up {
                    // Transition to Up
                    // Report link state Up
                    self.variant = StateVariant::Up;
                    Self::build_result(StateDecision::Notify, LinkState::Up)
                } else {
                    // Stay in Down
                    // No notify
                    Self::build_result(StateDecision::NoAction, LinkState::Down)
                }
            }

            StateVariant::PossibleDown { deadline } => {
                if is_link_up {
                    // Transition to Up
                    // No notify
                    self.variant = StateVariant::Up;
                    Self::build_result(StateDecision::NoAction, LinkState::Up)
                } else if Instant::now() >= *deadline {
                    // Transition to Down
                    // Report link state Down
                    self.variant = StateVariant::Down;
                    Self::build_result(StateDecision::Notify, LinkState::Down)
                } else {
                    Self::build_result(StateDecision::NoAction, LinkState::Up)
                }
            }

            StateVariant::Up => {
                if !is_link_up {
                    // Transition to PossibleDown
                    // No notify for now

                    let delay = if ping_enabled {
                        // If enhanced detection is enabled we will issue an ICMP echo request
                        // The maximum waiting time for a response can be WG_KEEPALIVE + rtt
                        // We will receive either an ICMP response or a Passive Keepalive message
                        WG_KEEPALIVE.checked_add(rtt).unwrap_or(WG_KEEPALIVE)
                    } else {
                        Self::POSSIBLE_DOWN_DELAY
                    };

                    self.variant = StateVariant::PossibleDown {
                        deadline: Instant::now()
                            .checked_add(delay)
                            .unwrap_or_else(Instant::now),
                    };
                    Self::build_result(StateDecision::Ping, LinkState::Up)
                } else {
                    // Current link_state is Up
                    Self::build_result(StateDecision::NoAction, LinkState::Up)
                }
            }
        }
    }

    fn time_since_last_rx(&self) -> Option<Duration> {
        if self.stats.rx_bytes > 0 {
            Some(self.stats.rx_ts.elapsed())
        } else {
            None
        }
    }

    fn current_link_state(&self) -> LinkState {
        match self.variant {
            StateVariant::Up | StateVariant::PossibleDown { .. } => LinkState::Up,
            StateVariant::Down => LinkState::Down,
        }
    }

    fn build_result(state_decision: StateDecision, link_state: LinkState) -> StateUpdateResult {
        StateUpdateResult {
            should_ping: state_decision.should_ping(),
            link_detection_update_result: LinkDetectionUpdateResult {
                should_notify: state_decision.should_notify(),
                link_state: Some(link_state),
            },
        }
    }
}

#[derive(Copy, Clone)]
struct BytesAndTimestamps {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_ts: Instant,
    tx_ts: Instant,
}

impl BytesAndTimestamps {
    fn new(rx_bytes: Option<u64>, tx_bytes: Option<u64>) -> Self {
        let now = Instant::now();
        BytesAndTimestamps {
            rx_bytes: rx_bytes.unwrap_or_default(),
            tx_bytes: tx_bytes.unwrap_or_default(),
            rx_ts: now,
            tx_ts: now,
        }
    }

    fn update(&mut self, new_rx: u64, new_tx: u64) {
        let now = Instant::now();

        if new_rx > self.rx_bytes {
            self.rx_bytes = new_rx;
            self.rx_ts = now;
        }

        if new_tx > self.tx_bytes {
            // Ignore the keepalive messages
            // This only works in a limited fashion because we poll every second and
            // the detection might not work as intended if there are more packets within that time window.
            // On the sender side persistent-keepalives might interfere as those are emitted regardless the activity,
            // meaning for example if persistent-keepalive is set at 5seconds then it might interfere with the
            // passive-keepalive which is a constant of 10seconds.
            if new_tx - self.tx_bytes != KEEPALIVE_PACKET_SIZE {
                self.tx_ts = now;
            }
            self.tx_bytes = new_tx;
        }
    }

    fn is_link_up(&self, rtt: Duration) -> bool {
        self.tx_ts <= self.rx_ts || self.rx_ts.elapsed() < WG_KEEPALIVE + rtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link_detection;
    use telio_model::{features::FeatureLinkDetection, mesh::Node};
    use tokio::time;

    const ONE_SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn test_is_disabled_config() {
        // Disabled
        let no_link_detection = LinkDetection::new(None);
        assert_eq!(no_link_detection.is_disabled(), true);

        // Enabled
        let features = FeatureLinkDetection {
            rtt_seconds: 1,
            no_of_pings: 0,
        };
        let no_link_detection = LinkDetection::new(Some(features));
        assert_eq!(no_link_detection.is_disabled(), false);
    }

    #[tokio::test(start_paused = true)]
    async fn test_time_since_last_rx_with_disabled_link_detection() {
        let mut ld = LinkDetectionDisabled::default();
        let key = PublicKey::default();

        assert_eq!(ld.time_since_last_rx(&key), None);

        // Insert
        ld.insert(&key, None);
        assert_eq!(ld.time_since_last_rx(&key), None);
        ld.remove(&key);

        time::advance(Duration::from_secs(1)).await;

        // Insert with value
        ld.insert(&key, Some(5));
        let last_change = Instant::now();
        assert_eq!(ld.time_since_last_rx(&key), Some(last_change.elapsed()));

        time::advance(Duration::from_secs(1)).await;

        // Update with no change in rx_bytes, so there will be no timestamp update
        ld.update(&key, Some(5), false).await;
        assert_eq!(ld.time_since_last_rx(&key), Some(last_change.elapsed()));

        time::advance(Duration::from_secs(1)).await;

        // Update with different rx_bytes
        ld.update(&key, Some(10), false).await;
        assert_eq!(ld.time_since_last_rx(&key), Some(Instant::now().elapsed()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_time_since_last_rx_with_enabled_link_detection() {
        let mut ld = LinkDetectionEnabled::new(Duration::from_secs(15), 0);
        let key = PublicKey::default();

        assert_eq!(ld.time_since_last_rx(&key), None);

        // Insert
        ld.insert(&key, None, None, NodeState::Connecting);
        assert_eq!(ld.time_since_last_rx(&key), None);
        ld.remove(&key);

        time::advance(Duration::from_secs(1)).await;

        // Insert with value
        ld.insert(&key, Some(5), None, NodeState::Connecting);
        let last_change = Instant::now();
        assert_eq!(ld.time_since_last_rx(&key), Some(last_change.elapsed()));

        time::advance(Duration::from_secs(1)).await;

        // Update with no change in rx_bytes, so there will be no timestamp update
        ld.update(&key, Some(5), None, NodeState::Connected, Vec::new(), false)
            .await;
        assert_eq!(ld.time_since_last_rx(&key), Some(last_change.elapsed()));

        time::advance(Duration::from_secs(1)).await;

        // Update with different rx_bytes
        ld.update(
            &key,
            Some(10),
            None,
            NodeState::Connected,
            Vec::new(),
            false,
        )
        .await;
        assert_eq!(ld.time_since_last_rx(&key), Some(Instant::now().elapsed()));
    }

    #[test]
    fn test_state_build() {
        let down = State::new(None, None, NodeState::Connecting);
        let up = State::new(None, None, NodeState::Connected);

        assert!(matches!(down.variant, StateVariant::Down));
        assert!(matches!(up.variant, StateVariant::Up));
    }

    #[test]
    fn test_state_update_guard() {
        let mut state = State {
            stats: BytesAndTimestamps::new(None, None),
            variant: StateVariant::Up,
        };

        state.update(None, None, NodeState::Connecting, ONE_SECOND, false);

        assert!(matches!(state.variant, StateVariant::Down));
    }

    #[tokio::test(start_paused = true)]
    async fn test_state_transitions_from_down() {
        let mut state = State {
            stats: BytesAndTimestamps::new(Some(0), Some(0)),
            variant: StateVariant::Down,
        };

        // Make sure the Keepalive period and rtt has passed
        time::advance(Duration::from_secs(20)).await;

        // Update with data send and no response
        state.update(Some(0), Some(1), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::Down));

        // Let one more update call and second to pass
        time::advance(ONE_SECOND).await;
        state.update(Some(0), Some(1), NodeState::Connected, ONE_SECOND, false);

        // Update with response
        time::advance(ONE_SECOND).await;
        state.update(Some(1), Some(1), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::Up));
    }

    #[tokio::test(start_paused = true)]
    async fn test_state_transition_from_up() {
        let mut state = State {
            stats: BytesAndTimestamps::new(Some(0), Some(0)),
            variant: StateVariant::Up,
        };

        time::advance(ONE_SECOND).await;

        // Send some data to increase tx timestamp
        state.update(Some(0), Some(1), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::Up));

        // Wait with no response
        time::advance(WG_KEEPALIVE).await;
        state.update(Some(0), Some(2), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::PossibleDown { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn test_state_transition_from_possible_down_to_down() {
        let longer_ago = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let long_ago = Instant::now();
        // Make sure the Keepalive period and rtt has passed
        time::advance(Duration::from_secs(20)).await;

        let mut state = State {
            stats: BytesAndTimestamps {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_ts: longer_ago, // Received ealier than sended
                tx_ts: long_ago,
            },
            variant: StateVariant::PossibleDown {
                deadline: Instant::now().checked_add(Duration::from_secs(3)).unwrap(),
            },
        };

        time::advance(ONE_SECOND).await;
        state.update(Some(0), Some(1), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::PossibleDown { .. }));

        time::advance(ONE_SECOND).await;
        state.update(Some(0), Some(1), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::PossibleDown { .. }));

        time::advance(ONE_SECOND).await;
        state.update(Some(0), Some(1), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::Down));
    }

    #[tokio::test(start_paused = true)]
    async fn test_state_transition_from_possible_down_to_up() {
        let longer_ago = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let long_ago = Instant::now();
        // Make sure the Keepalive period and rtt has passed
        time::advance(Duration::from_secs(20)).await;

        let mut state = State {
            stats: BytesAndTimestamps {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_ts: longer_ago, // Received ealier than sended
                tx_ts: long_ago,
            },
            variant: StateVariant::PossibleDown {
                deadline: Instant::now().checked_add(Duration::from_secs(3)).unwrap(),
            },
        };

        // Receive some data
        state.update(Some(1), Some(1), NodeState::Connected, ONE_SECOND, false);
        assert!(matches!(state.variant, StateVariant::Up));
    }

    #[test]
    fn test_state_current_link_state() {
        let down = State {
            stats: BytesAndTimestamps::new(None, None),
            variant: StateVariant::Down,
        };
        let possible_down = State {
            stats: BytesAndTimestamps::new(None, None),
            variant: StateVariant::PossibleDown {
                deadline: Instant::now(),
            },
        };
        let up = State {
            stats: BytesAndTimestamps::new(None, None),
            variant: StateVariant::Up,
        };

        assert_eq!(down.current_link_state(), LinkState::Down);
        assert_eq!(possible_down.current_link_state(), LinkState::Up);
        assert_eq!(up.current_link_state(), LinkState::Up);
    }

    #[tokio::test(start_paused = true)]
    async fn test_bytes_and_timestamps_is_link_up() {
        let long_time_ago = Instant::now().checked_sub(Duration::from_secs(20)).unwrap();
        let longer_time_ago = Instant::now().checked_sub(Duration::from_secs(21)).unwrap();
        let a_second_ago = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();

        let mut stats = BytesAndTimestamps::new(None, None);

        stats.rx_ts = long_time_ago;
        stats.tx_ts = longer_time_ago;
        assert_eq!(stats.is_link_up(ONE_SECOND), true);

        stats.rx_ts = longer_time_ago;
        stats.tx_ts = long_time_ago;
        assert_eq!(stats.is_link_up(ONE_SECOND), false);

        stats.rx_ts = Instant::now();
        stats.tx_ts = a_second_ago;
        assert_eq!(stats.is_link_up(ONE_SECOND), true);

        stats.rx_ts = a_second_ago;
        stats.tx_ts = Instant::now();
        assert_eq!(stats.is_link_up(ONE_SECOND), true);
    }

    #[tokio::test(start_paused = true)]
    async fn test_bytes_and_timestamps_update() {
        let a_second_ago = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let mut stats = BytesAndTimestamps::new(Some(0), Some(0));

        stats.rx_ts = a_second_ago;
        stats.tx_ts = a_second_ago;
        stats.update(1, 0);
        assert_eq!(stats.rx_ts, Instant::now());
        assert_eq!(stats.tx_ts, a_second_ago);

        stats.rx_bytes = 0;
        stats.rx_ts = a_second_ago;
        stats.tx_ts = a_second_ago;
        stats.update(0, 1);
        assert_eq!(stats.rx_ts, a_second_ago);
        assert_eq!(stats.tx_ts, Instant::now());

        stats.tx_bytes = 0;
        stats.rx_ts = a_second_ago;
        stats.tx_ts = a_second_ago;
        stats.update(0, KEEPALIVE_PACKET_SIZE);
        assert_eq!(stats.rx_ts, a_second_ago);
        assert_eq!(stats.tx_ts, a_second_ago);
    }
}
