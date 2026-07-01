//! Component that defines a peer link state, computing if its up/down.

use std::{
    collections::HashMap,
    default,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Mutex as TokioMutex;

use telio_crypto::PublicKey;
use telio_model::{
    features::FeatureLinkDetection,
    mesh::{LinkState, NodeState},
};
use telio_network_monitors::monitor::LocalInterfacesObserver;
use telio_sockets::SocketPool;
use telio_task::io::{chan, Chan};
use telio_utils::{
    get_ip_stack, telio_err_with_log, telio_log_debug, telio_log_error, telio_log_trace,
    telio_log_warn, Instant, IpStack,
};

#[cfg(target_os = "windows")]
use crate::LinkDetectionObserver;

use crate::{
    uapi::UpdateReason,
    wg::{BytesAndTimestamps, WG_KEEPALIVE},
};

/// Component that manages the link state of each peer.
///
/// `LinkDetection` monitors peer connectivity by analyzing traffic patterns.
///
/// # Features
/// - Passive detection based on WireGuard traffic statistics
/// - Optional enhanced detection using ICMP pings
/// - Network change awareness for improved reliability (windows-only, LLT-5073)
/// - Configurable RTT thresholds and downgrade behavior
pub struct LinkDetection {
    cfg_max_allowed_rtt: Duration,
    #[cfg(target_os = "windows")]
    nw_changes_observer: Arc<LinkDetectionObserver>,
    peers: HashMap<PublicKey, State>,
    use_for_downgrade: bool,
}

impl LinkDetection {
    /// Creates a new `LinkDetection` instance with the specified configuration.
    pub fn new(
        cfg: FeatureLinkDetection,
        #[cfg(target_os = "windows")] nw_changes_observer: Arc<LinkDetectionObserver>,
    ) -> Self {
        telio_log_debug!(
            "instantiating link detection. cfg.rtt_seconds: {:?}",
            cfg.rtt_seconds
        );

        LinkDetection {
            cfg_max_allowed_rtt: Duration::from_secs(cfg.rtt_seconds),
            #[cfg(target_os = "windows")]
            nw_changes_observer,
            peers: HashMap::default(),
            use_for_downgrade: cfg.use_for_downgrade,
        }
    }

    /// Inserts a new peer.
    ///
    /// # Parameters
    /// - `public_key`: The public key identifying the peer
    /// - `stats`: Shared peer's traffic counters
    pub fn insert(&mut self, public_key: &PublicKey, stats: Arc<Mutex<BytesAndTimestamps>>) {
        telio_log_debug!("insert {}", public_key);
        self.peers
            .insert(*public_key, State::new(stats, self.cfg_max_allowed_rtt));
    }

    /// Processes pending network change notifications.
    ///
    /// This method checks for network interface changes and adjusts link state tracking
    /// accordingly, particularly on Windows where interface state changes can affect
    /// traffic counter reliability.
    /// This is a workaround for WireguardNT (windows): #LLT-5073
    #[cfg(target_os = "windows")]
    pub async fn handle_network_changes(&mut self) {
        if self
            .nw_changes_observer
            .occurred
            .swap(false, Ordering::AcqRel)
        {
            // On WireguardNT tx counters are not increased when the interface is disabled. It's then
            // considered that it might have happened and thus the link state detection is triggered by
            // artificially setting the first_ts_after_rx instant and start the countdown
            // TODO: Implement local interfaces tracking to accurately find if the relevant interface
            // was indeed disabled.
            for (public_key, state) in &mut self.peers {
                state.stats.lock().map_or_else(
                    |e| {
                        telio_log_error!("poisoned lock - {}", e);
                    },
                    |mut stats| {
                        telio_log_debug!(
                            "Overriding first_tx_after_rx due to network change for: {}",
                            public_key
                        );
                        stats.first_tx_after_rx = Some(Instant::now());
                    },
                );
                state.variant = StateVariant::NetworkChanged;
            }
        }
    }

    /// Updates the link state for a specific peer.
    ///
    /// # Returns
    /// A `LinkDetectionUpdateResult` indicating whether the link state changed and
    /// whether a notification should be sent
    pub async fn update(
        &mut self,
        public_key: &PublicKey,
        node_addresses: Vec<IpAddr>,
        reason: UpdateReason,
        curr_ip_stack: Option<IpStack>,
    ) -> LinkDetectionUpdateResult {
        telio_log_debug!(
            "update for {:?}, node_addresses: {:?}, reason: {:?}, curr_ip_stack: {:?}",
            public_key,
            node_addresses,
            reason,
            curr_ip_stack
        );
        // We want to update info only on pull
        if reason == UpdateReason::Push {
            return self.push_update(public_key);
        }

        if let Some(state) = self.peers.get_mut(public_key) {
            let result = state.update(self.cfg_max_allowed_rtt);

            telio_log_debug!(
                "{:?} -> {:?}",
                public_key,
                result.link_detection_update_result
            );
            #[cfg(target_os = "windows")]
            if result.should_ping {
                self.nw_changes_observer
                    .ping(node_addresses, curr_ip_stack)
                    .await
            }

            result.link_detection_update_result
        } else {
            telio_log_debug!("no peer to update");
            LinkDetectionUpdateResult {
                should_notify: false,
                link_state: Some(LinkState::Down),
            }
        }
    }

    /// Removes a peer.
    pub fn remove(&mut self, public_key: &PublicKey) {
        telio_log_debug!("remove {}", public_key);
        self.peers.remove(public_key);
    }

    /// Gets the link state for a peer if downgrade detection is enabled.
    pub fn get_link_state_for_downgrade(&self, public_key: &PublicKey) -> Option<LinkState> {
        if self.use_for_downgrade {
            self.peers.get(public_key).map(|s| s.current_link_state())
        } else {
            None
        }
    }

    fn push_update(&self, public_key: &PublicKey) -> LinkDetectionUpdateResult {
        let res = LinkDetectionUpdateResult {
            should_notify: false,
            link_state: Some(
                self.peers
                    .get(public_key)
                    .map_or(LinkState::Down, |p| p.current_link_state()),
            ),
        };

        telio_log_debug!("push_update: {:?} -> {:?}", public_key, res);
        res
    }
}

/// Result of a link detection update operation.
#[derive(Default, Debug)]
pub struct LinkDetectionUpdateResult {
    /// Whether the link state change should trigger a notification
    pub should_notify: bool,
    /// The current link state, if available
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
// Whenever it is detected, it will reset the fsm into StateVariant::Down.
// Transitions to StateVariant::Up are straight forward, when the is_link_up condition is true.
// Transition from StateVariant::Up to StateVariant::Down is made through the StateVariant::PossibleDown state.
// Transition from StateVariant::Up to StateVariant::PossibleDown, when the is_link_up condition is false.
// StateVariant::PossibleDown introduces a delay of 3 seconds (State::POSSIBLE_DOWN_DELAY) until we report link state Down.
// Note (Windows): Whenever a network interface change is detected, an ICMP request is sent for every connected peer from the
// StateVariant::Up state. This while the first_tx_after_rx variable is artificially set so that LinkDetection component
// can work as usual. (LLT-5073)
#[derive(Debug)]
enum StateVariant {
    Down,
    PossibleDown {
        deadline: Instant,
    },
    Up,
    #[cfg(target_os = "windows")]
    NetworkChanged,
}

#[derive(Debug)]
struct StateUpdateResult {
    #[cfg(target_os = "windows")]
    should_ping: bool,
    link_detection_update_result: LinkDetectionUpdateResult,
}

#[derive(Debug)]
enum StateDecision {
    NoAction,
    Notify,
    #[cfg(target_os = "windows")]
    Ping,
}

impl StateDecision {
    fn should_notify(&self) -> bool {
        matches!(self, StateDecision::Notify)
    }

    #[cfg(target_os = "windows")]
    fn should_ping(&self) -> bool {
        matches!(self, StateDecision::Ping)
    }
}

#[derive(Debug)]
struct State {
    stats: Arc<Mutex<BytesAndTimestamps>>,
    variant: StateVariant,
}

impl State {
    const POSSIBLE_DOWN_DELAY: Duration = Duration::from_secs(3);

    fn new(stats: Arc<Mutex<BytesAndTimestamps>>, cfg_max_allowed_rtt: Duration) -> Self {
        State {
            stats: stats.clone(),
            variant: match stats.lock() {
                Ok(s) => {
                    if s.is_link_up(cfg_max_allowed_rtt, Instant::now()) {
                        StateVariant::Up
                    } else {
                        StateVariant::Down
                    }
                }
                Err(e) => {
                    telio_log_error!("poisoned lock - {}", e);
                    StateVariant::Down
                }
            },
        }
    }

    fn update(&mut self, cfg_max_allowed_rtt: Duration) -> StateUpdateResult {
        let now = Instant::now();
        let is_link_up = match self.stats.lock() {
            Ok(s) => s.is_link_up(cfg_max_allowed_rtt, now),
            Err(e) => {
                telio_log_error!("poisoned lock - {}", e);
                false
            }
        };

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
                } else if now >= *deadline {
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
                    let delay = Self::POSSIBLE_DOWN_DELAY;

                    self.variant = StateVariant::PossibleDown {
                        deadline: now.checked_add(delay).unwrap_or(now),
                    };
                    telio_log_debug!("Possibly down. delay={:?}", delay);
                } else {
                    telio_log_debug!("Definitely up");
                }

                // Nothing to do, delay timer have started if link down
                Self::build_result(StateDecision::NoAction, LinkState::Up)
            }

            #[cfg(target_os = "windows")]
            StateVariant::NetworkChanged => {
                telio_log_debug!("Network interfaces have changed making peer link state unreliable, will send ICMP request");
                self.variant = StateVariant::Up;

                Self::build_result(StateDecision::Ping, LinkState::Up)
            }
        }
    }

    fn current_link_state(&self) -> LinkState {
        match self.variant {
            StateVariant::Down => LinkState::Down,
            StateVariant::Up | StateVariant::PossibleDown { .. } => LinkState::Up,
            #[cfg(target_os = "windows")]
            StateVariant::NetworkChanged => LinkState::Up,
        }
    }

    fn build_result(state_decision: StateDecision, link_state: LinkState) -> StateUpdateResult {
        StateUpdateResult {
            #[cfg(target_os = "windows")]
            should_ping: state_decision.should_ping(),
            link_detection_update_result: LinkDetectionUpdateResult {
                should_notify: state_decision.should_notify(),
                link_state: Some(link_state),
            },
        }
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
    fn test_state_build() {
        let stats_down = Arc::new(Mutex::new(BytesAndTimestamps::new(
            None,
            None,
            Instant::now(),
        )));
        let stats_up = Arc::new(Mutex::new(BytesAndTimestamps::new(
            Some(100),
            Some(100),
            Instant::now(),
        )));
        let rtt = Duration::ZERO;

        let down = State::new(stats_down, rtt);
        let up = State::new(stats_up, rtt);

        assert!(matches!(up.variant, StateVariant::Up));
        assert!(matches!(down.variant, StateVariant::Down));
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn test_state_transitions_from_down() {
        let mut state = State {
            stats: Arc::new(Mutex::new(BytesAndTimestamps::new(
                None,
                None,
                Instant::now(),
            ))),
            variant: StateVariant::Down,
        };
        assert!(matches!(state.variant, StateVariant::Down));

        time::advance(ONE_SECOND).await;

        state.stats.lock().unwrap().update(0, 1, Instant::now());

        time::advance(WG_KEEPALIVE).await;

        state.update(Duration::ZERO);
        assert!(matches!(state.variant, StateVariant::Down));

        assert!(matches!(state.variant, StateVariant::Down));

        time::advance(ONE_SECOND).await;

        state.stats.lock().unwrap().update(1, 1, Instant::now());
        assert!(matches!(state.variant, StateVariant::Down));

        state.update(Duration::ZERO);
        assert!(matches!(state.variant, StateVariant::Up));
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn test_state_transition_from_up() {
        let mut state = State {
            stats: Arc::new(Mutex::new(BytesAndTimestamps::new(
                Some(0),
                Some(0),
                Instant::now(),
            ))),
            variant: StateVariant::Up,
        };

        state.stats.lock().unwrap().update(0, 1, Instant::now());
        time::advance(WG_KEEPALIVE).await;

        state.update(Duration::ZERO);
        assert!(matches!(state.variant, StateVariant::PossibleDown { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn test_state_transition_from_possible_down_to_down() {
        let mut state = State {
            stats: Arc::new(Mutex::new(BytesAndTimestamps::new(
                None,
                None,
                Instant::now(),
            ))),
            variant: StateVariant::PossibleDown {
                deadline: Instant::now().checked_add(Duration::from_secs(3)).unwrap(),
            },
        };
        assert!(matches!(state.variant, StateVariant::PossibleDown { .. }));

        time::advance(Duration::from_secs(3)).await;
        state.update(Duration::ZERO);
        assert!(matches!(state.variant, StateVariant::Down));
    }

    #[tokio::test(start_paused = true)]
    async fn test_state_transition_from_possible_down_to_up() {
        let mut state = State {
            stats: Arc::new(Mutex::new(BytesAndTimestamps::new(
                None,
                None,
                Instant::now(),
            ))),
            variant: StateVariant::PossibleDown {
                deadline: Instant::now().checked_add(Duration::from_secs(3)).unwrap(),
            },
        };
        assert!(matches!(state.variant, StateVariant::PossibleDown { .. }));

        state.stats.lock().unwrap().update(1, 1, Instant::now());
        state.update(ONE_SECOND);
        assert!(matches!(state.variant, StateVariant::Up));
    }

    #[test]
    fn test_state_current_link_state() {
        let down = State {
            stats: Arc::new(Mutex::new(BytesAndTimestamps::new(
                None,
                None,
                Instant::now(),
            ))),
            variant: StateVariant::Down,
        };
        let possible_down = State {
            stats: Arc::new(Mutex::new(BytesAndTimestamps::new(
                None,
                None,
                Instant::now(),
            ))),
            variant: StateVariant::PossibleDown {
                deadline: Instant::now(),
            },
        };
        let up = State {
            stats: Arc::new(Mutex::new(BytesAndTimestamps::new(
                None,
                None,
                Instant::now(),
            ))),
            variant: StateVariant::Up,
        };

        assert_eq!(down.current_link_state(), LinkState::Down);
        assert_eq!(possible_down.current_link_state(), LinkState::Up);
        assert_eq!(up.current_link_state(), LinkState::Up);
    }

    /// Characterize the link state detection window for a given `rtt`,
    /// and returns the measured hold-down after which `LinkState::Down` is reported.
    ///
    /// Polls once per second, like the real WireGuard UAPI cadence, and asserts:
    /// * **within the window**: the link is reported only `Up`
    /// * **at the deadline**: a single `Down` notify
    /// * **after the deadline**: `Down` holds and is not re-notified.
    async fn measure_hold_down_secs(rtt_secs: u64) -> u64 {
        let rtt = Duration::from_secs(rtt_secs);
        let start = Instant::now();
        let rx = 1;
        let tx = 1;

        let stats = Arc::new(Mutex::new(BytesAndTimestamps::new(
            Some(rx),
            Some(tx),
            start,
        )));
        time::advance(ONE_SECOND).await;
        // A tx delta of 1 (!= KEEPALIVE_PACKET_SIZE) counts as real data and arms first_tx_after_rx.
        stats.lock().unwrap().update(rx, tx + 1, Instant::now());
        let first_tx = Instant::now();

        let mut state = State {
            stats: stats.clone(),
            variant: StateVariant::Up,
        };

        // Track number of down notifications and the time of the first down state
        let mut first_down_at: Option<u64> = None;
        let mut down_notifications_count = 0u32;

        // 5 seconds to check Down state holds
        let down_window = 5;
        // Down event deadline: `13 + rtt`
        let test_duration = (WG_KEEPALIVE.as_secs() + rtt_secs)
            + State::POSSIBLE_DOWN_DELAY.as_secs()
            + down_window;

        for _ in 0..test_duration {
            time::advance(ONE_SECOND).await;
            let now = Instant::now();
            let elapsed = now.duration_since(first_tx).as_secs();
            let result = state.update(rtt);
            let update = result.link_detection_update_result;
            let is_down_notify =
                update.should_notify && matches!(update.link_state, Some(LinkState::Down));

            if is_down_notify {
                down_notifications_count += 1;
                first_down_at.get_or_insert(elapsed);
            }

            if first_down_at.is_none() {
                // within the rtt window only Up may be reported
                assert!(
                    !update.should_notify,
                    "rtt={}: unexpected notify at {}s, before the deadline",
                    rtt_secs, elapsed
                );
                assert!(
                    matches!(update.link_state, Some(LinkState::Up)),
                    "rtt={}: reported link_state != Up at {}s (within window)",
                    rtt_secs,
                    elapsed
                );
                assert!(
                    matches!(state.current_link_state(), LinkState::Up),
                    "rtt={}: current_link_state != Up at {}s (within window)",
                    rtt_secs,
                    elapsed
                );
            } else {
                // after the deadline Down must hold
                assert!(
                    matches!(state.current_link_state(), LinkState::Down),
                    "rtt={}: link not Down without inbound at {}s",
                    rtt_secs,
                    elapsed
                );
            }
        }

        assert_eq!(
            down_notifications_count, 1,
            "rtt={rtt_secs}: expected exactly one Down notify, got {down_notifications_count}"
        );
        first_down_at.unwrap_or_else(|| {
            panic!(
                "link never reported Down within the measurement window for rtt={}",
                rtt_secs
            )
        })
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn test_hold_down_time() {
        for rtt in [0u64, 5, 15, 20, 25, 30] {
            let expected = (WG_KEEPALIVE.as_secs() + rtt) + State::POSSIBLE_DOWN_DELAY.as_secs();
            let measured = measure_hold_down_secs(rtt).await;
            assert_eq!(
                measured, expected,
                "rtt={rtt}: expected {expected}s hold-down, measured {measured}s"
            );
        }
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn test_keepalive_within_hold_down_window() {
        for rtt_secs in [0u64, 5, 15, 20, 25, 30] {
            let rtt = Duration::from_secs(rtt_secs);
            let grace = WG_KEEPALIVE.as_secs() + rtt_secs;
            let hold_down = grace + State::POSSIBLE_DOWN_DELAY.as_secs();

            for inbound_interval in [grace - 1, hold_down - 1] {
                let start = Instant::now();
                let mut rx: u64 = 1;
                let mut tx: u64 = 1;
                let stats = Arc::new(Mutex::new(BytesAndTimestamps::new(
                    Some(rx),
                    Some(tx),
                    start,
                )));
                let mut state = State {
                    stats: stats.clone(),
                    variant: StateVariant::Up,
                };

                // Drive >3 inbound cycles.
                for i in 1..=(inbound_interval * 3 + 2) {
                    time::advance(ONE_SECOND).await;
                    let now = Instant::now();

                    // received keepalive lands every `inbound_interval` seconds
                    if i % inbound_interval == 0 {
                        rx += 1;
                    }
                    // transmitting non-keepalive data (delta != KEEPALIVE_PACKET_SIZE)
                    // re-arming first_tx_after_rx
                    tx += 1;
                    stats.lock().unwrap().update(rx, tx, now);

                    let result = state.update(rtt);
                    let update = result.link_detection_update_result;

                    assert!(
                        matches!(state.current_link_state(), LinkState::Up),
                        "rtt={} interval={}: link not Up at {}s (variant {:?})",
                        rtt_secs,
                        inbound_interval,
                        i,
                        state.variant
                    );
                    assert!(
                        !(update.should_notify
                            && matches!(update.link_state, Some(LinkState::Down))),
                        "rtt={} interval={}: unexpected Down notify at {}s",
                        rtt_secs,
                        inbound_interval,
                        i,
                    );
                }
            }
        }
    }
}
