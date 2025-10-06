//! Component that defines a peer link state, computing if its up/down.
mod enhanced_detection;

use std::{
    collections::HashMap,
    default,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

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

use self::enhanced_detection::EnhancedDetection;
use crate::{
    uapi::UpdateReason,
    wg::{BytesAndTimestamps, WG_KEEPALIVE},
};

/// Component that manages the link state of each peer.
///
/// `LinkDetection` monitors peer connectivity by analyzing traffic patterns and when enhanced
/// detection is enabled performing active probing through ICMP ping to determine if a peer link is up or down.
///
/// # Features
/// - Passive detection based on WireGuard traffic statistics
/// - Optional enhanced detection using ICMP pings
/// - Network change awareness for improved reliability (windows-only, LLT-5073)
/// - Configurable RTT thresholds and downgrade behavior
pub struct LinkDetection {
    cfg_max_allowed_rtt: Duration,
    enhanced_detection: Option<EnhancedDetection>,
    ping_channel: chan::Tx<(Vec<IpAddr>, Option<IpStack>)>,
    peers: HashMap<PublicKey, State>,
    use_for_downgrade: bool,
    enhanced_detection_enabled: bool,
    #[cfg(target_os = "windows")]
    nw_change_observer_rx: Option<chan::Rx<()>>,
    // Keeping observer handle ptr for lifetime management
    #[cfg(target_os = "windows")]
    _observer_handle: Option<Arc<LinkDetectionObserver>>,
}

/// Observer wrapper that forwards network change events from network monitor to LinkDetection
///
/// This spares LinkDetection to be Send+Sync because otherwise a LinkDetection reference would need
/// to be passed to the NetworkMonitor mod (see telio::device::Runtime::start()) just for the sake of
/// accessing the LocalInterfacesObserver::notify() implementation.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct LinkDetectionObserver {
    /// Channel transmitter for sending network change notifications
    pub tx: chan::Tx<()>,
}

#[cfg(target_os = "windows")]
impl LocalInterfacesObserver for LinkDetectionObserver {
    fn notify(&self) {
        telio_log_debug!("Notified about local interfaces change");
        // don't block or panic if the receiver is gone
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(()).await;
        });
    }
}

impl LinkDetection {
    /// Creates a new `LinkDetection` instance with the specified configuration.
    pub fn new(
        cfg: FeatureLinkDetection,
        ipv6_enabled: bool,
        socket_pool: Arc<SocketPool>,
        #[cfg(target_os = "windows")] nw_change_observer_rx: Option<chan::Rx<()>>,
        #[cfg(target_os = "windows")] _observer_handle: Option<Arc<LinkDetectionObserver>>,
    ) -> Self {
        let ping_channel = Chan::default();
        let enhanced_detection_enabled = cfg.no_of_pings > 0;
        let enhanced_detection = if enhanced_detection_enabled || cfg!(target_os = "windows") {
            EnhancedDetection::start_with(
                ping_channel.rx,
                cfg.no_of_pings,
                ipv6_enabled,
                socket_pool,
            )
            .ok()
        } else {
            None
        };

        telio_log_debug!(
            "instantiating link detection. cfg.rtt_seconds: {:?}, enhanced_detection: {}",
            cfg.rtt_seconds,
            enhanced_detection.is_some(),
        );

        LinkDetection {
            cfg_max_allowed_rtt: Duration::from_secs(cfg.rtt_seconds),
            enhanced_detection,
            ping_channel: ping_channel.tx,
            peers: HashMap::default(),
            use_for_downgrade: cfg.use_for_downgrade,
            enhanced_detection_enabled,
            #[cfg(target_os = "windows")]
            nw_change_observer_rx,
            #[cfg(target_os = "windows")]
            _observer_handle,
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
        if let Some(rx) = &mut self.nw_change_observer_rx {
            if rx.try_recv().is_ok() {
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
            "update for {}, node_addresses: {:?}, reason: {:?}, curr_ip_stack: {:?}",
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
            let result = state.update(self.cfg_max_allowed_rtt, self.enhanced_detection_enabled);

            telio_log_debug!(
                "enhanced detection: {}, result.should_ping: {}. result.link_detection_update_result: {:?}",
                self.enhanced_detection_enabled,
                result.should_ping,
                result.link_detection_update_result
            );
            if (self.enhanced_detection_enabled || cfg!(target_os = "windows"))
                && result.should_ping
            {
                if let Err(e) = self
                    .ping_channel
                    .send((node_addresses, curr_ip_stack))
                    .await
                {
                    telio_log_warn!("Failed to trigger ping to {:?} {:?}", public_key, e);
                }
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

    /// Stops the link detection component, releasing any associated resources.
    pub async fn stop(self) {
        if let Some(ed) = self.enhanced_detection {
            ed.stop().await;
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

        telio_log_debug!("push_update: {:?}", res);
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
// A ICMP ping request may be triggered from  PossibleDown when the ED is enabled, or (wireguardNT exclusive) from the
// StateVariant::Up state regardless of the ED state a network interface change is detected.
// StateVariant::PossibleDown which introduces a little delay of 3 seconds (or more for ED) until we report link state Down.
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
    should_ping: bool,
    link_detection_update_result: LinkDetectionUpdateResult,
}

#[derive(Debug)]
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

    fn update(&mut self, cfg_max_allowed_rtt: Duration, ping_enabled: bool) -> StateUpdateResult {
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
                    // Transition to PossibleDown
                    // No notify for now

                    let delay = if ping_enabled {
                        // If enhanced detection is enabled we will issue an ICMP echo request
                        // The maximum waiting time for a response can be WG_KEEPALIVE + rtt
                        // We will receive either an ICMP response or a Passive Keepalive message
                        WG_KEEPALIVE
                            .checked_add(cfg_max_allowed_rtt)
                            .unwrap_or(WG_KEEPALIVE)
                    } else {
                        Self::POSSIBLE_DOWN_DELAY
                    };

                    self.variant = StateVariant::PossibleDown {
                        deadline: now.checked_add(delay).unwrap_or(now),
                    };
                    telio_log_debug!("Possibly down. delay={:?}", delay);
                    if ping_enabled {
                        return Self::build_result(StateDecision::Ping, LinkState::Up);
                    }
                } else {
                    // Current link_state is Up
                    telio_log_debug!("definitely up");
                }
                Self::build_result(StateDecision::NoAction, LinkState::Up)
            }

            #[cfg(target_os = "windows")]
            StateVariant::NetworkChanged => {
                telio_log_debug!("Network interfaces have changed making peer link state unreliable, will ping regardless of enhanced detection state ({})", ping_enabled);
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

        state.update(Duration::ZERO, false);
        assert!(matches!(state.variant, StateVariant::Down));

        assert!(matches!(state.variant, StateVariant::Down));

        time::advance(ONE_SECOND).await;

        state.stats.lock().unwrap().update(1, 1, Instant::now());
        assert!(matches!(state.variant, StateVariant::Down));

        state.update(Duration::ZERO, false);
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

        state.update(Duration::ZERO, false);
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
        state.update(Duration::ZERO, false);
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
        state.update(ONE_SECOND, false);
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
}
