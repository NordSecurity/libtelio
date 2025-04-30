use enhanced_detection::EnhancedDetection;
use std::{
    collections::HashMap,
    default,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

use telio_crypto::PublicKey;
use telio_model::{
    features::FeatureLinkDetection,
    mesh::{LinkState, NodeState},
};
use telio_sockets::SocketPool;
use telio_task::io::{chan, Chan};
use telio_utils::{
    get_ip_stack, telio_err_with_log, telio_log_debug, telio_log_error, telio_log_trace,
    telio_log_warn, IpStack,
};

use crate::{
    uapi::UpdateReason,
    wg::{BytesAndTimestamps, WG_KEEPALIVE},
};

mod enhanced_detection;

pub struct LinkDetection {
    cfg_max_allowed_rtt: Duration,
    enhanced_detection: Option<EnhancedDetection>,
    ping_channel: chan::Tx<(Vec<IpAddr>, Option<IpStack>)>,
    peers: HashMap<PublicKey, State>,
    use_for_downgrade: bool,
}

impl LinkDetection {
    pub fn new(
        cfg: FeatureLinkDetection,
        ipv6_enabled: bool,
        socket_pool: Arc<SocketPool>,
    ) -> Self {
        let ping_channel = Chan::default();
        let enhanced_detection = if cfg.no_of_pings != 0 {
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
        }
    }

    pub fn insert(&mut self, public_key: &PublicKey, stats: Arc<Mutex<BytesAndTimestamps>>) {
        telio_log_debug!("insert {}", public_key);
        self.peers
            .insert(*public_key, State::new(stats, self.cfg_max_allowed_rtt));
    }

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
            let ping_enabled = self.enhanced_detection.is_some();
            let result = state.update(self.cfg_max_allowed_rtt, ping_enabled);

            telio_log_debug!(
                "ping_enabled: {}, result.should_ping: {}. result.link_detection_update_result: {:?}",
                ping_enabled,
                result.should_ping,
                result.link_detection_update_result
            );
            if ping_enabled && result.should_ping {
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

    pub fn remove(&mut self, public_key: &PublicKey) {
        telio_log_debug!("remove {}", public_key);
        self.peers.remove(public_key);
    }

    pub fn get_link_state_for_downgrade(&self, public_key: &PublicKey) -> Option<LinkState> {
        if self.use_for_downgrade {
            self.peers.get(public_key).map(|s| s.current_link_state())
        } else {
            None
        }
    }

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

#[derive(Default, Debug)]
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
#[derive(Debug)]
enum StateVariant {
    Down,
    PossibleDown { deadline: Instant },
    Up,
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
                    Self::build_result(StateDecision::Ping, LinkState::Up)
                } else {
                    // Current link_state is Up
                    telio_log_debug!("definitely up");
                    Self::build_result(StateDecision::NoAction, LinkState::Up)
                }
            }
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
