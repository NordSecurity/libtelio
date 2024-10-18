use std::fmt;
use telio_utils::{telio_log_debug, telio_log_warn};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EndpointState {
    Disconnected(Event),
    EndpointGathering,
    Ping,
    Published,
    Paused,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Event {
    StartUp,
    SendCallMeMaybeRequest,
    ReceiveCallMeMaybeResponse,
    Publish,
    Timeout,
    EndpointGone,
}

impl Default for EndpointState {
    fn default() -> Self {
        EndpointState::Disconnected(Event::StartUp)
    }
}
#[derive(Default, Debug)]
pub struct EndpointStateMachine {
    state: EndpointState,
}

impl EndpointStateMachine {
    pub fn handle_event(&mut self, event: Event) {
        match (&self.state, &event) {
            (EndpointState::Disconnected(_), Event::SendCallMeMaybeRequest) => {
                self.state = EndpointState::EndpointGathering;
            }

            (EndpointState::EndpointGathering, Event::ReceiveCallMeMaybeResponse) => {
                self.state = EndpointState::Ping;
            }

            (EndpointState::Ping, Event::Publish) => {
                self.state = EndpointState::Published;
            }

            (EndpointState::EndpointGathering | EndpointState::Ping, Event::Timeout) => {
                self.state = EndpointState::Disconnected(event);
            }

            (EndpointState::Published, Event::EndpointGone) => {
                self.state = EndpointState::Disconnected(event);
            }
            (EndpointState::Paused, event) => {
                telio_log_debug!("Endpoint is paused, event ignored: {:?}", event);
            }
            (_, event) => {
                telio_log_warn!("Invalid state transition {:?} -> {:?}", &self.state, event);
            }
        }
    }

    pub fn get(&self) -> EndpointState {
        self.state
    }

    pub fn new(state: EndpointState) -> EndpointStateMachine {
        EndpointStateMachine { state }
    }
}

impl PartialEq<EndpointState> for EndpointStateMachine {
    fn eq(&self, other: &EndpointState) -> bool {
        &self.state == other
    }
}

impl fmt::Display for EndpointStateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.state)
    }
}

#[macro_export]
macro_rules! do_state_transition {
    ($ep: expr, $event: expr) => {{
        if $ep.state.get() == EndpointState::Published || $event == Event::Publish {
            do_state_transition!($ep, $event, telio_log_info);
        } else {
            do_state_transition!($ep, $event, telio_log_debug);
        }
    }};
    ($ep: expr, $event: expr, $log: ident) => {{
        $log!(
            "Node's {:?} EP {:?} state transition {:?} -> {:?}",
            $ep.public_key,
            $ep.local_endpoint_candidate.udp,
            $ep.state,
            $event
        );
        $ep.last_state_transition = Instant::now();
        $ep.state.handle_event($event);
    }};
}
