use std::fmt;
use telio_utils::telio_log_warn;

#[derive(Debug, Default, PartialEq)]
pub enum EndpointState {
    #[default]
    Disconnected,
    EndpointGathering,
    Ping,
    Published,
}

#[derive(Debug, PartialEq)]
pub enum Event {
    SendCallMeMaybeRequest,
    ReceiveCallMeMaybeResponse,
    Publish,
    Timeout,
    EndpointGone,
}

#[derive(Default, Debug)]
pub struct EndpointStateMachine {
    state: EndpointState,
    last_event: Option<Event>,
}

impl EndpointStateMachine {
    pub fn handle_event(&mut self, event: Event) {
        match (&self.state, &event) {
            (EndpointState::Disconnected, Event::SendCallMeMaybeRequest) => {
                self.last_event = Some(event);
                self.state = EndpointState::EndpointGathering;
            }

            (EndpointState::EndpointGathering, Event::ReceiveCallMeMaybeResponse) => {
                self.last_event = Some(event);
                self.state = EndpointState::Ping;
            }

            (EndpointState::Ping, Event::Publish) => {
                self.last_event = Some(event);
                self.state = EndpointState::Published;
            }

            (EndpointState::EndpointGathering, Event::Timeout)
            | (EndpointState::Ping, Event::Timeout) => {
                self.last_event = Some(event);
                self.state = EndpointState::Disconnected;
            }

            (EndpointState::Published, Event::EndpointGone) => {
                self.last_event = Some(event);
                self.state = EndpointState::Disconnected;
            }

            (_, event) => {
                telio_log_warn!("Invalid state transition {:?} -> {:?}", &self.state, event);
            }
        }
    }

    pub fn get(&self) -> &EndpointState {
        &self.state
    }

    pub fn last_event(&self) -> &Option<Event> {
        &self.last_event
    }
}

impl PartialEq<EndpointState> for EndpointStateMachine {
    fn eq(&self, other: &EndpointState) -> bool {
        &self.state == other
    }
}

impl PartialEq<(EndpointState, Option<Event>)> for EndpointStateMachine {
    fn eq(&self, other: &(EndpointState, Option<Event>)) -> bool {
        self.state == other.0 && self.last_event == other.1
    }
}

impl fmt::Display for EndpointStateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.state)
    }
}

#[cfg(test)]
impl EndpointStateMachine {
    pub fn new(state: EndpointState, event: Option<Event>) -> EndpointStateMachine {
        EndpointStateMachine {
            state,
            last_event: event,
        }
    }
}

#[macro_export]
macro_rules! do_state_transition {
    ($ep: expr, $event: expr) => {{
        if $ep.state.get() == &EndpointState::Published || $event == Event::Publish {
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
