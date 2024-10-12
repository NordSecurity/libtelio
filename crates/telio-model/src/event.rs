//! Event reporting module

use super::mesh::Node;
use modifier::Modifier;
use serde::Serialize;

use crate::config::Server as Relay;

pub use modifier::Set;

/// Macro used to report events
/// # Arguments
/// 1) Channel to report the event into (for eg. Tx, Sender)
/// 2) Event to be reported
#[macro_export]
macro_rules! report_event {
    ($s:expr, $e:expr) => {
        if $s.send(Box::new($e)).is_err() {
            return;
        }
    };
}

/// Error levels. Used for app to decide what to do with `telio` device when error happens.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorLevel {
    /// The error level is critical (highest priority)
    #[default]
    Critical = 1,
    /// The error level is severe
    Severe = 2,
    /// The error is a warning
    Warning = 3,
    /// The error is of the lowest priority
    Notice = 4,
}

/// Error code. Common error code representation (for statistics).
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorCode {
    /// There is no error in the execution
    #[default]
    NoError = 0,
    /// The error type is unknown
    Unknown = 1,
}

/// Custom message for event (for log or present-to-user purposes).
pub type EventMsg = String;

/// Error event. Used to inform the upper layer about errors in `libtelio`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Error {
    /// The level of the error
    pub level: ErrorLevel,
    /// The error code, used to denote the type of the error
    pub code: ErrorCode,
    /// A more descriptive text of the error
    pub msg: EventMsg,
}

/// Used for the constructing `Event` object.
/// Adding another `Event` type, that type should implement this trait,
/// for the ability to be constructed, but not used outside of this module.
pub trait MakeEvent {
    /// Method signature to construct 'Event' objects
    fn make() -> EventBuilder;
}

impl MakeEvent for Relay {
    fn make() -> EventBuilder {
        EventBuilder::Relay { body: None }
    }
}

impl MakeEvent for Error {
    fn make() -> EventBuilder {
        EventBuilder::Error { body: None }
    }
}

impl MakeEvent for Node {
    fn make() -> EventBuilder {
        EventBuilder::Node { body: None }
    }
}

/// Main object of `Event`. See `Event::new()` for init options.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum Event {
    /// Used to report events related to the Relay
    Relay {
        /// Relay type event
        body: Relay,
    },
    /// Used to report events related to the Node
    Node {
        /// Node type event
        body: Node,
    },
    /// Initialize an Error type event.
    /// Used to inform errors to the upper layers of libtelio
    Error {
        /// Error type event
        body: Error,
    },
}

impl Event {
    /// Returns an event object. Use `modifier` for initiating all necessary fields.
    ///
    /// # Arguments
    ///
    /// * `T` - Event type
    ///
    /// # Examples
    ///
    /// ```
    /// use telio_model::event::*;
    ///
    /// let err_event = Event::builder::<Error>()
    ///     .set(EventMsg::from("Naughty error ..."))
    ///     .set(ErrorCode::Unknown)
    ///     .set(ErrorLevel::Severe)
    ///     .build();
    ///
    /// // let conn_event = Event::new::<RelayConn>().set(<some_relay_server_object>);
    ///
    /// // let node_event = Event::new::<Node>().set(<some_node_object>);
    /// ```
    pub fn builder<T: MakeEvent>() -> EventBuilder {
        T::make()
    }

    /// Converts event object to json string
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

#[allow(missing_docs)]
pub enum EventBuilder {
    Relay { body: Option<Relay> },
    Node { body: Option<Node> },
    Error { body: Option<Error> },
}

impl EventBuilder {
    /// Builds an event from the builder
    /// Only returns an event if the body of the builder is not None, or None otherwise
    pub fn build(self) -> Option<Event> {
        match self {
            EventBuilder::Relay { body: Some(body) } => Some(Event::Relay { body }),
            EventBuilder::Node { body: Some(body) } => Some(Event::Node { body }),
            EventBuilder::Error { body: Some(body) } => Some(Event::Error { body }),
            _ => None,
        }
    }
}

impl Modifier<EventBuilder> for Relay {
    fn modify(self, res: &mut EventBuilder) {
        if let EventBuilder::Relay { body } = res {
            *body = Some(self);
        }
    }
}

impl Modifier<EventBuilder> for Node {
    fn modify(self, res: &mut EventBuilder) {
        if let EventBuilder::Node { body } = res {
            *body = Some(self);
        }
    }
}

impl Modifier<EventBuilder> for ErrorLevel {
    fn modify(self, res: &mut EventBuilder) {
        if let EventBuilder::Error { body } = res {
            if body.is_none() {
                *body = Some(Error::default());
            }

            body.as_mut().map(|b| {
                b.level = self;
                b
            });
        }
    }
}

impl Modifier<EventBuilder> for ErrorCode {
    fn modify(self, res: &mut EventBuilder) {
        if let EventBuilder::Error { body } = res {
            if body.is_none() {
                *body = Some(Error::default());
            }

            body.as_mut().map(|b| {
                b.code = self;
                b
            });
        }
    }
}

impl Modifier<EventBuilder> for EventMsg {
    fn modify(self, res: &mut EventBuilder) {
        // Not nice, but cannot implement the other way
        if let EventBuilder::Error { body } = res {
            if body.is_none() {
                *body = Some(Error::default());
            }

            body.as_mut().map(|b| {
                b.msg = self;
                b
            });
        }
    }
}

impl Set for EventBuilder {}

#[cfg(test)]
mod tests {
    use crate::config::{RelayState, Server};

    use super::super::mesh::*;
    use super::Error as EventError;
    use super::*;
    use telio_crypto::{PublicKey, KEY_SIZE};

    #[test]
    fn validate_to_json() {
        let node = Node {
            identifier: "f2b18d10-82ed-49a3-8b50-3356685ec5fa".to_owned(),
            public_key: PublicKey([1_u8; KEY_SIZE]),
            nickname: Some(String::from("alpha")),
            state: NodeState::Connected,
            link_state: Some(LinkState::Up),
            is_exit: true,
            is_vpn: true,
            ip_addresses: Vec::from(["127.0.0.1".parse().unwrap()]),
            allowed_ips: Vec::from(["127.0.0.1/32".parse().unwrap()]),
            endpoint: Some(SocketAddr::new("127.0.0.1".parse().unwrap(), 8080)),
            hostname: Some(String::from("example.com")),
            allow_incoming_connections: false,
            allow_peer_traffic_routing: false,
            allow_peer_local_network_access: false,
            allow_peer_send_files: false,
            path: crate::features::PathType::Relay,
            allow_multicast: false,
            peer_allows_multicast: false,
        };

        let server = Server {
            region_code: "nl".to_string(),
            name: "Natlab #0001".to_string(),
            hostname: "derp-01".to_string(),
            ipv4: Ipv4Addr::new(10, 0, 10, 1),
            relay_port: 8765,
            stun_port: 3479,
            stun_plaintext_port: 3478,
            public_key: "SPB77H13eXlOdWc+PGrX6oAQfCvz2me1fvAB0lrxN0Y="
                .parse()
                .unwrap(),
            weight: 1,
            conn_state: RelayState::Connecting,
            use_plain_text: true,
        };

        let err_json = String::from(
            r#"{"type":"error","body":{"level":"severe","code":"unknown","msg":"big_error"}}"#,
        );
        let conn_json = String::from(concat!(
            r#"{"type":"relay","#,
            r#""body":"#,
            r#"{"region_code":"nl","#,
            r#""name":"Natlab #0001","#,
            r#""hostname":"derp-01","#,
            r#""ipv4":"10.0.10.1","#,
            r#""relay_port":8765,"#,
            r#""stun_port":3479,"#,
            r#""stun_plaintext_port":3478,"#,
            r#""public_key":"SPB77H13eXlOdWc+PGrX6oAQfCvz2me1fvAB0lrxN0Y=","#,
            r#""weight":1,"#,
            r#""use_plain_text":true,"#,
            r#""conn_state":"connecting""#,
            r#"}}"#
        ));

        let node_json = String::from(concat!(
            r#"{"type":"node","#,
            r#""body":"#,
            r#"{"identifier":"f2b18d10-82ed-49a3-8b50-3356685ec5fa","#,
            r#""public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","nickname":"alpha","state":"connected","link_state":"up","#,
            r#""is_exit":true,"is_vpn":true,"ip_addresses":["127.0.0.1"],"allowed_ips":["127.0.0.1/32"],"#,
            r#""endpoint":"127.0.0.1:8080","hostname":"example.com","#,
            r#""allow_incoming_connections":false,"#,
            r#""allow_peer_traffic_routing":false,"#,
            r#""allow_peer_local_network_access":false,"#,
            r#""allow_peer_send_files":false,"#,
            r#""path":"relay","#,
            r#""allow_multicast":false,"#,
            r#""peer_allows_multicast":false"#,
            r#"}}"#
        ));

        let err_event = Event::builder::<EventError>()
            .set(EventMsg::from("big_error"))
            .set(ErrorCode::Unknown)
            .set(ErrorLevel::Severe)
            .build()
            .unwrap();

        let conn_event = Event::builder::<Relay>().set(server).build().unwrap();

        let node_event = Event::builder::<Node>().set(node).build().unwrap();

        assert_eq!(err_json, err_event.to_json().unwrap());
        assert_eq!(conn_json, conn_event.to_json().unwrap());
        assert_eq!(node_json, node_event.to_json().unwrap());
    }
}
