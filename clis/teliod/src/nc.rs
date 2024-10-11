use anyhow::ensure;
use reqwest::{Certificate, ClientBuilder, StatusCode, Url};
use rumqttc::{
    AsyncClient, ClientError, ConnAck, ConnectReturnCode, Event, EventLoop, MqttOptions, Packet,
    Publish, QoS, TlsConfiguration, Transport,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Duration};
use telio::telio_utils::{
    exponential_backoff::{
        Backoff, Error as BackoffError, ExponentialBackoff, ExponentialBackoffBounds,
    },
    Hidden,
};
use tokio::{
    select,
    sync::Mutex,
    time::{error::Elapsed, timeout, Instant},
};
use tokio_rustls::rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use self::outgoing::{Acknowledgement, DeliveryConfirmation};

const TOKENS_URL: &'static str = "https://api.nordvpn.com/v1/notifications/tokens";
const USERNAME: &'static str = "token";
const ROUTER_PLATFORM_ID: u64 = 900;
const MQTT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

const TOPIC_SUBSCRIBE: &'static str = "meshnet";
const TOPIC_DELIVERED: &'static str = "delivered";
const TOPIC_ACKNOWLEDGED: &'static str = "ack";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to send http request for token: {0}")]
    TokenHttpError(#[from] reqwest::Error),
    #[error("Failed to get token: {0}")]
    TokenError(String),
    #[error("Malformed notification center json response: {0}")]
    MalformedNotificationCenterJsonResponse(#[from] serde_json::Error),
    #[error("Mqtt broker rejected connection: {0:?}")]
    MqttConnectionRejected(ConnectReturnCode),
    #[error("Unexpected mqtt event before connection established: {0:?}")]
    MqttUnexpectedEventBeforeConnection(Event),
    #[error("Mqtt connection timeout")]
    MqttConnectionTimeout,
    #[error("Mqtt connection error: {0}")]
    MqttConnectionError(rumqttc::ConnectionError),
    #[error(transparent)]
    BackoffBoundsError(#[from] BackoffError),
    #[error(transparent)]
    MqttClientError(#[from] ClientError),
    #[error("Notification Center credentials are missing hostname")]
    CredentialsMissingHostname,
    #[error("Notification Center credentials are missing port number")]
    CredentialsMissingPortNumber,
    #[error("Failed to read http cert file: {0}")]
    FailedToReadHttpCertFile(std::io::Error),
    #[error("Failed to read mqtt cert file: {0}")]
    FailedToReadMqttCertFile(std::io::Error),
    #[error("Failed to parse mqtt pem certificate: {0:?}")]
    FailedToParseMqttCertificate(tokio_rustls::rustls::pki_types::pem::Error),
    #[error("Failed to load native certs: {0:?}")]
    FailedToLoadNativeCerts(Vec<rustls_native_certs::Error>),
}

type Callback = Arc<dyn Fn(&[Uuid]) + Send + Sync>;

pub struct NotificationCenter {
    callbacks: Arc<Mutex<Vec<Callback>>>,
}

struct NCConfig {
    authentication_token: String,
    app_user_uid: Uuid,
    callbacks: Arc<Mutex<Vec<Callback>>>,
    http_certificate_file_path: Option<PathBuf>,
    mqtt_certificate_file_path: Option<PathBuf>,
}

impl NotificationCenter {
    pub async fn new(
        config: &super::TeliodDaemonConfig,
        callbacks: Vec<Callback>,
    ) -> Result<Self, Error> {
        let callbacks = Arc::new(Mutex::new(callbacks));

        let nc_config = NCConfig {
            authentication_token: config.authentication_token.clone(),
            app_user_uid: config.app_user_uid,
            callbacks: callbacks.clone(),

            http_certificate_file_path: config.http_certificate_file_path.clone(),
            mqtt_certificate_file_path: config.mqtt_certificate_file_path.clone(),
        };

        start_mqtt(nc_config).await?;

        Ok(Self { callbacks })
    }

    pub async fn add_callback(&self, callback: Callback) {
        let mut callbacks = self.callbacks.lock().await;
        callbacks.push(callback);
    }
}

async fn start_mqtt(nc_config: NCConfig) -> Result<(), Error> {
    let backoff_bounds = ExponentialBackoffBounds {
        initial: Duration::from_secs(1),
        maximal: Some(Duration::from_secs(300)),
    };
    let backoff = ExponentialBackoff::new(backoff_bounds)?;

    tokio::spawn(async move {
        loop {
            let (client, mut eventloop, expires_at) =
                Box::pin(connect_to_nc_with_backoff(&nc_config, backoff.clone())).await;

            loop {
                select! {
                    _ = tokio::time::sleep_until(expires_at) => {
                        info!("Notification Center credentials expired, mqtt will be restarted");
                        break;
                    },
                    event = eventloop.poll() => {
                        match event {
                            Ok(Event::Incoming(Packet::Publish(p))) => {
                                if let Err(e) = handle_incoming_publish(&client, p, &nc_config.callbacks).await {
                                    error!("Failed to handle incoming publish: {e}");
                                }
                            }
                            Ok(Event::Incoming(p)) => {
                                debug!("mqtt incoming: {p:?}");
                            }
                            Ok(Event::Outgoing(p)) => debug!("mqtt outgoing event: {p:?}"),
                            Err(e) => {
                                error!("mqtt event loop error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

async fn connect_to_nc_with_backoff(
    nc_config: &NCConfig,
    mut backoff: ExponentialBackoff,
) -> (AsyncClient, EventLoop, Instant) {
    loop {
        match connect_to_nc(nc_config).await {
            Ok(mqtt) => return mqtt,
            Err(e) => {
                warn!(
                    "Failed to connect to mqtt: {e}, will wait for {:?} and retry",
                    backoff.get_backoff()
                );
                tokio::time::sleep(backoff.get_backoff()).await;
                backoff.next_backoff();
            }
        }
    }
}

async fn connect_to_nc(nc_config: &NCConfig) -> Result<(AsyncClient, EventLoop, Instant), Error> {
    let credentials = request_nc_credentials(&nc_config).await?;

    let mut mqttoptions = MqttOptions::new(
        nc_config.app_user_uid.to_string(),
        credentials.host()?,
        credentials.port()?,
    );
    mqttoptions.set_credentials(credentials.username.clone(), &*credentials.password);
    mqttoptions.set_keep_alive(Duration::from_secs(30));
    mqttoptions.set_clean_session(true);

    // Use rustls-native-certs to load root certificates from the operating system.
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();

    if let Some(cert_path) = &nc_config.mqtt_certificate_file_path {
        debug!("Using custom mqtt cert file from {cert_path:?}");
        let certs = tokio::fs::read(cert_path)
            .await
            .map_err(Error::FailedToReadMqttCertFile)?;
        let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(&certs).collect();
        root_cert_store
            .add_parsable_certificates(certs.map_err(Error::FailedToParseMqttCertificate)?);
    } else {
        let cert_loading_result = rustls_native_certs::load_native_certs();
        if cert_loading_result.errors.is_empty() {
            root_cert_store.add_parsable_certificates(cert_loading_result.certs);
        } else {
            return Err(Error::FailedToLoadNativeCerts(cert_loading_result.errors));
        }
    }

    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    );

    mqttoptions.set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
        client_config,
    )));

    let (client, eventloop) = AsyncClient::new(mqttoptions, 10);
    let eventloop = Box::pin(wait_for_connection(eventloop, MQTT_CONNECTION_TIMEOUT)).await?;
    let expires_at = Instant::now() + Duration::from_secs(credentials.expires_in);
    client.subscribe(TOPIC_SUBSCRIBE, QoS::AtLeastOnce).await?;

    info!("Notification Center connection established");

    return Ok((client, eventloop, expires_at));
}

async fn handle_incoming_publish(
    client: &AsyncClient,
    p: Publish,
    callbacks: &Arc<Mutex<Vec<Callback>>>,
) -> Result<(), anyhow::Error> {
    let text = std::str::from_utf8(&*p.payload)?;
    let notification: incoming::Notification = serde_json::from_str(&text)?;
    debug!("mqtt incoming publish: {p:?}: {text:?}");

    ensure!(
        !notification.is_acked(),
        "received {:?} which is already acked",
        notification.message_id()
    );

    send_delivery_confirmation(client, notification.message_id()).await?;
    send_acknowledgement(client, notification.message_id()).await?;

    let callbacks: Vec<Callback> = (*callbacks.lock().await).clone();

    callbacks
        .into_iter()
        .for_each(|c| c(&notification.message.data.event.attributes.affected_machines));

    Ok(())
}

async fn send_delivery_confirmation(
    client: &AsyncClient,
    message_id: MessageID,
) -> Result<(), anyhow::Error> {
    let payload = DeliveryConfirmation { message_id };
    let payload = serde_json::to_string(&payload)?;

    client
        .publish_bytes(TOPIC_DELIVERED, QoS::AtLeastOnce, false, payload.into())
        .await?;

    Ok(())
}

async fn send_acknowledgement(
    client: &AsyncClient,
    message_id: MessageID,
) -> Result<(), anyhow::Error> {
    let payload = Acknowledgement {
        message_id,
        track_type: outgoing::TrackType::Processed,
        action_slug: None,
    };

    let payload = serde_json::to_string(&payload)?;

    client
        .publish_bytes(TOPIC_ACKNOWLEDGED, QoS::AtLeastOnce, false, payload.into())
        .await?;

    Ok(())
}

async fn request_nc_credentials(
    nc_config: &NCConfig,
) -> Result<NotificationCenterCredentials, Error> {
    let mut builder = ClientBuilder::new();
    if let Some(cert_path) = &nc_config.http_certificate_file_path {
        debug!("Using custom http cert file from {cert_path:?}");
        let cert = tokio::fs::read(cert_path)
            .await
            .map_err(Error::FailedToReadHttpCertFile)?;
        for cert in Certificate::from_pem_bundle(&cert)? {
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = builder.build()?;

    let data = TokenHttpRequestData {
        app_user_uid: nc_config.app_user_uid.to_string(),
        platform_id: ROUTER_PLATFORM_ID,
    };
    let resp = client
        .post(TOKENS_URL)
        .basic_auth(USERNAME, Some(nc_config.authentication_token.clone()))
        .json(&data)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if status != StatusCode::CREATED {
        return Err(Error::TokenError(text));
    }

    let resp: NotificationCenterCredentials = serde_json::from_str(&text)?;
    Ok(resp)
}

async fn wait_for_connection(mut event_loop: EventLoop, t: Duration) -> Result<EventLoop, Error> {
    match timeout(t, event_loop.poll()).await {
        Ok(Ok(Event::Incoming(Packet::ConnAck(ConnAck { code, .. })))) => {
            if code == ConnectReturnCode::Success {
                Ok(event_loop)
            } else {
                Err(Error::MqttConnectionRejected(code))
            }
        }
        Ok(Ok(unexpected_event)) => {
            Err(Error::MqttUnexpectedEventBeforeConnection(unexpected_event))
        }
        Err(Elapsed { .. }) => Err(Error::MqttConnectionTimeout),
        Ok(Err(err)) => Err(Error::MqttConnectionError(err)),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenHttpRequestData {
    app_user_uid: String,
    platform_id: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct NotificationCenterCredentials {
    endpoint: Url,
    username: String,
    password: Hidden<String>,
    expires_in: u64,
}

impl NotificationCenterCredentials {
    fn host(&self) -> Result<String, Error> {
        match self.endpoint.host_str() {
            Some(host) => Ok(host.to_owned()),
            None => Err(Error::CredentialsMissingHostname),
        }
    }

    fn port(&self) -> Result<u16, Error> {
        match self.endpoint.port() {
            Some(port) => Ok(port),
            None => Err(Error::CredentialsMissingPortNumber),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MessageID(Uuid);

mod incoming {
    use super::*;

    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Notification {
        pub message: Message,
    }

    impl Notification {
        pub fn message_id(&self) -> MessageID {
            self.message.data.metadata.message_id
        }
        pub fn is_acked(&self) -> bool {
            self.message.data.metadata.acked
        }
    }

    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Message {
        pub data: Data,
    }

    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Data {
        pub event: Event,
        pub metadata: Metadata,
    }

    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Metadata {
        pub acked: bool,
        pub created_at: u64,
        pub message_id: MessageID,
        pub target_uid: String,
    }

    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Event {
        #[serde(rename = "type")]
        pub type_: String,
        pub attributes: Attributes,
    }

    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct Attributes {
        pub affected_machines: Vec<Uuid>,
    }
}

mod outgoing {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub enum TrackType {
        Opened,
        Clicked,
        Cleared,
        Disabled,
        Processed,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DeliveryConfirmation {
        pub message_id: MessageID,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Acknowledgement {
        pub message_id: MessageID,
        pub track_type: TrackType,
        pub action_slug: Option<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_response() {
        let input = r#"
{
    "endpoint": "tcp://example.com:1883",
    "username": "A790124142",
    "password": "foo-bar-baz",
    "expires_in": 86400
}
        "#;

        let expected = NotificationCenterCredentials {
            endpoint: Url::parse("tcp://example.com:1883").unwrap(),
            username: "A790124142".to_owned(),
            password: Hidden("foo-bar-baz".to_owned()),
            expires_in: 86400,
        };

        let credentials: NotificationCenterCredentials = serde_json::from_str(&input).unwrap();
        assert_eq!(expected, credentials);
    }

    #[test]
    fn parse_notification() {
        let input = r#"
{
  "message": {
    "data": {
      "event": {
        "type": "meshnet_network_update",
        "attributes": {
          "affected_machines": [
            "8d8469c9-f06b-42d4-a7dc-9444566c374b",
            "264081b1-b06d-40b8-a237-0283766c002e",
            "49b655cb-c6a7-4d02-a8dd-70e8540a2c10",
            "1ada0209-76b3-4173-b94d-de6c9c4a5e9a",
            "f41e43ef-5295-4fb2-a033-4fc6f90ed74c"
          ]
        }
      },
      "metadata": {
        "acked": false,
        "created_at": 1728637984,
        "message_id": "99289a53-ed53-4b0a-9012-63df9539b16c",
        "target_uid": "ecd92ba8-14a2-4ec6-aead-c49364251407"
      }
    },
    "notification": null
  }
}
        "#;
        use incoming::*;
        let expected = Notification {
            message: Message {
                data: Data {
                    event: Event {
                        type_: "meshnet_network_update".to_owned(),
                        attributes: Attributes {
                            affected_machines: vec![
                                Uuid::parse_str("8d8469c9-f06b-42d4-a7dc-9444566c374b").unwrap(),
                                Uuid::parse_str("264081b1-b06d-40b8-a237-0283766c002e").unwrap(),
                                Uuid::parse_str("49b655cb-c6a7-4d02-a8dd-70e8540a2c10").unwrap(),
                                Uuid::parse_str("1ada0209-76b3-4173-b94d-de6c9c4a5e9a").unwrap(),
                                Uuid::parse_str("f41e43ef-5295-4fb2-a033-4fc6f90ed74c").unwrap(),
                            ],
                        },
                    },
                    metadata: Metadata {
                        acked: false,
                        created_at: 1728637984,
                        message_id: MessageID(
                            Uuid::parse_str("99289a53-ed53-4b0a-9012-63df9539b16c").unwrap(),
                        ),
                        target_uid: "ecd92ba8-14a2-4ec6-aead-c49364251407".to_owned(),
                    },
                },
            },
        };
        let notification: Notification = serde_json::from_str(&input).unwrap();
        assert_eq!(expected, notification);
    }
}
