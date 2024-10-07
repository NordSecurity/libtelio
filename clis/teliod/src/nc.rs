use anyhow::ensure;
use reqwest::{Client, StatusCode, Url};
use rumqttc::{
    AsyncClient, ConnAck, ConnectReturnCode, Event, EventLoop, Incoming, MqttOptions, Packet,
    Publish, QoS, TlsConfiguration, Transport,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use telio::telio_utils::Hidden;
use tokio::{
    select,
    sync::Mutex,
    time::{error::Elapsed, timeout, Instant},
};
use tokio_rustls::rustls::ClientConfig;
use tracing::{debug, error, info};
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
    #[error("Failed to get send http request for token: {0}")]
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
}

type Callback = Arc<dyn Fn(&[Uuid]) + Send + Sync>;

pub struct NotificationCenter {
    callbacks: Arc<Mutex<Vec<Callback>>>,
}

impl NotificationCenter {
    pub async fn new(
        authentication_token: &str,
        app_user_uid: Uuid,
        callbacks: Vec<Callback>,
    ) -> Result<Self, Error> {
        let callbacks = Arc::new(Mutex::new(callbacks));
        let nc_config = request_nc_config(authentication_token, app_user_uid).await?;

        dbg!(&nc_config);

        start_mqtt(nc_config, app_user_uid, callbacks.clone()).await?;

        Ok(Self { callbacks })
    }

    pub async fn add_callback(&self, callback: Callback) {
        let mut callbacks = self.callbacks.lock().await;
        callbacks.push(callback);
    }
}

async fn start_mqtt(
    nc_config: NotificationCenterConfig,
    app_user_uid: Uuid,
    callbacks: Arc<Mutex<Vec<Callback>>>,
) -> Result<(), Error> {
    let (client, mut eventloop, expires_at) = connect_to_mqtt(nc_config, app_user_uid).await?;

    client
        .subscribe(TOPIC_SUBSCRIBE, QoS::AtLeastOnce)
        .await
        .unwrap();

    tokio::spawn(async move {
        loop {
            select! {
                _ = tokio::time::sleep_until(expires_at) => {

                },
                event = eventloop.poll() => {
                    match event {
                        Ok(Event::Incoming(Packet::Publish(p))) => {
                            if let Err(e) = handle_incoming_publish(&client, p, &callbacks).await {
                                error!("Failed to handle incomming publish: {e}");
                            }
                        }
                        Ok(Event::Incoming(p)) => {
                            info!("mqtt incomming: {p:?}");
                        }
                        Ok(Event::Outgoing(p)) => info!("mqtt outgoing: {p:?}"),
                        Err(e) => {
                            error!("mqtt event loop error: {e}");
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

async fn connect_to_mqtt(
    nc_config: NotificationCenterConfig,
    app_user_uid: Uuid,
) -> Result<(AsyncClient, EventLoop, Instant), Error> {
    let mut mqttoptions = MqttOptions::new(
        app_user_uid.to_string(),
        nc_config.endpoint.host().unwrap().to_string(),
        nc_config.endpoint.port().unwrap(),
    );
    mqttoptions.set_credentials(nc_config.username.clone(), &*nc_config.password);
    mqttoptions.set_keep_alive(Duration::from_secs(30));
    mqttoptions.set_clean_session(true);

    // Use rustls-native-certs to load root certificates from the operating system.
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
    root_cert_store.add_parsable_certificates(
        rustls_native_certs::load_native_certs().expect("could not load platform certs"),
    );

    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    );

    mqttoptions.set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
        client_config,
    )));

    let (client, eventloop) = AsyncClient::new(mqttoptions, 10);
    let eventloop = wait_for_connection(eventloop, MQTT_CONNECTION_TIMEOUT).await?;
    info!("Mqtt connection established");
    let start = Instant::now();
    let expires_in = Duration::from_secs(nc_config.expires_in);
    let expires_at = start + expires_in;
    Ok((client, eventloop, expires_at))
}

async fn handle_incoming_publish(
    client: &AsyncClient,
    p: Publish,
    callbacks: &Arc<Mutex<Vec<Callback>>>,
) -> Result<(), anyhow::Error> {
    let text = std::str::from_utf8(&*p.payload)?;
    let notification: incoming::Notification = serde_json::from_str(&text)?;
    debug!("mqtt incomming publish: {p:?}: {text:?}");

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

async fn request_nc_config(
    authentication_token: &str,
    app_user_uid: Uuid,
) -> Result<NotificationCenterConfig, Error> {
    let client = Client::new();

    let data = TokenHttpRequestData {
        app_user_uid: app_user_uid.to_string(),
        platform_id: ROUTER_PLATFORM_ID,
    };
    let resp = client
        .post(TOKENS_URL)
        .basic_auth(USERNAME, Some(authentication_token))
        .json(&data)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if status != StatusCode::CREATED {
        return Err(Error::TokenError(text));
    }

    let resp: NotificationCenterConfig = serde_json::from_str(&text)?;
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

#[derive(Debug, Serialize, Deserialize)]
struct NotificationCenterConfig {
    endpoint: Url,
    username: String,
    password: Hidden<String>,
    expires_in: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MessageID(Uuid);

mod incoming {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
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

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Message {
        pub data: Data,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Data {
        pub event: Event,
        metadata: Metadata,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Metadata {
        acked: bool,
        created_at: u64,
        message_id: MessageID,
        target_uid: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Event {
        #[serde(rename = "type")]
        type_: String,
        pub attributes: Attributes,
    }

    #[derive(Debug, Serialize, Deserialize)]
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
