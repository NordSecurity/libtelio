use std::sync::Arc;

use async_trait::async_trait;
use telio_crypto::{PublicKey, SecretKey};
use telio_lana::*;
use telio_model::{config::Server, event::Event};
use telio_proto::HeartbeatMessage;
use telio_relay::{multiplexer::Multiplexer, DerpRelay};
use telio_task::{
    io::{chan, mc_chan, Chan, McChan},
    task_exec, Runtime, RuntimeExt, Task, WaitResponse,
};
use telio_utils::{telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn};
use telio_wg::uapi::AnalyticsEvent;
use uuid::Uuid;

use crate::data::{AnalyticsMessage, HeartbeatInfo};
use crate::error::Error;
use crate::{config::Config, data::MeshConfigUpdateEvent};

use crate::heartbeat::Analytics as HeartbeatAnalytics;
use crate::heartbeat::Io as HeartbeatIo;

use crate::qos::Analytics as QoSAnalytics;
use crate::qos::Io as QoSIo;
use crate::qos::OutputData as QoSData;

/// Input/output channels for Nurse
pub struct NurseIo<'a> {
    /// Event channel to gather derp events
    pub derp_event_channel: &'a mc_chan::Tx<Box<Server>>,
    /// Event channel to gather wg events
    pub wg_event_channel: &'a mc_chan::Tx<Box<Event>>,
    /// Relay multiplexer to be able to communicate with other nodes
    pub relay_multiplexer: &'a Multiplexer,
    /// Event channel to gather wg data
    pub wg_analytics_channel: Option<mc_chan::Tx<Box<AnalyticsEvent>>>,
    /// Event channel to gather meshnet config update
    pub config_update_channel: Option<mc_chan::Tx<Box<MeshConfigUpdateEvent>>>,
    /// Event channel to manual trigger a collection
    pub collection_trigger_channel: Option<mc_chan::Tx<Box<()>>>,
}

/// Nurse entity
pub struct Nurse {
    task: Task<State>,
}

impl Nurse {
    /// Nurse's constructor
    pub async fn start_with(
        public_key: PublicKey,
        derp: Arc<DerpRelay>,
        config: Config,
        io: NurseIo<'_>,
    ) -> Self {
        Self {
            task: Task::start(State::new(public_key, derp, config, io).await),
        }
    }

    /// Update private key
    pub async fn set_private_key(&self, private_key: SecretKey) {
        let _ = task_exec!(&self.task, async move |state| {
            state.set_private_key(private_key).await;
            Ok(())
        })
        .await;
    }

    /// Stop nurse
    pub async fn stop(self) {
        let _ = self.task.stop().await.resume_unwind();
    }
}

/// Nurse struct, combines meshnet health data from different sources
/// --
/// State contains:
/// * Analytics channel
/// * Heartbeat component
/// * QoS component
pub struct State {
    analytics_channel: chan::Rx<AnalyticsMessage>,
    heartbeat: Task<HeartbeatAnalytics>,
    qos: Option<Task<QoSAnalytics>>,
}

impl State {
    /// Start Nurse
    ///
    /// # Arguments
    ///
    /// * `public_key` - Used for heartbeat requests.
    /// * `config` - Contains configuration for heartbeats and QoS.
    /// * `io` - Nurse io channels.
    ///
    /// # Returns
    ///
    /// A Nurse instance.
    pub async fn new(
        public_key: PublicKey,
        derp: Arc<DerpRelay>,
        config: Config,
        io: NurseIo<'_>,
    ) -> Self {
        let meshnet_id = Self::meshnet_id();

        // Analytics channel
        let analytics_channel = Chan::default();

        // If Nurse start is called config_update_channel exists for sure
        let config_update_channel = io
            .config_update_channel
            .unwrap_or_else(|| McChan::default().tx);
        let collection_trigger_channel = io
            .collection_trigger_channel
            .unwrap_or_else(|| McChan::default().tx);

        // Heartbeat component
        let heartbeat_io = HeartbeatIo {
            chan: io
                .relay_multiplexer
                .get_channel::<HeartbeatMessage>()
                .await
                .unwrap_or_default(),
            derp_event_channel: io.derp_event_channel.subscribe(),
            wg_event_channel: io.wg_event_channel.subscribe(),
            config_update_channel: config_update_channel.subscribe(),
            analytics_channel: analytics_channel.tx.clone(),
            collection_trigger_channel: collection_trigger_channel.subscribe(),
        };

        let heartbeat = HeartbeatAnalytics::new(
            public_key,
            meshnet_id,
            config.heartbeat_config,
            heartbeat_io,
            derp,
        );

        // Qos component
        let qos = if let Some(qos_config) = config.qos_config {
            let wg_channel = io
                .wg_analytics_channel
                .unwrap_or_else(|| McChan::default().tx)
                .subscribe();

            Some(Task::start(QoSAnalytics::new(
                qos_config,
                QoSIo { wg_channel },
            )))
        } else {
            None
        };

        State {
            analytics_channel: analytics_channel.rx,
            heartbeat: Task::start(heartbeat),
            qos,
        }
    }

    /// Inform Nurse of the private key changing.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The new private key to use.
    pub async fn set_private_key(&self, private_key: SecretKey) {
        let _ = task_exec!(&self.heartbeat, async move |state| {
            state.cached_private_key = Some(private_key);
            state.update_public_key().await;
            telio_log_debug!("Updated private key");

            Ok(())
        })
        .await;
    }

    async fn handle_heartbeat_event(&self, info: HeartbeatInfo) {
        // Re-parse the foreign tracker before sending an event, in case it has changed since last time
        init_context_info();

        // Send off nominated fingerprint to moose
        let _ = lana!(
            set_context_application_config_currentState_internalMeshnet_fp,
            info.meshnet_id.to_string()
        );

        // We pray that nothing goes wrong here
        let _ = lana!(
            set_context_application_config_currentState_internalMeshnet_members,
            info.fingerprints
        );

        // And send this off to moose
        let _ = lana!(
            set_context_application_config_currentState_internalMeshnet_connectivityMatrix,
            info.connectivity_matrix
        );

        let _ = lana!(
            set_context_application_config_currentState_externalLinks,
            info.external_links
        );

        let _ = lana!(
            set_context_application_config_currentState_internalMeshnet_fpNat,
            info.nat_type
        );

        let _ = lana!(
            set_context_application_config_currentState_internalMeshnet_membersNat,
            info.peer_nat_types.join(",")
        );

        // TODO: Make it better
        let internal_sorted_public_keys = info.internal_sorted_public_keys;
        let external_sorted_public_keys = info.external_sorted_public_keys;
        let (internal_qos_data, external_qos_data) = if let Some(qos) = self.qos.as_ref() {
            task_exec!(qos, async move |state| {
                let result = (
                    state.get_data(&internal_sorted_public_keys),
                    state.get_data(&external_sorted_public_keys),
                );
                state.reset_cached_data();
                Ok(result)
            })
            .await
            .unwrap_or_default()
        } else {
            (QoSData::default(), QoSData::default())
        };

        let qos_data = QoSData::merge(internal_qos_data, external_qos_data);

        let _ = lana!(
            send_serviceQuality_node_heartbeat,
            qos_data.connection_duration,
            info.heartbeat_interval,
            qos_data.rx,
            qos_data.rtt,
            qos_data.tx
        );
    }

    fn meshnet_id() -> Uuid {
        lana!(fetch_context)
            .map(|context| context.application.config.current_state.internal_meshnet.fp)
            .unwrap_or(None)
            .map(|fp| {
                Uuid::parse_str(&fp).unwrap_or_else(|_| {
                    telio_log_error!(
                        "Failed to parse moose meshnet id ({:?}), generating a new one",
                        fp
                    );
                    Uuid::new_v4()
                })
            })
            .unwrap_or_else(|| {
                telio_log_trace!(
                    "Could not find stored meshnet id by moose, generating a fresh one"
                );
                Uuid::new_v4()
            })
    }
}

#[async_trait]
impl Runtime for State {
    const NAME: &'static str = "Nurse";

    type Err = Error;

    async fn wait(&mut self) -> WaitResponse<'_, Self::Err> {
        if let Some(event) = self.analytics_channel.recv().await {
            Self::guard(async move {
                match event {
                    AnalyticsMessage::Heartbeat { heartbeat_info } => {
                        self.handle_heartbeat_event(heartbeat_info).await
                    }
                }
                Ok(())
            })
        } else {
            Self::error(Error::Stopped)
        }
    }

    /// Stop Nurse
    async fn stop(self) {
        telio_log_trace!("Stopping Nurse...");
        let _ = self.heartbeat.stop().await;
        if let Some(qos) = self.qos {
            let _ = qos.stop().await;
        }
    }
}
