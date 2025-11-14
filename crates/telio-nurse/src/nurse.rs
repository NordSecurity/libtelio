use std::collections::HashSet;

use async_trait::async_trait;
use std::sync::Arc;
use telio_crypto::{PublicKey, SecretKey};
use telio_lana::*;
use telio_model::event::Event;
use telio_sockets::SocketPool;
use telio_task::{
    io::{chan, mc_chan, Chan, McChan},
    task_exec, ExecError, Runtime, RuntimeExt, Task, WaitResponse,
};
use telio_utils::{
    telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
};
use telio_wg::uapi::AnalyticsEvent;
use tokio::task::spawn_blocking;
use uuid::Uuid;

#[mockall_double::double]
use crate::aggregator::ConnectivityDataAggregator;

use crate::error::Error;
use crate::{config::Config, data::MeshConfigUpdateEvent};
use crate::{
    data::{AnalyticsMessage, HeartbeatInfo},
    heartbeat::MeshnetEntities,
};

use crate::heartbeat::Analytics as HeartbeatAnalytics;
use crate::heartbeat::Io as HeartbeatIo;

use crate::qos::Analytics as QoSAnalytics;
use crate::qos::Io as QoSIo;
use crate::qos::OutputData as QoSData;

/// Input/output channels for Nurse
pub struct NurseIo<'a> {
    /// Event channel to gather wg events
    pub wg_event_channel: &'a mc_chan::Tx<Box<Event>>,
    /// Event channel to gather wg data
    pub wg_analytics_channel: Option<mc_chan::Tx<Box<AnalyticsEvent>>>,
    /// Event channel to gather meshnet config update
    pub config_update_channel: Option<mc_chan::Tx<Box<MeshConfigUpdateEvent>>>,
    /// Event channel to manual trigger a collection
    pub collection_trigger_channel: Option<mc_chan::Tx<()>>,
    /// Event channel to manual trigger a qos
    pub qos_trigger_channel: Option<mc_chan::Tx<()>>,
}

/// Nurse entity
pub struct Nurse {
    task: Task<State>,
}

impl Nurse {
    /// Nurse's constructor
    pub async fn start_with(
        public_key: PublicKey,
        config: Config,
        io: NurseIo<'_>,
        aggregator: Arc<ConnectivityDataAggregator>,
        ipv6_enabled: bool,
        socket_pool: Arc<SocketPool>,
    ) -> Self {
        Self {
            task: Task::start(
                State::new(
                    public_key,
                    config,
                    io,
                    aggregator,
                    ipv6_enabled,
                    socket_pool,
                )
                .await,
            ),
        }
    }

    /// Run when you change meshnet configuration
    pub async fn configure_meshnet(&self, meshnet_entities: Option<MeshnetEntities>) {
        let _ = task_exec!(&self.task, async move |state| {
            state.configure_meshnet(meshnet_entities).await;
            Ok(())
        })
        .await;
    }

    /// Update private key
    pub async fn set_private_key(&self, private_key: SecretKey) {
        let _ = task_exec!(&self.task, async move |state| {
            state.set_private_key(private_key).await;
            Ok(())
        })
        .await;
    }

    /// Send disconnect data
    pub async fn send_disconnect_data(&self) {
        let _ = task_exec!(&self.task, async move |state| {
            state.send_disconnect_data().await;
            Ok(())
        })
        .await;
    }

    /// Stop nurse
    pub async fn stop(self) {
        self.send_disconnect_data().await;
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
    /// * `aggregator` - ConnectivityDataAggregator.
    /// * `ipv6_enabled` - IPv6 support.
    /// * `socket_pool` - SocketPool used to protect the sockets.
    ///
    /// # Returns
    ///
    /// A Nurse instance.
    pub async fn new(
        public_key: PublicKey,
        config: Config,
        io: NurseIo<'_>,
        aggregator: Arc<ConnectivityDataAggregator>,
        ipv6_enabled: bool,
        socket_pool: Arc<SocketPool>,
    ) -> Self {
        // Analytics channel
        let analytics_channel = Chan::default();

        // If Nurse start is called config_update_channel exists for sure
        let config_update_channel = io
            .config_update_channel
            .unwrap_or_else(|| McChan::default().tx);
        let collection_trigger_channel = io
            .collection_trigger_channel
            .unwrap_or_else(|| McChan::default().tx);
        let qos_trigger_channel = io
            .qos_trigger_channel
            .unwrap_or_else(|| McChan::default().tx);

        // Heartbeat component
        let heartbeat_io = HeartbeatIo {
            chan: None,
            wg_event_channel: io.wg_event_channel.subscribe(),
            config_update_channel: config_update_channel.subscribe(),
            analytics_channel: analytics_channel.tx.clone(),
            collection_trigger_channel: collection_trigger_channel.subscribe(),
        };

        let heartbeat = HeartbeatAnalytics::new(
            public_key,
            None,
            config.heartbeat_config,
            heartbeat_io,
            aggregator,
        );

        // Qos component
        let qos = if let Some(qos_config) = config.qos_config {
            let wg_channel = io
                .wg_analytics_channel
                .unwrap_or_else(|| McChan::default().tx)
                .subscribe();

            Some(Task::start(QoSAnalytics::new(
                qos_config,
                QoSIo {
                    wg_channel,
                    manual_trigger_channel: qos_trigger_channel.subscribe(),
                    config_update_channel: config_update_channel.subscribe(),
                },
                ipv6_enabled,
                socket_pool,
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

    /// Inform Nurse that Meshnet started or stopped.
    ///
    /// # Arguments
    ///
    /// * `meshnet_entities` - meshnet entities if meshnet started, None if it stopped.
    pub async fn configure_meshnet(&self, meshnet_entities: Option<MeshnetEntities>) {
        let _ = task_exec!(&self.heartbeat, async move |state| {
            state.configure_meshnet(meshnet_entities).await;

            telio_log_debug!("Updated meshnet config");

            Ok(())
        })
        .await;
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

    async fn handle_service_quality_event(&self, info: &HeartbeatInfo, disconnect: bool) {
        let internal_sorted_public_keys = info.internal_sorted_public_keys.clone();
        let external_sorted_public_keys = info.external_sorted_public_keys.clone();
        let (internal_qos_data, external_qos_data) = if let Some(qos) = self.qos.as_ref() {
            task_exec!(qos, async move |state| {
                let result = (
                    state.get_data(&internal_sorted_public_keys),
                    state.get_data(&external_sorted_public_keys),
                );
                let every_node_in_config: HashSet<PublicKey> = internal_sorted_public_keys
                    .into_iter()
                    .chain(external_sorted_public_keys.into_iter())
                    .collect();

                state.clean_nodes_list(&every_node_in_config);
                state.reset_cached_data();

                Ok(result)
            })
            .await
            .unwrap_or_default()
        } else {
            (QoSData::default(), QoSData::default())
        };

        telio_log_info!(
            "Attempting to send moose {} event ...",
            if disconnect {
                "disconnect"
            } else {
                "heartbeat"
            },
        );

        let qos_data = QoSData::merge(internal_qos_data, external_qos_data);

        let r = if disconnect {
            lana!(
                send_serviceQuality_node_disconnect,
                qos_data.connection_duration,
                qos_data.rtt,
                qos_data.rtt_loss,
                qos_data.rtt6,
                qos_data.rtt6_loss,
                qos_data.tx,
                qos_data.rx,
                info.heartbeat_interval,
                0, // TODO Derp Connection Duration
                info.nat_traversal_conn_info.clone(),
                info.derp_conn_info.clone(),
                None
            )
        } else {
            lana!(
                send_serviceQuality_node_heartbeat,
                qos_data.connection_duration,
                qos_data.rtt,
                qos_data.rtt_loss,
                qos_data.rtt6,
                qos_data.rtt6_loss,
                qos_data.tx,
                qos_data.rx,
                info.heartbeat_interval,
                0, // TODO Derp Connection Duration
                info.nat_traversal_conn_info.clone(),
                info.derp_conn_info.clone(),
                None
            )
        };

        telio_log_info!(
            "Moose {} event result: {:?}",
            if disconnect {
                "disconnect"
            } else {
                "heartbeat"
            },
            r
        );
    }

    async fn handle_heartbeat_event(&self, info: HeartbeatInfo) {
        let _ = lana!(
            set_context_application_libtelioapp_config_currentState_meshnetEnabled,
            info.meshnet_enabled
        );

        // Send off nominated fingerprint to moose
        let _ = lana!(
            set_context_application_libtelioapp_config_currentState_internalMeshnet_fp,
            info.meshnet_id.to_string()
        );

        // We pray that nothing goes wrong here
        let _ = lana!(
            set_context_application_libtelioapp_config_currentState_internalMeshnet_members,
            info.fingerprints.clone()
        );

        // And send this off to moose
        let _ = lana!(
            set_context_application_libtelioapp_config_currentState_internalMeshnet_connectivityMatrix,
            info.connectivity_matrix.clone()
        );

        let _ = lana!(
            set_context_application_libtelioapp_config_currentState_externalLinks,
            info.external_links.clone()
        );

        let _ = lana!(
            set_context_application_libtelioapp_config_currentState_internalMeshnet_fpNat,
            info.nat_type.clone()
        );

        let _ = lana!(
            set_context_application_libtelioapp_config_currentState_internalMeshnet_membersNat,
            info.peer_nat_types.join(",")
        );

        self.handle_service_quality_event(&info, false).await;

        let _ = spawn_blocking(move || {
            telio_log_info!("Attempting to flush moose changes");
            let r = lana!(flush_changes);
            telio_log_info!("Flushing moose changes result: {:?}", r);
        })
        .await;
    }

    pub fn meshnet_id() -> Uuid {
        telio_lana::fetch_context_string(String::from(
            "application.libtelioapp.config.current_state.internal_meshnet.fp",
        ))
        .map(|fp| {
            Uuid::parse_str(&fp).unwrap_or_else(|e| {
                telio_log_error!(
                    "Failed to parse moose meshnet id ({:?}), generating a new one: {e}",
                    fp
                );
                Uuid::new_v4()
            })
        })
        .unwrap_or_else(|| {
            telio_log_info!("Could not find stored meshnet id by moose, generating a fresh one");
            Uuid::new_v4()
        })
    }

    async fn send_disconnect_data(&self) {
        if let Ok(Ok(hb_info)) = task_exec!(&self.heartbeat, async move |state| {
            Ok(state.get_disconnect_data().await.map_err(|_| ExecError))
        })
        .await
        {
            self.handle_service_quality_event(&hb_info, true).await;
            let r = lana!(flush_changes);
            telio_log_info!("Flushing moose changes result: {:?}", r);
        }
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
