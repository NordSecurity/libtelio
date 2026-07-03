use std::sync::Arc;

use parking_lot::Mutex;
use telio_model::features::{FeatureDerp, FeatureLana, FeatureValidateKeys, Features};

pub struct FeaturesDefaultsBuilder {
    config: Mutex<Features>,
}

impl FeaturesDefaultsBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            config: Mutex::new(Features {
                nurse: None,
                ..default()
            }),
        }
    }

    /// Build final config
    pub fn build(self: Arc<Self>) -> Features {
        self.config.lock().clone()
    }

    /// Enable lana, this requires input from apps
    pub fn enable_lana(self: Arc<Self>, event_path: String, prod: bool) -> Arc<Self> {
        self.config.lock().lana = Some(FeatureLana { event_path, prod });
        self
    }

    /// Enable nurse with defaults
    pub fn enable_nurse(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().nurse = Some(default());
        self
    }

    /// Enable direct connections with defaults;
    pub fn enable_direct(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().direct = Some(default());
        self
    }

    /// Enable firewall connection resets when NepTUN is enabled
    pub fn enable_firewall_connection_reset(self: Arc<Self>) -> Arc<Self> {
        self.config
            .lock()
            .firewall
            .get_or_insert_with(Default::default)
            .neptun_reset_conns = true;
        self
    }

    /// Enable default wireguard timings, derp timings and other features for best battery performance
    pub fn enable_battery_saving_defaults(self: Arc<Self>) -> Arc<Self> {
        {
            // Do not override any preexisting values not related to battery savings
            let mut cfg = self.config.lock();
            cfg.wireguard.persistent_keepalive.vpn = Some(115);
            cfg.wireguard.persistent_keepalive.direct = 10;
            cfg.wireguard.persistent_keepalive.proxying = Some(125);
            cfg.wireguard.persistent_keepalive.stun = Some(125);

            // Preserve any previous values if those were set.
            let prev = cfg.derp.as_ref().cloned().unwrap_or_default();
            cfg.derp = Some(FeatureDerp {
                tcp_keepalive: Some(125),
                derp_keepalive: Some(125),
                enable_polling: Some(true),
                ..prev
            });
        }
        self
    }

    /// Enable key validation in set_config call with defaults
    pub fn enable_validate_keys(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().validate_keys = FeatureValidateKeys(true);
        self
    }

    /// Enable IPv6 with defaults
    pub fn enable_ipv6(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().ipv6 = true;
        self
    }

    /// Enable nicknames with defaults
    pub fn enable_nicknames(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().nicknames = true;
        self
    }

    /// Enable blocking event flush with timeout on stop with defaults
    pub fn enable_flush_events_on_stop_timeout_seconds(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().flush_events_on_stop_timeout_seconds = Some(0);
        self
    }

    /// Enable Link detection mechanism with defaults
    pub fn enable_link_detection(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().link_detection = Some(default());
        self
    }

    /// Enable multicast with defaults
    pub fn enable_multicast(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().multicast = true;
        self
    }

    pub fn enable_dynamic_wg_nt_control(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().wireguard.enable_dynamic_wg_nt_control = true;
        self
    }

    pub fn set_skt_buffer_size(self: Arc<Self>, skt_buffer_size: u32) -> Arc<Self> {
        self.config.lock().wireguard.skt_buffer_size = Some(skt_buffer_size);
        self
    }

    pub fn set_inter_thread_channel_size(
        self: Arc<Self>,
        inter_thread_channel_size: u32,
    ) -> Arc<Self> {
        self.config.lock().wireguard.inter_thread_channel_size = Some(inter_thread_channel_size);
        self
    }

    pub fn set_max_inter_thread_batched_pkts(
        self: Arc<Self>,
        max_inter_thread_batched_pkts: u32,
    ) -> Arc<Self> {
        self.config.lock().wireguard.max_inter_thread_batched_pkts =
            Some(max_inter_thread_batched_pkts);
        self
    }

    pub fn enable_error_notification_service(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().error_notification_service = Some(Default::default());
        self
    }
}

impl Default for FeaturesDefaultsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default<T: Default>() -> T {
    T::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_builder_default_features() {
        let expected_features = Features {
            nurse: None,
            ..default()
        };

        let builder = Arc::new(FeaturesDefaultsBuilder::new());
        let features = builder.build();

        assert_eq!(features, expected_features);
    }
}
