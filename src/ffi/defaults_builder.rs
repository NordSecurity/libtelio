use std::sync::Arc;

use parking_lot::Mutex;
use telio_model::features::{
    FeatureDerp, FeatureFirewall, FeatureLana, FeatureValidateKeys, Features,
};

pub struct FeaturesDefaultsBuilder {
    config: Mutex<Features>,
}

impl FeaturesDefaultsBuilder {
    pub fn new() -> Self {
        let config = Features {
            wireguard: default(),
            validate_keys: default(),
            firewall: default(),
            post_quantum_vpn: default(),
            dns: default(),
            nurse: None,
            lana: None,
            paths: None,
            direct: None,
            is_test_env: None,
            hide_user_data: true,
            hide_thread_id: true,
            // All inner values of derp are None's or false's
            // and as it does not actualy control derp
            // builder part is not added
            derp: None,
            link_detection: None,
            flush_events_on_stop_timeout_seconds: None,
            multicast: false,
            ipv6: false,
            nicknames: false,
            batching: None,
            error_notification_service: None,
        };

        Self {
            config: Mutex::new(config),
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
        if let Some(firewall) = self.config.lock().firewall.as_mut() {
            firewall.neptun_reset_conns = true;
        } else {
            self.config.lock().firewall = Some(FeatureFirewall {
                neptun_reset_conns: true,
                ..Default::default()
            });
        }
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

            // Preseve any previous values if those were set.
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

    /// Enable key valiation in set_config call with defaults
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

    /// Enable blocking event flush with timout on stop with defaults
    pub fn enable_flush_events_on_stop_timeout_seconds(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().flush_events_on_stop_timeout_seconds = Some(0);
        self
    }

    /// Enable Link detection mechanism with defaults
    pub fn enable_link_detection(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().link_detection = Some(default());
        self
    }

    /// Eanable multicast with defaults
    pub fn enable_multicast(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().multicast = true;
        self
    }

    pub fn enable_batching(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().batching = Some(default());
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
