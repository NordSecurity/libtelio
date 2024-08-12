use std::sync::Arc;

use parking_lot::Mutex;
use telio_model::features::{
    FeatureDerp, FeatureLana, FeaturePersistentKeepalive, FeatureValidateKeys, FeatureWireguard,
    Features,
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
            hide_ips: true,
            // All inner values of derp are None's or false's
            // and as it does not actualy control derp
            // builder part is not added
            derp: None,
            link_detection: None,
            pmtu_discovery: None,
            flush_events_on_stop_timeout_seconds: None,
            multicast: false,
            ipv6: false,
            nicknames: false,
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

    /// Enable firewall connection resets when boringtun is enabled
    pub fn enable_firewall_connection_reset(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().firewall.boringtun_reset_conns = true;
        self
    }

    /// Enable default wireguard timings, derp timings and other features for best battery performance
    pub fn enable_battery_saving_defaults(self: Arc<Self>) -> Arc<Self> {
        {
            let mut cfg = self.config.lock();
            cfg.wireguard = FeatureWireguard {
                persistent_keepalive: FeaturePersistentKeepalive {
                    vpn: Some(115),
                    direct: 10,
                    proxying: Some(125),
                    stun: Some(125),
                },
            };
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

    /// Enable PMTU discovery with defaults
    pub fn enable_pmtu_discovery(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().pmtu_discovery = Some(default());
        self
    }

    /// Eanable multicast with defaults
    pub fn enable_multicast(self: Arc<Self>) -> Arc<Self> {
        self.config.lock().multicast = true;
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
