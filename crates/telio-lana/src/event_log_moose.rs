//! This module serves an interface for libmoose.
//!

pub use moosemeshnetapp as moose;
pub use moosemeshnetapp::Error;

pub use telio_utils::{telio_log_debug, telio_log_warn};

use serde_json::Value;

trait CustomDebug {
    fn custom_debug(&self) -> String;
}

impl CustomDebug for moose::MeshnetappContextApplicationConfigCurrentState {
    fn custom_debug(&self) -> String {
        format!(
            "MeshnetappContextApplicationConfigCurrentState {{ nordvpnapp_version: {:?}, meshnet_enabled: {:?}, internal_meshnet: {:?}, external_links: {:?} }}",
            self.nordvpnapp_version,
            self.meshnet_enabled,
            self.internal_meshnet.custom_debug(),
            self.external_links
        )
    }
}

impl CustomDebug for moose::MeshnetappContextApplicationConfigCurrentStateInternalMeshnet {
    fn custom_debug(&self) -> String {
        format!(
            "MeshnetappContextApplicationConfigCurrentStateInternalMeshnet {{ members: {:?}, members_nat: {:?}, fp: {:?}, fp_nat: {:?}, connectivity_matrix: {:?} }}",
            self.members,
            self.members_nat,
            self.fp,
            self.fp_nat,
            self.connectivity_matrix
        )
    }
}

/// Wrapper to call a moose function with optional arguments.
///
/// # Parameters:
/// * func - Name of the moose function to call.
/// * arg - Contains the arguments passed to the called function, if any.
/// # Returns:
/// * result - Moose function call result (successful or not).
/// * Err() - moose::Error::NotInitiatedError if lana was not initialized.
macro_rules! call_moose {
    (
        $func:ident
        $(,$arg:expr)*
    ) => {
            let result = moose::$func($($arg),*);
            if let Some(error) = result.as_ref().err() {
                telio_log_warn!("[Moose] Error: {} on call to `{}`", error, stringify!($func));
            }
    };
}

/// Fetch and set the context info from the foreign tracker
pub fn init_context_info() {
    macro_rules! set_context_fields {
        ( $( $func:ident, $field:expr $(, $t:tt)? );* $(;)?) => {
            $( set_context_fields!(@one $func, $field $(, $t)?); )*
        };

        (@one $func:ident, $field:expr) => {
            if let Some(val) = $field {
                call_moose!($func, val);
            } else {
                telio_log_warn!(
                    "[Lana] couldn't find foreign context field {}",
                    stringify!($field)
                )
            }
        };
        (@one $func:ident, $field:expr, optional) => {
            if let Some(val) = $field {
                call_moose!($func, val);
            } else {
                telio_log_debug!(
                    "[Lana] foreign context field {} does not exist",
                    stringify!($field)
                )
            }
        };
    }

    let foreign_tracker = "nordvpnapp";

    if let Ok(foreign_context) = moose::fetch_specific_context(foreign_tracker) {
        telio_log_debug!("foreign_context: {}", foreign_context);
        let tracker_context_info = parse_foreign_context(&foreign_context);
        telio_log_debug!("PARSED foreign_context: {:?}", tracker_context_info.application.config.current_state.custom_debug());
        set_context_fields!(
            set_context_application_config_currentState_nordvpnappVersion, tracker_context_info.application.version;
            set_context_device_brand, tracker_context_info.device.brand;
            set_context_device_fp, tracker_context_info.device.fp;
            set_context_device_location_city, tracker_context_info.device.location.city;
            set_context_device_location_country, tracker_context_info.device.location.country;
            set_context_device_location_region, tracker_context_info.device.location.region;
            set_context_device_model, tracker_context_info.device.model;
            set_context_device_os, tracker_context_info.device.os;
            set_context_device_resolution, tracker_context_info.device.resolution;
            set_context_device_timeZone, tracker_context_info.device.time_zone;
            set_context_device_type, tracker_context_info.device.x_type;
            set_context_user_fp, tracker_context_info.user.fp;
            set_context_user_subscription_currentState_activationDate, tracker_context_info.user.subscription.current_state.activation_date, optional;
            set_context_user_subscription_currentState_frequencyInterval, tracker_context_info.user.subscription.current_state.frequency_interval, optional;
            set_context_user_subscription_currentState_frequencyUnit, tracker_context_info.user.subscription.current_state.frequency_unit, optional;
            set_context_user_subscription_currentState_isActive, tracker_context_info.user.subscription.current_state.is_active, optional;
            set_context_user_subscription_currentState_isNewCustomer, tracker_context_info.user.subscription.current_state.is_new_customer, optional;
            set_context_user_subscription_currentState_merchantId, tracker_context_info.user.subscription.current_state.merchant_id, optional;
            set_context_user_subscription_currentState_paymentAmount, tracker_context_info.user.subscription.current_state.payment_amount, optional;
            set_context_user_subscription_currentState_paymentCurrency, tracker_context_info.user.subscription.current_state.payment_currency, optional;
            set_context_user_subscription_currentState_paymentProvider, tracker_context_info.user.subscription.current_state.payment_provider, optional;
            set_context_user_subscription_currentState_paymentStatus, tracker_context_info.user.subscription.current_state.payment_status, optional;
            set_context_user_subscription_currentState_planId, tracker_context_info.user.subscription.current_state.plan_id, optional;
            set_context_user_subscription_currentState_planType, tracker_context_info.user.subscription.current_state.plan_type, optional;
            set_context_user_subscription_currentState_subscriptionStatus, tracker_context_info.user.subscription.current_state.subscription_status, optional;
            set_context_user_subscription_history, tracker_context_info.user.subscription.history, optional;
        );
    } else {
        telio_log_warn!("[Moose] Failed to fetch context for {}", foreign_tracker);
    }
}

/// Parse a json context to mesh context structure
///
/// # Parameters:
/// * foreign_context - &str value containing the json context
/// # Returns:
/// * MeshnetappContext - Item containing user, app and device information parsed from the json context
/// if successful or empty item otherwise.
fn parse_foreign_context(foreign_context: &str) -> moose::MeshnetappContext {
    let mut tracker_info = moose::MeshnetappContext::default();

    if let Ok(foreign_context) = serde_json::from_str::<Value>(foreign_context) {
        if let Some(foreign_device_info) = foreign_context.get("device") {
            tracker_info.device.brand = get_string_field(foreign_device_info, "brand");
            tracker_info.device.fp = get_string_field(foreign_device_info, "fp");
            tracker_info.device.model = get_string_field(foreign_device_info, "model");
            tracker_info.device.os = get_string_field(foreign_device_info, "os");
            tracker_info.device.resolution = get_string_field(foreign_device_info, "resolution");
            tracker_info.device.time_zone = get_string_field(foreign_device_info, "time_zone");

            if let Some(Value::String(string_type)) = foreign_device_info.get("type") {
                let ty = format!("\"{}\"", string_type);
                if let Ok(ty) = serde_json::from_str::<moose::MeshnetappDeviceType>(&ty) {
                    tracker_info.device.x_type = Some(ty);
                }
            }

            if let Some(foreign_location) = foreign_device_info.get("location") {
                tracker_info.device.location.city = get_string_field(foreign_location, "city");
                tracker_info.device.location.country =
                    get_string_field(foreign_location, "country");
                tracker_info.device.location.region = get_string_field(foreign_location, "region");
            }
        }

        if let Some(foreign_user_info) = foreign_context.get("user") {
            tracker_info.user.fp = get_string_field(foreign_user_info, "fp");

            if let Some(foreign_subscription) = foreign_user_info.get("subscription") {
                tracker_info.user.subscription.history =
                    get_string_field(foreign_subscription, "history");
                if let Some(foreign_state) = foreign_subscription.get("current_state") {
                    tracker_info.user.subscription.current_state.activation_date =
                        get_string_field(foreign_state, "activation_date");
                    tracker_info
                        .user
                        .subscription
                        .current_state
                        .frequency_interval = get_i32_field(foreign_state, "frequency_interval");
                    tracker_info.user.subscription.current_state.frequency_unit =
                        get_string_field(foreign_state, "frequency_unit");
                    tracker_info.user.subscription.current_state.is_active =
                        get_bool_field(foreign_state, "is_active");
                    tracker_info.user.subscription.current_state.is_new_customer =
                        get_bool_field(foreign_state, "is_new_customer");
                    tracker_info.user.subscription.current_state.merchant_id =
                        get_i32_field(foreign_state, "merchant_id");
                    tracker_info.user.subscription.current_state.payment_amount =
                        get_f32_field(foreign_state, "payment_amount");
                    tracker_info
                        .user
                        .subscription
                        .current_state
                        .payment_currency = get_string_field(foreign_state, "payment_currency");
                    tracker_info
                        .user
                        .subscription
                        .current_state
                        .payment_provider = get_string_field(foreign_state, "payment_provider");
                    tracker_info.user.subscription.current_state.payment_status =
                        get_string_field(foreign_state, "payment_status");
                    tracker_info.user.subscription.current_state.plan_id =
                        get_i32_field(foreign_state, "plan_id");
                    tracker_info.user.subscription.current_state.plan_type =
                        get_string_field(foreign_state, "plan_type");
                    tracker_info
                        .user
                        .subscription
                        .current_state
                        .subscription_status =
                        get_string_field(foreign_state, "subscription_status");
                }
            }
        }

        if let Some(foreign_app_info) = foreign_context.get("application") {
            tracker_info.application.name = get_string_field(foreign_app_info, "name");
            tracker_info.application.version = get_string_field(foreign_app_info, "version");
            tracker_info.application.platform = get_string_field(foreign_app_info, "platform");
            tracker_info.application.arch = get_string_field(foreign_app_info, "arch");

            if let Some(foreign_app_config_info) = foreign_app_info.get("config") {
                if let Some(foreign_app_config_current_state_info) =
                    foreign_app_config_info.get("current_state")
                {
                    tracker_info
                        .application
                        .config
                        .current_state
                        .nordvpnapp_version = get_string_field(
                        foreign_app_config_current_state_info,
                        "nordvpnapp_version",
                    );
                }
            }
        }
    };

    tracker_info
}

/// Returns a field value in a json array
///
/// # Parameters:
/// * json - Json array
/// * field - Field to look for
/// # Returns:
/// * Some(i) - if successful, where i contains a String with the field value
/// * None - otherwise
fn get_string_field(json: &Value, field: &str) -> Option<String> {
    if let Some(Value::String(x)) = json.get(field) {
        Some(x.clone())
    } else {
        None
    }
}

/// Returns a field value in a json array
///
/// # Parameters:
/// * json - Json array
/// * field - Field to look for
/// # Returns:
/// * Some(i) - if successful, where i contains a i32 with the field value
/// * None - otherwise
fn get_i32_field(json: &Value, field: &str) -> Option<i32> {
    if let Some(Value::Number(x)) = json.get(field) {
        x.as_i64().map(|x| x as i32)
    } else {
        None
    }
}

/// Returns a field value in a json array
/// # Parameters:
/// * json - Json array
/// * field - Field to look for
/// # Returns:
/// * Some(i) - if successful, where i contains a f32 with the field value
/// * None - otherwise
fn get_f32_field(json: &Value, field: &str) -> Option<f32> {
    if let Some(Value::Number(x)) = json.get(field) {
        x.as_f64().map(|x| x as f32)
    } else {
        None
    }
}

/// Returns a field value in a json array
/// # Parameters:
/// * json - Json array
/// * field - Field to look for
/// # Returns:
/// * Some(i) - if successful, where i contains a bool with the field value
/// * None - otherwise
fn get_bool_field(json: &Value, field: &str) -> Option<bool> {
    if let Some(Value::Bool(x)) = json.get(field) {
        Some(*x)
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use moose::MeshnetappDeviceType;

    #[test]
    fn test_deserialize_complete_device() {
        let complete_string_json = r#"{
            "application": {
                "arch": "test-arch",
                "config": {
                    "current_state": {
                        "external_links": "test-external-links",
                        "internal_meshnet": {
                            "connectivity_matrix": "test-connectivity-matrix",
                            "fp": "test-fp",
                            "fp_nat": "test-fp-nat",
                            "members": "test-members",
                            "members_nat": "test-members-nat"
                        },
                        "meshnet_enabled": true,
                        "nordvpnapp_version": "test-nordvpnapp-version"
                    }
                },
                "name": "test-name",
                "platform": "test-platform",
                "version": "test-version"
            },
            "device": {
                "brand": "test-brand",
                "fp": "test-fp",
                "location": {
                    "city": "test-city",
                    "country": "test-country",
                    "region": "test-region"
                },
                "model": "test-model",
                "os": "test-os",
                "resolution": "test-resolution",
                "time_zone": "test-time-zone",
                "type": "desktop"
            },
            "user": {
                "fp": "test-fp",
                "subscription": {
                    "current_state": {
                        "activation_date": "test-activation-date",
                        "frequency_interval": 1,
                        "frequency_unit": "test-frequency-unit",
                        "is_active": true,
                        "is_new_customer": true,
                        "payment_amount": 100.0,
                        "payment_currency": "test-payment-currency",
                        "payment_provider": "test-payment-provider",
                        "payment_status": "test-payment-status",
                        "plan_id": 32,
                        "plan_type": "test-plan-type",
                        "subscription_status": "test-subscription-status"
                    },
                    "history": "test-history"
                }
            }
          }"#;

        let tracker_context_info = parse_foreign_context(complete_string_json);

        assert_eq!(
            tracker_context_info.device.brand,
            Some(String::from("test-brand"))
        );
        assert_eq!(
            tracker_context_info.device.fp,
            Some(String::from("test-fp"))
        );
        assert_eq!(
            tracker_context_info.device.model,
            Some(String::from("test-model"))
        );
        assert_eq!(
            tracker_context_info.device.os,
            Some(String::from("test-os"))
        );
        assert_eq!(
            tracker_context_info.device.resolution,
            Some(String::from("test-resolution"))
        );
        assert_eq!(
            tracker_context_info.device.time_zone,
            Some(String::from("test-time-zone"))
        );
        assert_eq!(
            tracker_context_info.device.location.city,
            Some(String::from("test-city"))
        );
        assert_eq!(
            tracker_context_info.device.location.country,
            Some(String::from("test-country"))
        );
        assert_eq!(
            tracker_context_info.device.location.region,
            Some(String::from("test-region"))
        );

        assert_eq!(tracker_context_info.user.fp, Some(String::from("test-fp")));
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .activation_date,
            Some(String::from("test-activation-date"))
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .frequency_interval,
            Some(1)
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .frequency_unit,
            Some(String::from("test-frequency-unit"))
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .is_active,
            Some(true)
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .is_new_customer,
            Some(true)
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .payment_amount,
            Some(100.0)
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .payment_currency,
            Some(String::from("test-payment-currency"))
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .payment_provider,
            Some(String::from("test-payment-provider"))
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .payment_status,
            Some(String::from("test-payment-status"))
        );
        assert_eq!(
            tracker_context_info.user.subscription.current_state.plan_id,
            Some(32)
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .plan_type,
            Some(String::from("test-plan-type"))
        );
        assert_eq!(
            tracker_context_info
                .user
                .subscription
                .current_state
                .subscription_status,
            Some(String::from("test-subscription-status"))
        );
        assert_eq!(
            tracker_context_info.user.subscription.history,
            Some(String::from("test-history"))
        );

        assert_eq!(
            tracker_context_info.application.arch,
            Some(String::from("test-arch"))
        );
        assert_eq!(
            tracker_context_info.application.name,
            Some(String::from("test-name"))
        );
        assert_eq!(
            tracker_context_info.application.platform,
            Some(String::from("test-platform"))
        );
        assert_eq!(
            tracker_context_info.application.version,
            Some(String::from("test-version"))
        );

        // nordvpnapp tracker context does not contain internalmeshnet data (except app version),
        // for that reason those values are not parsed
        assert_eq!(
            tracker_context_info
                .application
                .config
                .current_state
                .nordvpnapp_version,
            Some(String::from("test-nordvpnapp-version"))
        );
        assert!(tracker_context_info
            .application
            .config
            .current_state
            .meshnet_enabled
            .is_none());
        assert!(tracker_context_info
            .application
            .config
            .current_state
            .external_links
            .is_none());
        assert!(tracker_context_info
            .application
            .config
            .current_state
            .internal_meshnet
            .connectivity_matrix
            .is_none());
        assert!(tracker_context_info
            .application
            .config
            .current_state
            .internal_meshnet
            .fp_nat
            .is_none());
        assert!(tracker_context_info
            .application
            .config
            .current_state
            .internal_meshnet
            .fp
            .is_none());
        assert!(tracker_context_info
            .application
            .config
            .current_state
            .internal_meshnet
            .members
            .is_none());
        assert!(tracker_context_info
            .application
            .config
            .current_state
            .internal_meshnet
            .members_nat
            .is_none());

        let same_type = tracker_context_info
            .device
            .x_type
            .map(|ty| ty == MeshnetappDeviceType::MeshnetappDeviceTypeDesktop)
            .unwrap_or(false);
        assert!(same_type);
    }

    #[test]
    fn test_deserialize_bad_type() {
        let bad_type_string_json = r#"{
            "application": {
                "arch": "test-arch",
                "config": {
                    "current_state": {
                        "external_links": "test-external-links",
                        "internal_meshnet": {
                            "connectivity_matrix": "test-connectivity-matrix",
                            "fp": "test-fp",
                            "fp_nat": "test-fp-nat",
                            "members": "test-members",
                            "members_nat": "test-members-nat"
                        },
                        "meshnet_enabled": true,
                        "nordvpnapp_version": "test-nordvpnapp-version"
                    }
                },
                "name": "test-name",
                "platform": "test-platform",
                "version": "test-version"
            },
            "device": {
                "brand": "test-brand",
                "fp": "test-fp",
                "location": {
                    "city": "test-city",
                    "country": "test-country",
                    "region": "test-region"
                },
                "model": "test-model",
                "os": "test-os",
                "resolution": "test-resolution",
                "time_zone": "test-time-zone",
                "type": "bad-type"
            },
            "user": {
                "fp": "test-fp",
                "subscription": {
                    "current_state": {
                        "activation_date": "test-activation-date",
                        "frequency_interval": 1,
                        "frequency_unit": "test-frequency-unit",
                        "is_active": true,
                        "is_new_customer": true,
                        "payment_amount": 100.0,
                        "payment_currency": "test-payment-currency",
                        "payment_provider": "test-payment-provider",
                        "payment_status": "test-payment-status",
                        "plan_id": 32,
                        "plan_type": "test-plan-type",
                        "subscription_status": "test-subscription-status"
                    },
                    "history": "test-history"
                }
            }
          }"#;

        let no_type_string_json = r#"{
            "application": {
                "arch": "test-arch",
                "config": {
                    "current_state": {
                        "external_links": "test-external-links",
                        "internal_meshnet": {
                            "connectivity_matrix": "test-connectivity-matrix",
                            "fp": "test-fp",
                            "fp_nat": "test-fp-nat",
                            "members": "test-members",
                            "members_nat": "test-members-nat"
                        },
                        "meshnet_enabled": true,
                        "nordvpnapp_version": "test-nordvpnapp-version"
                    }
                },
                "name": "test-name",
                "platform": "test-platform",
                "version": "test-version"
            },
            "device": {
                "brand": "test-brand",
                "fp": "test-fp",
                "location": {
                    "city": "test-city",
                    "country": "test-country",
                    "region": "test-region"
                },
                "model": "test-model",
                "os": "test-os",
                "resolution": "test-resolution",
                "time_zone": "test-time-zone",
            },
            "user": {
                "fp": "test-fp",
                "subscription": {
                    "current_state": {
                        "activation_date": "test-activation-date",
                        "frequency_interval": 1,
                        "frequency_unit": "test-frequency-unit",
                        "is_active": true,
                        "is_new_customer": true,
                        "payment_amount": 100.0,
                        "payment_currency": "test-payment-currency",
                        "payment_provider": "test-payment-provider",
                        "plan_id": 32,
                        "plan_type": "test-plan-type",
                        "subscription_status": "test-subscription-status"
                    },
                    "history": "test-history"
                }
            }
          }"#;

        let bad_tracker_context_info = parse_foreign_context(bad_type_string_json);
        let no_type_no_status_tracker_context = parse_foreign_context(no_type_string_json);

        assert!(bad_tracker_context_info.device.x_type.is_none());
        assert!(no_type_no_status_tracker_context.device.x_type.is_none());
        assert!(no_type_no_status_tracker_context
            .user
            .subscription
            .current_state
            .payment_status
            .is_none());
    }

    #[test]
    fn test_deserialize_bad_location() {
        let missing_and_extra_fields_json = r#"{
            "application": {
                "arch": "test-arch",
                "config": {
                    "current_state": {
                        "external_links": "test-external-links",
                        "internal_meshnet": {
                            "connectivity_matrix": "test-connectivity-matrix",
                            "fp": "test-fp",
                            "fp_nat": "test-fp-nat",
                            "members": "test-members",
                            "members_nat": "test-members-nat"
                        },
                        "meshnet_enabled": true,
                        "nordvpnapp_version": "test-nordvpnapp-version"
                    }
                },
                "name": "test-name",
                "platform": "test-platform",
                "version": "test-version"
            },
            "device": {
                "brand": "test-brand",
                "fp": "test-fp",
                "location": {
                    "city": "test-city",
                    "bad-country": "bad-test-country",
                    "region": "test-region"
                },
                "model": "test-model",
                "os": "test-os",
                "resolution": "test-resolution",
                "time_zone": "test-time-zone",
                "type": "desktop"
            },
            "user": {
                "fp": "test-fp",
                "subscription": {
                    "current_state": {
                        "activation_date": "test-activation-date",
                        "frequency_interval": 1,
                        "frequency_unit": "test-frequency-unit",
                        "is_active": true,
                        "is_new_customer": true,
                        "payment_amount": 100.0,
                        "payment_currency": "test-payment-currency",
                        "payment_provider": "test-payment-provider",
                        "payment_status": "test-payment-status",
                        "plan_id": 32,
                        "plan_type": "test-plan-type",
                        "subscription_status": "test-subscription-status"
                    },
                    "history": "test-history"
                }
            }
          }"#;

        let no_location_and_state_json = r#"{
            "application": {
                "arch": "test-arch",
                "config": {
                    "current_state": {
                        "external_links": "test-external-links",
                        "internal_meshnet": {
                            "connectivity_matrix": "test-connectivity-matrix",
                            "fp": "test-fp",
                            "fp_nat": "test-fp-nat",
                            "members": "test-members",
                            "members_nat": "test-members-nat"
                        },
                        "meshnet_enabled": true,
                        "nordvpnapp_version": "test-nordvpnapp-version"
                    }
                },
                "name": "test-name",
                "platform": "test-platform",
                "version": "test-version"
            },
            "device": {
                "brand": "test-brand",
                "fp": "test-fp",
                "model": "test-model",
                "os": "test-os",
                "resolution": "test-resolution",
                "time_zone": "test-time-zone",
                "type": "desktop"
            },
            "user": {
                fp: "test-fp",
                "subscription": {
                    history: "test-history",
                }
            }
          }"#;

        let missing_and_extra_fields_tracker_context_info =
            parse_foreign_context(missing_and_extra_fields_json);
        let no_location_and_state_tracker_context_info =
            parse_foreign_context(no_location_and_state_json);

        assert!(missing_and_extra_fields_tracker_context_info
            .device
            .location
            .country
            .is_none());
        assert_eq!(
            missing_and_extra_fields_tracker_context_info
                .device
                .location
                .city,
            Some(String::from("test-city"))
        );
        assert_eq!(
            missing_and_extra_fields_tracker_context_info
                .device
                .location
                .region,
            Some(String::from("test-region"))
        );

        assert!(no_location_and_state_tracker_context_info
            .device
            .location
            .city
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .device
            .location
            .country
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .device
            .location
            .region
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .activation_date
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .frequency_interval
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .frequency_unit
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .is_active
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .is_new_customer
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .merchant_id
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .payment_amount
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .payment_currency
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .payment_provider
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .payment_status
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .plan_id
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .plan_type
            .is_none());
        assert!(no_location_and_state_tracker_context_info
            .user
            .subscription
            .current_state
            .subscription_status
            .is_none());
    }

    #[test]
    fn test_deserialize_junk() {
        let junk_json = r#"{
            "device": {
                "junk": "junk"
            }  
          }"#;
        let junk = parse_foreign_context(junk_json);

        assert!(junk.application.arch.is_none());
        assert!(junk.application.name.is_none());
        assert!(junk.application.platform.is_none());
        assert!(junk.application.version.is_none());
        assert!(junk
            .application
            .config
            .current_state
            .nordvpnapp_version
            .is_none());
        assert!(junk
            .application
            .config
            .current_state
            .meshnet_enabled
            .is_none());
        assert!(junk
            .application
            .config
            .current_state
            .external_links
            .is_none());
        assert!(junk
            .application
            .config
            .current_state
            .internal_meshnet
            .connectivity_matrix
            .is_none());
        assert!(junk
            .application
            .config
            .current_state
            .internal_meshnet
            .fp_nat
            .is_none());
        assert!(junk
            .application
            .config
            .current_state
            .internal_meshnet
            .fp
            .is_none());
        assert!(junk
            .application
            .config
            .current_state
            .internal_meshnet
            .members
            .is_none());
        assert!(junk
            .application
            .config
            .current_state
            .internal_meshnet
            .members_nat
            .is_none());
        assert!(junk.device.brand.is_none());
        assert!(junk.device.fp.is_none());
        assert!(junk.device.model.is_none());
        assert!(junk.device.os.is_none());
        assert!(junk.device.resolution.is_none());
        assert!(junk.device.time_zone.is_none());
        assert!(junk.device.x_type.is_none());
        assert!(junk.device.location.city.is_none());
        assert!(junk.device.location.country.is_none());
        assert!(junk.device.location.region.is_none());
        assert!(junk.user.fp.is_none());
        assert!(junk.user.subscription.history.is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .activation_date
            .is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .frequency_interval
            .is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .frequency_unit
            .is_none());
        assert!(junk.user.subscription.current_state.is_active.is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .is_new_customer
            .is_none());
        assert!(junk.user.subscription.current_state.merchant_id.is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .payment_amount
            .is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .payment_currency
            .is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .payment_provider
            .is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .payment_status
            .is_none());
        assert!(junk.user.subscription.current_state.plan_id.is_none());
        assert!(junk.user.subscription.current_state.plan_type.is_none());
        assert!(junk
            .user
            .subscription
            .current_state
            .subscription_status
            .is_none());
    }
}
