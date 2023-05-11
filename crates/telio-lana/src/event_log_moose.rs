//! This module serves an interface for libmoose.
//!
pub use moosemeshnetapp as moose;
pub use moosemeshnetapp::Error;

pub use telio_utils::telio_log_warn;

use serde_json::Value;

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
        ( $( $func:ident, $field:expr );* ) => {
            $(
                if let Some(val) = $field {
                    call_moose!($func, val);
                } else {
                    telio_log_warn!(
                        "[Lana] couldn't find foreign context field {}",
                        stringify!($field)
                    )
                }
            )*
        };
    }

    let foreign_tracker = "nordvpnapp";

    if let Ok(foreign_context) = moose::fetch_specific_context(foreign_tracker) {
        let (device_info, user_info) = parse_foreign_context(&foreign_context);

        set_context_fields!(
            set_context_device_brand, device_info.brand;
            set_context_device_fp, device_info.fp;
            set_context_device_location_city, device_info.location.city;
            set_context_device_location_country, device_info.location.country;
            set_context_device_location_region, device_info.location.region;
            set_context_device_model, device_info.model;
            set_context_device_os, device_info.os;
            set_context_device_resolution, device_info.resolution;
            set_context_device_timeZone, device_info.time_zone;
            set_context_device_type, device_info.x_type;
            set_context_user_fp, user_info.fp;
            set_context_user_subscription_currentState_activationDate, user_info.subscription.current_state.activation_date;
            set_context_user_subscription_currentState_frequencyInterval, user_info.subscription.current_state.frequency_interval;
            set_context_user_subscription_currentState_frequencyUnit, user_info.subscription.current_state.frequency_unit;
            set_context_user_subscription_currentState_isActive, user_info.subscription.current_state.is_active;
            set_context_user_subscription_currentState_isNewCustomer, user_info.subscription.current_state.is_new_customer;
            set_context_user_subscription_currentState_merchantId, user_info.subscription.current_state.merchant_id;
            set_context_user_subscription_currentState_paymentAmount, user_info.subscription.current_state.payment_amount;
            set_context_user_subscription_currentState_paymentCurrency, user_info.subscription.current_state.payment_currency;
            set_context_user_subscription_currentState_paymentProvider, user_info.subscription.current_state.payment_provider;
            set_context_user_subscription_currentState_paymentStatus, user_info.subscription.current_state.payment_status;
            set_context_user_subscription_currentState_planId, user_info.subscription.current_state.plan_id;
            set_context_user_subscription_currentState_planType, user_info.subscription.current_state.plan_type;
            set_context_user_subscription_currentState_subscriptionStatus, user_info.subscription.current_state.subscription_status;
            set_context_user_subscription_history, user_info.subscription.history
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
/// * MeshnetappContextDevice - Item containing parsed information from the json context
/// if successful or empty item otherwise.
fn parse_foreign_context(
    foreign_context: &str,
) -> (moose::MeshnetappContextDevice, moose::MeshnetappContextUser) {
    let mut device_info = moose::MeshnetappContextDevice {
        brand: None,
        fp: None,
        location: moose::MeshnetappContextDeviceLocation {
            city: None,
            country: None,
            region: None,
        },
        model: None,
        os: None,
        resolution: None,
        time_zone: None,
        x_type: None,
    };

    let mut user_info = moose::MeshnetappContextUser {
        fp: None,
        subscription: moose::MeshnetappContextUserSubscription {
            current_state: moose::MeshnetappContextUserSubscriptionCurrentState {
                activation_date: None,
                frequency_interval: None,
                frequency_unit: None,
                is_active: None,
                is_new_customer: None,
                merchant_id: None,
                payment_amount: None,
                payment_currency: None,
                payment_provider: None,
                payment_status: None,
                plan_id: None,
                plan_type: None,
                subscription_status: None,
            },
            history: None,
        },
    };

    if let Ok(foreign_context) = serde_json::from_str::<Value>(foreign_context) {
        if let Some(foreign_device_info) = foreign_context.get("device") {
            device_info.brand = get_string_field(foreign_device_info, "brand");
            device_info.fp = get_string_field(foreign_device_info, "fp");
            device_info.model = get_string_field(foreign_device_info, "model");
            device_info.os = get_string_field(foreign_device_info, "os");
            device_info.resolution = get_string_field(foreign_device_info, "resolution");
            device_info.time_zone = get_string_field(foreign_device_info, "time_zone");

            if let Some(Value::String(string_type)) = foreign_device_info.get("type") {
                let ty = format!("\"{}\"", string_type);
                if let Ok(ty) = serde_json::from_str::<moose::MeshnetappDeviceType>(&ty) {
                    device_info.x_type = Some(ty);
                }
            }

            if let Some(foreign_location) = foreign_device_info.get("location") {
                device_info.location.city = get_string_field(foreign_location, "city");
                device_info.location.country = get_string_field(foreign_location, "country");
                device_info.location.region = get_string_field(foreign_location, "region");
            }
        }

        if let Some(foreign_user_info) = foreign_context.get("user") {
            user_info.fp = get_string_field(foreign_user_info, "fp");

            if let Some(foreign_subscription) = foreign_user_info.get("subscription") {
                user_info.subscription.history = get_string_field(foreign_subscription, "history");
                if let Some(foreign_state) = foreign_subscription.get("current_state") {
                    user_info.subscription.current_state.activation_date =
                        get_string_field(foreign_state, "activation_date");
                    user_info.subscription.current_state.frequency_interval =
                        get_i32_field(foreign_state, "frequency_interval");
                    user_info.subscription.current_state.frequency_unit =
                        get_string_field(foreign_state, "frequency_unit");
                    user_info.subscription.current_state.is_active =
                        get_bool_field(foreign_state, "is_active");
                    user_info.subscription.current_state.is_new_customer =
                        get_bool_field(foreign_state, "is_new_customer");
                    user_info.subscription.current_state.merchant_id =
                        get_i32_field(foreign_state, "merchant_id");
                    user_info.subscription.current_state.payment_amount =
                        get_f32_field(foreign_state, "payment_amount");
                    user_info.subscription.current_state.payment_currency =
                        get_string_field(foreign_state, "payment_currency");
                    user_info.subscription.current_state.payment_provider =
                        get_string_field(foreign_state, "payment_provider");
                    user_info.subscription.current_state.payment_status =
                        get_string_field(foreign_state, "payment_status");
                    user_info.subscription.current_state.plan_id =
                        get_i32_field(foreign_state, "plan_id");
                    user_info.subscription.current_state.plan_type =
                        get_string_field(foreign_state, "plan_type");
                    user_info.subscription.current_state.subscription_status =
                        get_string_field(foreign_state, "subscription_status");
                }
            }
        }
    }

    (device_info, user_info)
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

        let (device, user) = parse_foreign_context(complete_string_json);

        assert_eq!(device.brand, Some(String::from("test-brand")));
        assert_eq!(device.fp, Some(String::from("test-fp")));
        assert_eq!(device.model, Some(String::from("test-model")));
        assert_eq!(device.os, Some(String::from("test-os")));
        assert_eq!(device.resolution, Some(String::from("test-resolution")));
        assert_eq!(device.time_zone, Some(String::from("test-time-zone")));
        assert_eq!(device.location.city, Some(String::from("test-city")));
        assert_eq!(device.location.country, Some(String::from("test-country")));
        assert_eq!(device.location.region, Some(String::from("test-region")));

        assert_eq!(user.fp, Some(String::from("test-fp")));
        assert_eq!(
            user.subscription.current_state.activation_date,
            Some(String::from("test-activation-date"))
        );
        assert_eq!(user.subscription.current_state.frequency_interval, Some(1));
        assert_eq!(
            user.subscription.current_state.frequency_unit,
            Some(String::from("test-frequency-unit"))
        );
        assert_eq!(user.subscription.current_state.is_active, Some(true));
        assert_eq!(user.subscription.current_state.is_new_customer, Some(true));
        assert_eq!(user.subscription.current_state.payment_amount, Some(100.0));
        assert_eq!(
            user.subscription.current_state.payment_currency,
            Some(String::from("test-payment-currency"))
        );
        assert_eq!(
            user.subscription.current_state.payment_provider,
            Some(String::from("test-payment-provider"))
        );
        assert_eq!(
            user.subscription.current_state.payment_status,
            Some(String::from("test-payment-status"))
        );
        assert_eq!(user.subscription.current_state.plan_id, Some(32));
        assert_eq!(
            user.subscription.current_state.plan_type,
            Some(String::from("test-plan-type"))
        );
        assert_eq!(
            user.subscription.current_state.subscription_status,
            Some(String::from("test-subscription-status"))
        );
        assert_eq!(
            user.subscription.history,
            Some(String::from("test-history"))
        );

        let same_type = device
            .x_type
            .map(|ty| ty == MeshnetappDeviceType::MeshnetappDeviceTypeDesktop)
            .unwrap_or(false);
        assert!(same_type);
    }

    #[test]
    fn test_deserialize_bad_type() {
        let bad_type_string_json = r#"{
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

        let bad_type = parse_foreign_context(bad_type_string_json);
        let no_type_no_status = parse_foreign_context(no_type_string_json);

        assert!(bad_type.0.x_type.is_none());
        assert!(no_type_no_status.0.x_type.is_none());
        assert!(no_type_no_status
            .1
            .subscription
            .current_state
            .payment_status
            .is_none());
    }

    #[test]
    fn test_deserialize_bad_location() {
        let missing_and_extra_fields_json = r#"{
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

        let missing_and_extra_fields = parse_foreign_context(missing_and_extra_fields_json);
        let no_location_and_state = parse_foreign_context(no_location_and_state_json);

        assert!(missing_and_extra_fields.0.location.country.is_none());
        assert_eq!(
            missing_and_extra_fields.0.location.city,
            Some(String::from("test-city"))
        );
        assert_eq!(
            missing_and_extra_fields.0.location.region,
            Some(String::from("test-region"))
        );

        assert!(no_location_and_state.0.location.city.is_none());
        assert!(no_location_and_state.0.location.country.is_none());
        assert!(no_location_and_state.0.location.region.is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .activation_date
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .frequency_interval
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .frequency_unit
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .is_active
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .is_new_customer
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .merchant_id
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .payment_amount
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .payment_currency
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .payment_provider
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .payment_status
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .plan_id
            .is_none());
        assert!(no_location_and_state
            .1
            .subscription
            .current_state
            .plan_type
            .is_none());
        assert!(no_location_and_state
            .1
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

        assert!(junk.0.brand.is_none());
        assert!(junk.0.fp.is_none());
        assert!(junk.0.model.is_none());
        assert!(junk.0.os.is_none());
        assert!(junk.0.resolution.is_none());
        assert!(junk.0.time_zone.is_none());
        assert!(junk.0.x_type.is_none());
        assert!(junk.0.location.city.is_none());
        assert!(junk.0.location.country.is_none());
        assert!(junk.0.location.region.is_none());
        assert!(junk.1.fp.is_none());
        assert!(junk.1.subscription.history.is_none());
        assert!(junk.1.subscription.current_state.activation_date.is_none());
        assert!(junk
            .1
            .subscription
            .current_state
            .frequency_interval
            .is_none());
        assert!(junk.1.subscription.current_state.frequency_unit.is_none());
        assert!(junk.1.subscription.current_state.is_active.is_none());
        assert!(junk.1.subscription.current_state.is_new_customer.is_none());
        assert!(junk.1.subscription.current_state.merchant_id.is_none());
        assert!(junk.1.subscription.current_state.payment_amount.is_none());
        assert!(junk.1.subscription.current_state.payment_currency.is_none());
        assert!(junk.1.subscription.current_state.payment_provider.is_none());
        assert!(junk.1.subscription.current_state.payment_status.is_none());
        assert!(junk.1.subscription.current_state.plan_id.is_none());
        assert!(junk.1.subscription.current_state.plan_type.is_none());
        assert!(junk
            .1
            .subscription
            .current_state
            .subscription_status
            .is_none());
    }
}
