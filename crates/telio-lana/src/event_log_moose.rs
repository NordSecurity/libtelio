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

/// Fetch and set to libmoose device information
pub fn init_device_info() {
    let foreign_tracker = "nordvpnapp";

    if let Ok(foreign_context) = moose::fetch_specific_context(foreign_tracker) {
        let device_info = parse_foreign_context(&foreign_context);

        if let Some(brand) = device_info.brand {
            call_moose!(set_context_device_brand, brand);
        } else {
            telio_log_warn!("[Lana] couldn't find device brand");
        }

        if let Some(fp) = device_info.fp {
            call_moose!(set_context_device_fp, fp);
        } else {
            telio_log_warn!("[Lana] couldn't find device fp");
        }

        if let Some(city) = device_info.location.city {
            call_moose!(set_context_device_location_city, city);
        } else {
            telio_log_warn!("[Lana] couldn't find device location city");
        }

        if let Some(country) = device_info.location.country {
            call_moose!(set_context_device_location_country, country);
        } else {
            telio_log_warn!("[Lana] couldn't find device location country");
        }

        if let Some(region) = device_info.location.region {
            call_moose!(set_context_device_location_region, region);
        } else {
            telio_log_warn!("[Lana] couldn't find device location region");
        }

        if let Some(model) = device_info.model {
            call_moose!(set_context_device_model, model);
        } else {
            telio_log_warn!("[Lana] couldn't find device model");
        }

        if let Some(os) = device_info.os {
            call_moose!(set_context_device_os, os);
        } else {
            telio_log_warn!("[Lana] couldn't find device os");
        }

        if let Some(resolution) = device_info.resolution {
            call_moose!(set_context_device_resolution, resolution);
        } else {
            telio_log_warn!("[Lana] couldn't find device resolution");
        }

        if let Some(time_zone) = device_info.time_zone {
            call_moose!(set_context_device_timeZone, time_zone);
        } else {
            telio_log_warn!("[Lana] couldn't find device timezone");
        }

        if let Some(ty) = device_info.x_type {
            call_moose!(set_context_device_type, ty);
        } else {
            telio_log_warn!("[Lana] couldn't find device type");
        }
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
fn parse_foreign_context(foreign_context: &str) -> moose::MeshnetappContextDevice {
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
    }

    device_info
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
            }  
          }"#;

        let x = parse_foreign_context(complete_string_json);

        assert_eq!(x.brand, Some(String::from("test-brand")));
        assert_eq!(x.fp, Some(String::from("test-fp")));
        assert_eq!(x.model, Some(String::from("test-model")));
        assert_eq!(x.os, Some(String::from("test-os")));
        assert_eq!(x.resolution, Some(String::from("test-resolution")));
        assert_eq!(x.time_zone, Some(String::from("test-time-zone")));
        assert_eq!(x.location.city, Some(String::from("test-city")));
        assert_eq!(x.location.country, Some(String::from("test-country")));
        assert_eq!(x.location.region, Some(String::from("test-region")));

        let same_type = x
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
            }  
          }"#;

        let bad_type = parse_foreign_context(bad_type_string_json);
        let no_type = parse_foreign_context(no_type_string_json);

        assert!(bad_type.x_type.is_none());
        assert!(no_type.x_type.is_none());
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
            }  
          }"#;

        let no_location_json = r#"{
            "device": {
                "brand": "test-brand",
                "fp": "test-fp",
                "model": "test-model",
                "os": "test-os",
                "resolution": "test-resolution",
                "time_zone": "test-time-zone",
                "type": "desktop"
            }  
          }"#;

        let missing_and_extra_fields = parse_foreign_context(missing_and_extra_fields_json);
        let no_location = parse_foreign_context(no_location_json);

        assert!(missing_and_extra_fields.location.country.is_none());
        assert_eq!(
            missing_and_extra_fields.location.city,
            Some(String::from("test-city"))
        );
        assert_eq!(
            missing_and_extra_fields.location.region,
            Some(String::from("test-region"))
        );

        assert!(no_location.location.city.is_none());
        assert!(no_location.location.country.is_none());
        assert!(no_location.location.region.is_none());
    }

    #[test]
    fn test_deserialize_junk() {
        let junk_json = r#"{
            "device": {
                "junk": "junk"
            }  
          }"#;
        let junk = parse_foreign_context(junk_json);

        assert!(junk.brand.is_none());
        assert!(junk.fp.is_none());
        assert!(junk.model.is_none());
        assert!(junk.os.is_none());
        assert!(junk.resolution.is_none());
        assert!(junk.time_zone.is_none());
        assert!(junk.x_type.is_none());
        assert!(junk.location.city.is_none());
        assert!(junk.location.country.is_none());
        assert!(junk.location.region.is_none());
    }
}
