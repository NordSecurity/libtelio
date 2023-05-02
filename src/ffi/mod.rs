pub mod types;

use base64::{decode as base64decode, encode as base64encode};
use crypto_box::SecretKey;
use ffi_helpers::{error_handling, panic as panic_handling};
use ipnetwork::IpNetwork;
use libc::c_char;
use log::{error, Level, Metadata, Record};
use telio_wg::AdapterType;

#[cfg(target_os = "linux")]
use libc::c_uint;

#[cfg(not(target_os = "windows"))]
use libc::c_int;
#[cfg(target_os = "android")]
use telio_sockets::Protect;
use uuid::Uuid;

use std::{
    ffi::{CStr, CString},
    net::{IpAddr, SocketAddr},
    panic,
    ptr::null,
    sync::{Mutex, Once},
    time::Duration,
};

use self::types::*;
use crate::device::{Device, DeviceConfig, Result as DevResult};
use telio_model::{config::Config, event::*, mesh::ExitNode};

// debug tools
use telio_utils::{
    commit_sha, telio_log_debug, telio_log_error, telio_log_trace, telio_log_warn, version_tag,
};

const DEFAULT_PANIC_MSG: &str = "libtelio panicked";

/// Check if res is ok, else return early by converting Error into telio_result
/// and saving it to LAST_ERROR storage
macro_rules! ffi_try {
    ($expr:expr $(,)?) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                telio_log_trace!("ffi_try: {:?}", e);
                let telio_res_err = telio_result::from(&e);
                error_handling::update_last_error(e);
                return telio_res_err;
            }
        }
    };
}

/// Check, if block panics, and if so, save the panic message
macro_rules! ffi_catch_panic {
    ($expr:expr $(,)?) => {{
        let result = panic::catch_unwind(move || $expr).map_err(|e| {
            let message = panic_handling::recover_panic_message(e)
                .unwrap_or_else(|| DEFAULT_PANIC_MSG.to_string());
            anyhow::Error::from(panic_handling::Panic { message })
        });

        ffi_try!(result)
    }};
}

/// Length of a public or private key
const KEY_SIZE: usize = 32;

struct LogStatus {
    string: String,
    counter: u32,
}

lazy_static::lazy_static! {
    static ref LAST_LOG_STATUS: Mutex<LogStatus> = {
        Mutex::new(LogStatus{string: String::default(), counter: 0})
    };
}

#[allow(non_camel_case_types)]
pub struct telio(Mutex<Device>);

/// cbindgen:ignore
static PANIC_HOOK: Once = Once::new();

extern "C" {
    fn fortify_source();
}

#[no_mangle]
/// Create new telio library instance
/// # Parameters
/// - `events`:     Events callback
/// - `features`:   JSON string of enabled features
/// - `log_level`:  Log level
/// - `logger`:     Logging callback
pub extern "C" fn telio_new(
    dev: *mut *mut telio,
    features: *const c_char,
    events: telio_event_cb,
    log_level: telio_log_level,
    logger: telio_logger_cb,
) -> telio_result {
    unsafe {
        fortify_source();
    }

    let ret = telio_new_common(
        dev,
        features,
        events,
        log_level,
        logger,
        #[cfg(target_os = "android")]
        None,
    );

    match ret {
        // TELIO_RES_ALREADY_STARTED should not be returned here ever
        TELIO_RES_ALREADY_STARTED => telio_log_debug!("Device is already started (telio_new)"),
        TELIO_RES_INVALID_KEY => telio_log_debug!("Cannot parse key as base64 string (telio_new)"),
        TELIO_RES_BAD_CONFIG => telio_log_debug!("Cannot Parse Configuration (telio_new)"),
        TELIO_RES_LOCK_ERROR => telio_log_debug!("Cannot lock a mutex (telio_new)"),
        TELIO_RES_INVALID_STRING => telio_log_debug!("Cannot parse a string (telio_new)"),
        TELIO_RES_ERROR => telio_log_debug!("Unknown error (telio_new)"),
        TELIO_RES_OK => telio_log_debug!("Operation was succesful (telio_new)"),
    };

    ret
}

#[cfg(target_os = "android")] // to avoid one-liner
#[no_mangle]
/// Create new telio library instance
/// # Parameters
/// - `events`:     Events callback
/// - `features`:   JSON string of enabled features
/// - `log_level`:  Log level
/// - `logger`:     Logging callback
/// - `protect`:    Callback executed after exit-node connect (for VpnService::protectFromVpn())
pub extern "C" fn telio_new_with_protect(
    dev: *mut *mut telio,
    features: *const c_char,
    events: telio_event_cb,
    log_level: telio_log_level,
    logger: telio_logger_cb,
    protect: telio_protect_cb,
) -> telio_result {
    telio_new_common(dev, features, events, log_level, logger, Some(protect))
}

fn telio_new_common(
    dev: *mut *mut telio,
    features: *const c_char,
    events: telio_event_cb,
    log_level: telio_log_level,
    logger: telio_logger_cb,
    #[cfg(target_os = "android")] protect_cb: Option<telio_protect_cb>,
) -> telio_result {
    if let Err(err) = log::set_boxed_logger(Box::new(logger)) {
        error!("{}", err)
    }

    log::set_max_level(
        (<types::telio_log_level as Into<Level>>::into(log_level) as Level).to_level_filter(),
    );
    let event_dispatcher = move |e: Box<Event>| {
        let _ = CString::new(
            e.to_json()
                .unwrap_or_else(|_| String::from("event_to_json error")),
        )
        .map(|s| unsafe { (events.cb)(events.ctx, s.as_ptr()) })
        .map_err(|e| telio_log_warn!("Failed to create CString: {:?}", e));
    };

    PANIC_HOOK.call_once(|| {
        let events = event_dispatcher;
        panic::set_hook(Box::new(move |info| {
            // We need it on the logs as well ...
            error!("{}", info);

            let err = {
                let message = {
                    if let Some(msg) = info.payload().downcast_ref::<String>() {
                        msg.clone()
                    } else if let Some(msg) = info.payload().downcast_ref::<&str>() {
                        msg.to_string()
                    } else {
                        DEFAULT_PANIC_MSG.to_string()
                    }
                };
                anyhow::Error::from(panic_handling::Panic { message })
            };

            // Updating LAST_ERROR.
            // NOTE: this "could" duplicate updating error, if the error happens on ffi call stack as well ...
            error_handling::update_last_error(err);

            // Send this "cry for help" to whoever is on the upper side
            let e = Box::new(
                Event::new::<Error>()
                    .set(ErrorCode::Unknown)
                    .set(ErrorLevel::Critical)
                    .set(format!("{}", info)),
            );

            telio_log_debug!("call_once: {:?}", e);
            events(e);
        }));
    });

    let features = if !features.is_null() {
        let features = ffi_try!(unsafe { CStr::from_ptr(features) }
            .to_str()
            .map_err(|_| TELIO_RES_INVALID_STRING));

        ffi_try!(serde_json::from_str(features))
    } else {
        Default::default()
    };

    ffi_catch_panic!({
        // TODO: Update windows ffi to take in void*, for protect
        #[cfg(not(target_os = "android"))]
        let protect = None;
        #[cfg(target_os = "android")]
        let protect: Option<Protect> = match protect_cb {
            Some(protect) => Some(std::sync::Arc::new(move |fd| unsafe {
                (protect.cb)(protect.ctx, fd);
            })),
            None => None,
        };

        let device = ffi_try!(Device::new(features, event_dispatcher, protect));

        unsafe { *dev = Box::into_raw(Box::new(telio(Mutex::new(device)))) };

        TELIO_RES_OK
    })
}

#[no_mangle]
/// Completely stop and uninit telio lib.
pub extern "C" fn telio_destroy(dev: *mut telio) {
    let dev = unsafe { Box::from_raw(dev) };
    let mut dev = match dev.0.lock() {
        Ok(dev) => dev,
        Err(poisoned) => {
            telio_log_debug!("main telio lock has been poisoned");
            poisoned.into_inner()
        }
    };
    dev.stop();
    dev.shutdown_art();
}

#[no_mangle]
/// Explicitly deallocate telio object and shutdown async rt.
pub extern "C" fn telio_destroy_hard(dev: *mut telio) -> telio_result {
    let dev_b = unsafe { Box::from_raw(dev) };
    let device = dev_b.0.into_inner().unwrap_or_else(|e| e.into_inner());

    let res = device.try_shutdown(Duration::from_millis(1000));

    if res.is_ok() {
        telio_log_debug!("telio_destroy_hard sucessfull");
        return TELIO_RES_OK;
    }

    telio_log_debug!("Unknown error - telio_destroy_hard");
    TELIO_RES_ERROR
}

#[no_mangle]
/// Get default recommended adapter type for platform.
pub extern "C" fn telio_get_default_adapter() -> telio_adapter_type {
    AdapterType::default().into()
}

#[no_mangle]
/// Start telio with specified adapter.
///
/// Adapter will attempt to open its own tunnel.
pub extern "C" fn telio_start(
    dev: &telio,
    private_key: *const c_char,
    adapter: telio_adapter_type,
) -> telio_result {
    ffi_catch_panic!({
        let mut dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));

        let cstr = unsafe { CStr::from_ptr(private_key) };
        let private_key = ffi_try!(cstr.to_str().map_err(|_| TELIO_RES_INVALID_STRING));
        let private_key = ffi_try!(private_key.parse().map_err(|_| TELIO_RES_INVALID_STRING));
        dev.start(&DeviceConfig {
            private_key,
            adapter: adapter.into(),
            fwmark: None,
            name: None,
            tun: None,
        })
        .telio_log_result("telio_start")
    })
}

#[no_mangle]
/// Start telio with specified adapter and name.
///
/// Adapter will attempt to open its own tunnel.
pub extern "C" fn telio_start_named(
    dev: &telio,
    private_key: *const c_char,
    adapter: telio_adapter_type,
    name: *const c_char,
) -> telio_result {
    ffi_catch_panic!({
        let mut dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));

        let cstr = unsafe { CStr::from_ptr(private_key) };
        let private_key = ffi_try!(cstr.to_str().map_err(|_| TELIO_RES_INVALID_STRING));
        let private_key = ffi_try!(private_key.parse().map_err(|_| TELIO_RES_INVALID_STRING));
        let cstr_name = unsafe { CStr::from_ptr(name) };
        let name = ffi_try!(cstr_name.to_str().map_err(|_| TELIO_RES_INVALID_STRING)).to_owned();
        dev.start(&DeviceConfig {
            private_key,
            adapter: adapter.into(),
            fwmark: None,
            name: Some(name),
            tun: None,
        })
        .telio_log_result("telio_start_named")
    })
}

#[cfg(not(target_os = "windows"))]
#[no_mangle]
/// Start telio device with specified adapter and already open tunnel.
///
/// Telio will take ownership of tunnel , and close it on stop.
///
/// # Parameters
/// - `private_key`: base64 encoded private_key.
/// - `adapter`: Adapter type.
/// - `tun`: A valid filedescriptor to tun device.
///
pub extern "C" fn telio_start_with_tun(
    dev: &telio,
    private_key: *const c_char,
    adapter: telio_adapter_type,
    tun: c_int,
) -> telio_result {
    ffi_catch_panic!({
        let mut dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));
        let cstr = unsafe { CStr::from_ptr(private_key) };
        let private_key = ffi_try!(cstr.to_str().map_err(|_| TELIO_RES_INVALID_STRING));
        let private_key = ffi_try!(private_key.parse().map_err(|_| TELIO_RES_INVALID_STRING));
        dev.start(&DeviceConfig {
            private_key,
            adapter: adapter.into(),
            fwmark: None,
            name: None,
            tun: Some(tun),
        })
        .telio_log_result("telio_start_with_tun")
    })
}

#[no_mangle]
/// Stop telio device.
pub extern "C" fn telio_stop(dev: &telio) -> telio_result {
    ffi_catch_panic!({
        let mut dev = match dev.0.lock() {
            Ok(dev) => dev,
            Err(poisoned) => poisoned.into_inner(),
        };
        dev.stop();
        TELIO_RES_OK
    })
}

#[no_mangle]
/// get device luid.
pub extern "C" fn telio_get_adapter_luid(dev: &telio) -> u64 {
    match dev.0.lock() {
        Ok(mut d) => d.get_adapter_luid(),
        Err(e) => {
            telio_log_error!("telio_get_adapter_luid() failed {:?}", e);
            0
        }
    }
}

#[no_mangle]
/// Sets private key for started device.
///
/// If private_key is not set, device will never connect.
///
/// # Parameters
/// - `private_key`: Base64 encoded WireGuard private key, must not be NULL.
///
pub extern "C" fn telio_set_private_key(dev: &telio, private_key: *const c_char) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));
        let cstr = unsafe { CStr::from_ptr(private_key) };
        let private_key = ffi_try!(cstr.to_str().map_err(|_| TELIO_RES_INVALID_STRING));
        let private_key = ffi_try!(private_key.parse().map_err(|_| TELIO_RES_INVALID_STRING));
        ffi_try!(dev.set_private_key(&private_key));
        TELIO_RES_OK
    })
}

#[no_mangle]
pub extern "C" fn telio_get_private_key(dev: &telio) -> *mut c_char {
    let dev = match dev.0.lock() {
        Ok(dev) => dev,
        Err(err) => {
            telio_log_error!("telio_get_private_key: dev.get_private_key: {}", err);
            return bytes_to_zero_terminated_unmanaged_bytes(&[0_u8]);
        }
    };

    match dev.get_private_key() {
        Ok(key) => key_to_c_zero_terminated_string_unmanaged(&key.0),
        Err(err) => {
            telio_log_error!("telio_get_private_key: dev.get_private_key: {}", err);
            bytes_to_zero_terminated_unmanaged_bytes(&[0_u8])
        }
    }
}

#[no_mangle]
#[cfg(target_os = "linux")]
/// Sets fmark for started device.
///
/// # Parameters
/// - `fwmark`: unsigned 32-bit integer
///
pub extern "C" fn telio_set_fwmark(dev: &telio, fwmark: c_uint) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));
        ffi_try!(dev.set_fwmark(fwmark));
        TELIO_RES_OK
    })
}

#[no_mangle]
/// Notify telio with network state changes.
///
/// # Parameters
/// - `network_info`: Json encoded network sate info.
///                   Format to be decided, pass empty string for now.
pub extern "C" fn telio_notify_network_change(
    dev: &telio,
    network_info: *const c_char,
) -> telio_result {
    #![allow(unused_variables)]

    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));
        dev.notify_network_change()
            .telio_log_result("telio_notify_network_change")
    })
}

#[no_mangle]
/// Wrapper for `telio_connect_to_exit_node_with_id` that doesn't take an identifier
pub extern "C" fn telio_connect_to_exit_node(
    dev: &telio,
    public_key: *const c_char,
    allowed_ips: *const c_char,
    endpoint: *const c_char,
) -> telio_result {
    telio_connect_to_exit_node_with_id(dev, null(), public_key, allowed_ips, endpoint)
}

#[no_mangle]
/// Connects to an exit node. (VPN if endpoint is not NULL, Peer if endpoint is NULL)
///
/// Routing should be set by the user accordingly.
///
/// # Parameters
/// - `identifier`: String that identifies the exit node, will be generated if null is passed.
/// - `public_key`: Base64 encoded WireGuard public key for an exit node.
/// - `allowed_ips`: Semicolon separated list of subnets which will be routed to the exit node.
///                  Can be NULL, same as "0.0.0.0/0".
/// - `endpoint`: An endpoint to an exit node. Can be NULL, must contain a port.
///
/// # Examples
///
/// ```c
/// // Connects to VPN exit node.
/// telio_connect_to_exit_node_with_id(
///     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
///     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
///     "0.0.0.0/0", // Equivalent
///     "1.2.3.4:5678"
/// );
///
/// // Connects to VPN exit node, with specified allowed_ips.
/// telio_connect_to_exit_node_with_id(
///     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
///     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
///     "100.100.0.0/16;10.10.23.0/24",
///     "1.2.3.4:5678"
/// );
///
/// // Connect to exit peer via DERP
/// telio_connect_to_exit_node_with_id(
///     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
///     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
///     "0.0.0.0/0",
///     NULL
/// );
/// ```
///
pub extern "C" fn telio_connect_to_exit_node_with_id(
    dev: &telio,
    identifier: *const c_char,
    public_key: *const c_char,
    allowed_ips: *const c_char,
    endpoint: *const c_char,
) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));
        let identifier = if !identifier.is_null() {
            let cstr = ffi_try!(unsafe { CStr::from_ptr(identifier) }
                .to_str()
                .map_err(|_| TELIO_RES_INVALID_STRING));
            cstr.to_owned()
        } else {
            Uuid::new_v4().to_string()
        };

        let public_key = if !public_key.is_null() {
            let cstr = ffi_try!(unsafe { CStr::from_ptr(public_key) }
                .to_str()
                .map_err(|_| TELIO_RES_INVALID_STRING));
            ffi_try!(cstr.parse().map_err(|_| TELIO_RES_INVALID_STRING))
        } else {
            telio_log_error!("Public Key is NULL");
            return TELIO_RES_ERROR;
        };

        let allowed_ips = if !allowed_ips.is_null() {
            let cstr = ffi_try!(unsafe { CStr::from_ptr(allowed_ips) }
                .to_str()
                .map_err(|_| TELIO_RES_INVALID_STRING))
            .split(';');
            let allowed_ips: Vec<IpNetwork> = ffi_try!(cstr
                .map(|net| net.parse())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| TELIO_RES_INVALID_STRING));
            Some(allowed_ips)
        } else {
            None
        };

        let endpoint = if !endpoint.is_null() {
            let cstr = ffi_try!(unsafe { CStr::from_ptr(endpoint) }
                .to_str()
                .map_err(|_| TELIO_RES_INVALID_STRING));
            match cstr {
                "" => None,
                _ => {
                    let endpoint: SocketAddr =
                        ffi_try!(cstr.parse().map_err(|_| TELIO_RES_INVALID_STRING));
                    Some(endpoint)
                }
            }
        } else {
            None
        };

        let node = ExitNode {
            identifier,
            public_key,
            allowed_ips,
            endpoint,
        };
        dev.connect_exit_node(&node)
            .telio_log_result("telio_connect_to_exit_node")
    })
}

#[no_mangle]
/// Enables magic DNS if it was not enabled yet,
///
/// Routing should be set by the user accordingly.
///
/// # Parameters
/// - 'forward_servers': JSON array of DNS servers to route the requests trough.
///                      Cannot be NULL, accepts an empty array of servers.
/// # Examples
///
/// ```c
/// // Enable magic dns with some forward servers
/// telio_enable_magic_dns("[\"1.1.1.1\", \"8.8.8.8\"]");
///
/// // Enable magic dns with no forward server
/// telio_enable_magic_dns("[\"\"]");
/// ```
pub extern "C" fn telio_enable_magic_dns(
    dev: &telio,
    forward_servers: *const c_char,
) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_BAD_CONFIG));
        let servers_str = ffi_try!(unsafe { CStr::from_ptr(forward_servers) }
            .to_str()
            .map_err(|_| TELIO_RES_INVALID_STRING));
        let servers: Vec<IpAddr> = ffi_try!(serde_json::from_str(servers_str));
        dev.enable_magic_dns(&servers)
            .telio_log_result("telio_enable_magic_dns")
    })
}

#[no_mangle]
/// Disables magic DNS if it was enabled.
pub extern "C" fn telio_disable_magic_dns(dev: &telio) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_BAD_CONFIG));

        dev.disable_magic_dns()
            .telio_log_result("telio_disable_magic_dns")
    })
}

#[no_mangle]
/// Disconnects from specified exit node.
///
/// # Parameters
/// - `public_key`: Base64 encoded WireGuard public key for exit node.
///
pub extern "C" fn telio_disconnect_from_exit_node(
    dev: &telio,
    public_key: *const c_char,
) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));
        let public_key = if !public_key.is_null() {
            let cstr = ffi_try!(unsafe { CStr::from_ptr(public_key) }
                .to_str()
                .map_err(|_| TELIO_RES_INVALID_STRING));
            ffi_try!(cstr.parse().map_err(|_| TELIO_RES_INVALID_STRING))
        } else {
            telio_log_debug!("Public Key is NULL");
            return TELIO_RES_ERROR;
        };

        dev.disconnect_exit_node(&public_key)
            .telio_log_result("telio_disconnect_from_exit_node")
    })
}

#[no_mangle]
/// Disconnects from all exit nodes with no parameters required.
pub extern "C" fn telio_disconnect_from_exit_nodes(dev: &telio) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));

        dev.disconnect_exit_nodes()
            .telio_log_result("telio_disconnect_from_exit_nodes")
    })
}

#[no_mangle]
/// Enables meshnet if it is not enabled yet.
/// In case meshnet is enabled, this updates the peer map with the specified one.
///
/// # Parameters
/// - `cfg`: Output of GET /v1/meshnet/machines/{machineIdentifier}/map
///
pub extern "C" fn telio_set_meshnet(dev: &telio, cfg: *const c_char) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));

        if cfg.is_null() {
            telio_log_debug!("Stopping meshnet due to empty config");
            dev.set_config(&None).telio_log_result("telio_set_meshnet")
        } else {
            let cfg_str = ffi_try!(unsafe { CStr::from_ptr(cfg) }
                .to_str()
                .map_err(|_| TELIO_RES_INVALID_STRING));
            let cfg: Config = ffi_try!(serde_json::from_str(cfg_str));
            dev.set_config(&Some(cfg))
                .telio_log_result("telio_set_meshnet")
        }
    })
}

#[no_mangle]
/// Disables the meshnet functionality by closing all the connections.
pub extern "C" fn telio_set_meshnet_off(dev: &telio) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));

        dev.set_config(&None)
            .telio_log_result("telio_set_meshnet_off")
    })
}

#[no_mangle]
pub extern "C" fn telio_generate_secret_key(_dev: &telio) -> *mut c_char {
    let mut rng = crypto_box::rand_core::OsRng;
    let secret_key = SecretKey::generate(&mut rng);
    key_to_c_zero_terminated_string_unmanaged(secret_key.as_bytes()) //Managed by swig
}

#[no_mangle]
pub extern "C" fn telio_generate_public_key(_dev: &telio, secret: *const c_char) -> *mut c_char {
    if secret.is_null() {
        return std::ptr::null_mut();
    }
    let secret_base64: String = unsafe { CStr::from_ptr(secret) }
        .to_str()
        .unwrap_or_default()
        .parse()
        .unwrap_or_default();
    if secret_base64.is_empty() {
        return std::ptr::null_mut();
    }
    let secret_dec = match base64decode(secret_base64.as_bytes()) {
        Ok(x) => x,
        Err(_) => return std::ptr::null_mut(),
    };
    let mut secret_bytes = [0_u8; 32];
    secret_bytes.copy_from_slice(&secret_dec);

    let secret_key = SecretKey::from(secret_bytes);
    let public_key = secret_key.public_key();

    key_to_c_zero_terminated_string_unmanaged(public_key.as_bytes()) //Managed by swig
}

#[no_mangle]
pub extern "C" fn telio_get_version_tag() -> *mut c_char {
    bytes_to_zero_terminated_unmanaged_bytes(version_tag().as_bytes())
}

#[no_mangle]
pub extern "C" fn telio_get_commit_sha() -> *mut c_char {
    bytes_to_zero_terminated_unmanaged_bytes(commit_sha().as_bytes())
}

#[no_mangle]
pub extern "C" fn telio_get_status_map(dev: &telio) -> *mut c_char {
    log::trace!("acquiring dev lock");
    let dev = match dev.0.lock() {
        Ok(dev) => dev,
        Err(err) => {
            log::error!("telio_get_status_map: dev lock: {}", err);
            return std::ptr::null_mut();
        }
    };
    log::trace!("retrieving external nodes");
    let nodes = match dev.external_nodes() {
        Ok(nodes) => nodes,
        Err(err) => {
            log::error!("telio_get_status_map: external_nodes: {}", err);
            return std::ptr::null_mut();
        }
    };
    log::trace!("serializing");
    let json = match serde_json::to_string(&nodes) {
        Ok(json) => json,
        Err(err) => {
            log::error!("telio_get_status_map: to_string: {}", err);
            return std::ptr::null_mut();
        }
    };
    log::trace!("converting to char pointer");
    bytes_to_zero_terminated_unmanaged_bytes(json.as_bytes())
}

#[no_mangle]
/// Get last error's message length, including trailing null
pub extern "C" fn telio_get_last_error(_dev: &telio) -> *mut c_char {
    if let Some(err_str) = error_handling::error_message() {
        return bytes_to_zero_terminated_unmanaged_bytes(err_str.as_bytes());
    }

    std::ptr::null_mut()
}

#[allow(clippy::panic)]
#[no_mangle]
/// For testing only.
pub extern "C" fn __telio_generate_stack_panic(dev: &telio) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));

        if dev.is_running() {
            panic!("runtime_panic_test_call_stack");
        }

        telio_log_debug!("Unknown error ( __telio_generate_stack_panic )");
        TELIO_RES_ERROR
    })
}

#[no_mangle]
/// For testing only.
pub extern "C" fn __telio_generate_thread_panic(dev: &telio) -> telio_result {
    ffi_catch_panic!({
        let dev = ffi_try!(dev.0.lock().map_err(|_| TELIO_RES_LOCK_ERROR));

        if dev.is_running() {
            let res = dev._panic();

            if res.is_ok() {
                return TELIO_RES_OK;
            }
        }

        telio_log_debug!("Unknown error ( __telio_generate_thread_panic )");
        TELIO_RES_ERROR
    })
}

fn filter_log_message(msg: String) -> Option<String> {
    let mut log_status = match LAST_LOG_STATUS.lock() {
        Ok(status) => status,
        Err(_) => {
            return None;
        }
    };

    if !log_status.string.eq(&msg) {
        log_status.string = msg.clone();
        log_status.counter = 0;
        return Some(msg);
    }

    if log_status.counter > 0 && log_status.counter % 100 == 0 {
        log_status.counter += 1;
        return Some(format!("[repeated 100 times!] {}", msg));
    }

    if log_status.counter < 10 {
        log_status.counter += 1;
        return Some(msg);
    }

    log_status.counter += 1;
    None
}

impl log::Log for telio_logger_cb {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        if let Some(filtered_msg) = filter_log_message(format!(
            "{:#?}:{:#?} {}",
            record.file().unwrap_or("unknown file"),
            record.line().unwrap_or(0),
            record.args()
        )) {
            if let Ok(cstr) = CString::new(filtered_msg) {
                unsafe { (self.cb)(self.ctx, record.level().into(), cstr.as_ptr()) };
            }
        }
    }

    fn flush(&self) {}
}

trait FFILog {
    fn telio_log_result(self, caller: &str) -> telio_result;
}

impl FFILog for DevResult {
    fn telio_log_result(self, caller: &str) -> telio_result {
        let msg = format!("{:?}", self);
        let res = telio_result::from(self);
        match res {
            TELIO_RES_OK => telio_log_debug!("{}: {}", caller, msg),
            _ => telio_log_error!("{}: {}", caller, msg),
        };
        res
    }
}

fn key_to_c_zero_terminated_string_unmanaged(key: &[u8; KEY_SIZE]) -> *mut c_char {
    bytes_to_zero_terminated_unmanaged_bytes(base64encode(key).as_bytes())
}

fn bytes_to_zero_terminated_unmanaged_bytes(bytes: &[u8]) -> *mut c_char {
    let buf = unsafe {
        let buf = libc::malloc(bytes.len() + 1) as *mut u8;
        std::slice::from_raw_parts_mut(buf, bytes.len() + 1)
    };
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0; //set last byte to 0 for null terminated C string
    buf.as_ptr() as *mut c_char
}
