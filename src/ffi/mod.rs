// TODO(Mathias): Remove this in cleanup PR
#![allow(dead_code)]

pub mod types;

use anyhow::anyhow;
use base64::{decode as base64decode, encode as base64encode};
use ffi_helpers::{error_handling, panic as panic_handling};
use ipnetwork::IpNetwork;
use libc::c_char;
use rand::Rng;
use telio_crypto::{PublicKey, SecretKey};
use telio_wg::AdapterType;
use tracing::{error, trace, Level, Subscriber};

#[cfg(target_os = "linux")]
use libc::c_uint;

#[cfg(not(target_os = "windows"))]
use libc::c_int;
#[cfg(target_os = "android")]
use telio_sockets::Protect;
use uuid::Uuid;

use std::{
    ffi::{CStr, CString},
    fmt,
    net::{IpAddr, SocketAddr},
    panic::{self, AssertUnwindSafe},
    process::abort,
    ptr::null,
    sync::{Arc, Mutex, Once},
    time::Duration,
};

use self::types::*;
use crate::device::{Device, DeviceConfig, Result as DevResult};
use telio_model::{
    api_config::Features,
    config::{Config, ConfigParseError},
    event::*,
    mesh::{ExitNode, Node},
};

// debug tools
use telio_utils::{
    commit_sha, telio_log_debug, telio_log_error, telio_log_info, telio_log_trace, telio_log_warn,
    version_tag,
};

const DEFAULT_PANIC_MSG: &str = "libtelio panicked";
const MAX_CONFIG_LENGTH: usize = 16 * 1024 * 1024;

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

/// Execute a given closure and catch any panics
///
/// If the closure returns an error or panics, the inner errors or panic message is added to LAST_ERROR storage
fn catch_ffi_panic<T, F>(expr: F) -> FFIResult<T>
where
    F: FnMut() -> FFIResult<T>,
{
    let result = panic::catch_unwind(AssertUnwindSafe(expr)).map_err(|e| {
        let message = panic_handling::recover_panic_message(e)
            .unwrap_or_else(|| DEFAULT_PANIC_MSG.to_string());
        anyhow::Error::from(panic_handling::Panic { message })
    });
    match result {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(err)) => {
            error_handling::update_last_error(anyhow!(err.to_string()));
            Err(err)
        }
        Err(err) => {
            error_handling::update_last_error(anyhow!(err.to_string()));
            Err(TelioError::UnknownError(anyhow!(err)))
        }
    }
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

/// Set the global logger.
/// # Parameters
/// - `log_level`: Max log level to log.
/// - `logger`: Callback to handle logging events.
pub fn set_global_logger(log_level: TelioLogLevel, logger: Box<dyn TelioLoggerCb>) {
    let tracing_subscriber = TelioTracingSubscriber {
        callback: SubscriberCallback::Uniffi(logger),
        max_level: log_level.into(),
    };
    if tracing::subscriber::set_global_default(tracing_subscriber).is_err() {
        telio_log_warn!("Could not set logger, because logger had already been set by previous libtelio instance");
    }
}

/// Get default recommended adapter type for platform.
pub fn uniffi_telio_get_default_adapter() -> TelioAdapterType {
    AdapterType::default().into()
}

/// Get current version tag.
pub fn uniffi_telio_get_version_tag() -> String {
    version_tag().to_owned()
}

/// Get current commit sha.
pub fn uniffi_telio_get_commit_sha() -> String {
    commit_sha().to_owned()
}

/// Generate a new secret key.
pub fn generate_secret_key() -> SecretKey {
    SecretKey::gen()
}

/// Get the public key that corresponds to a given private key.
pub fn generate_public_key(secret_key: SecretKey) -> PublicKey {
    secret_key.public()
}

/// Utility function to create a `Features` object from a json-string
/// Passing an empty string will return the default feature config
pub fn string_to_features(fstr: String) -> FFIResult<Features> {
    if fstr.is_empty() {
        Ok(Features::default())
    } else {
        serde_json::from_str(&fstr).map_err(|_| TelioError::InvalidString)
    }
}

/// Utility function to create a `Config` object from a json-string
pub fn string_to_meshnet_config(cfg_str: String) -> FFIResult<Config> {
    match Config::new_from_str(&cfg_str) {
        Ok((cfg, _)) => Ok(cfg),
        Err(e) => match e {
            ConfigParseError::BadConfig => Err(TelioError::BadConfig),
            _ => Err(TelioError::InvalidString),
        },
    }
}

// TODO(Mathias): Remove this in cleanup PR
// TODO(Mathias): Rename telio->Telio
#[allow(non_camel_case_types)]
pub struct telio {
    inner: Mutex<Option<Device>>,
    id: usize,
}

impl telio {
    /// Create new telio library instance
    /// # Parameters
    /// - `events`:     Events callback
    /// - `features`:   JSON string of enabled features
    pub fn new(features: Features, events: Box<dyn TelioEventCb>) -> FFIResult<Self> {
        unsafe {
            fortify_source();
        }
        let serialized_event_fn = format!("{:?}", events);
        let ret = Self::new_common(&features, events, None);
        Self::log_entry(features, serialized_event_fn, &ret);
        ret
    }

    /// Create new telio library instance
    /// # Parameters
    /// - `events`:     Events callback
    /// - `features`:   JSON string of enabled features
    /// - `protect`:    Callback executed after exit-node connect (for VpnService::protectFromVpn())
    pub fn new_with_protect(
        features: Features,
        events: Box<dyn TelioEventCb>,
        protect: Box<dyn TelioProtectCb>,
    ) -> FFIResult<Self> {
        let serialized_event_fn = format!("{:?}", events);
        let ret = Self::new_common(&features, events, Some(protect));
        Self::log_entry(features, serialized_event_fn, &ret);
        ret
    }

    fn new_common(
        features: &Features,
        events: Box<dyn TelioEventCb>,
        #[allow(unused)] protect_cb: Option<Box<dyn TelioProtectCb>>,
    ) -> FFIResult<Self> {
        let events = Arc::new(events);
        let event_dispatcher = move |e: Box<Event>| {
            let payload = e
                .to_json()
                .unwrap_or_else(|_| String::from("event_to_json error"));
            events.event(payload);
        };

        let panic_event_dispatcher = event_dispatcher.clone();
        PANIC_HOOK.call_once(|| {
            let events = panic_event_dispatcher;
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

        #[cfg(not(target_os = "android"))]
        let protect = None;
        #[cfg(target_os = "android")]
        let protect: Option<Protect> = match protect_cb {
            Some(protect) if cfg!(windows) => {
                let protect = protect;
                Some(Arc::new(move |fd| {
                    protect.protect(fd);
                }))
            }
            _ => None,
        };

        catch_ffi_panic(|| {
            let features = features.clone();
            let event_dispatcher = event_dispatcher.clone();
            let protect = protect.clone();
            let device = Device::new(features, event_dispatcher, protect)?;
            Ok(Self {
                inner: Mutex::new(Some(device)),
                id: rand::thread_rng().gen::<usize>(),
            })
        })
    }

    fn log_entry(features: Features, serialized_event_fn: String, ret: &Result<telio, TelioError>) {
        telio_log_info!(
            "Telio::new entry. features: {:?}. Event_ptr: {serialized_event_fn}. Return value: {:?}",
            features,
            ret.as_ref().map(|_| ())
        );
    }

    fn device_op<F, R>(&self, break_on_lock_error: bool, op: F) -> FFIResult<R>
    where
        F: Fn(&mut Device) -> FFIResult<R>,
    {
        let mut dev = match self.inner.lock() {
            Ok(dev) => dev,
            Err(poisoned) => {
                telio_log_debug!("main telio lock has been poisoned");
                match break_on_lock_error {
                    true => return Err(TelioError::LockError),
                    false => poisoned.into_inner(),
                }
            }
        };

        match *dev {
            Some(ref mut dev) => op(dev),
            None => Err(TelioError::NotStarted),
        }
    }

    /// Completely stop and uninit telio lib.
    pub fn destroy(&self) -> FFIResult<()> {
        catch_ffi_panic(|| {
            self.device_op(false, |dev| {
                dev.stop();
                dev.shutdown_art();
                Ok(())
            })
        })
    }

    /// Explicitly deallocate telio object and shutdown async rt.
    pub fn destroy_hard(&self) -> FFIResult<()> {
        let res = catch_ffi_panic(|| {
            let mut dev = match self.inner.lock() {
                Ok(dev) => dev,
                Err(poisoned) => poisoned.into_inner(),
            };
            let mut shutdown = false;
            if let Some(ref mut dev) = *dev {
                shutdown = dev.try_shutdown(Duration::from_millis(1000)).is_ok();
            }
            *dev = None;
            Ok(shutdown)
        });

        if res.is_ok() {
            telio_log_debug!("Telio::destroy_hard sucessfull");
            return Ok(());
        }

        telio_log_debug!("Unknown error - Telio::destroy_hard");
        Err(TelioError::UnknownError(anyhow!(
            "Unknown error - Telio::destroy_hard"
        )))
    }

    /// Start telio with specified adapter.
    ///
    /// Adapter will attempt to open its own tunnel.
    pub fn start(&self, private_key: SecretKey, adapter: TelioAdapterType) -> FFIResult<()> {
        telio_log_info!(
            "Telio::start entry with instance id: {}. Public key: {:?}. Adapter: {:?}",
            self.id,
            private_key.public(),
            &adapter
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.start(&DeviceConfig {
                    private_key,
                    adapter: adapter.into(),
                    fwmark: None,
                    name: None,
                    tun: None,
                })
                .log_result("Telio::start")
            })
        })
    }

    /// Start telio with specified adapter and name.
    ///
    /// Adapter will attempt to open its own tunnel.
    pub fn start_named(
        &self,
        private_key: SecretKey,
        adapter: TelioAdapterType,
        name: String,
    ) -> FFIResult<()> {
        telio_log_info!(
            "Telio::start entry with instance id: {}. Public key: {:?}. Adapter: {:?}. Name: {}",
            self.id,
            private_key.public(),
            &adapter,
            &name,
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.start(&DeviceConfig {
                    private_key,
                    adapter: adapter.into(),
                    fwmark: None,
                    name: Some(name.clone()),
                    tun: None,
                })
                .log_result("Telio::start_named")
            })
        })
    }

    /// Start telio device with specified adapter and already open tunnel.
    ///
    /// Telio will take ownership of tunnel , and close it on stop.
    ///
    /// The file descriptor in the `tun` parameter is not forwarded
    /// on windows
    ///
    /// # Parameters
    /// - `private_key`: base64 encoded private_key.
    /// - `adapter`: Adapter type.
    /// - `tun`: A valid filedescriptor to tun device.
    ///
    pub fn start_with_tun(
        &self,
        private_key: SecretKey,
        adapter: TelioAdapterType,
        _tun: i32,
    ) -> FFIResult<()> {
        telio_log_info!(
            "Telio::start entry with instance id: {}. Public key: {:?}. Adapter: {:?}. Tun: {_tun}",
            self.id,
            private_key.public(),
            &adapter
        );
        #[cfg(not(target_os = "windows"))]
        let tun = Some(_tun);
        #[cfg(target_os = "windows")]
        let tun = None;
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.start(&DeviceConfig {
                    private_key,
                    adapter: adapter.into(),
                    fwmark: None,
                    name: None,
                    tun,
                })
                .log_result("Telio::start_with_tun")
            })
        })
    }

    /// Stop telio device.
    pub fn stop(&self) -> FFIResult<()> {
        telio_log_info!("Telio::stop entry with instance id: {}.", self.id,);
        catch_ffi_panic(|| {
            self.device_op(false, |dev| {
                dev.stop();
                Ok(())
            })
        })
    }

    /// get device luid.
    pub fn get_adapter_luid(&self) -> u64 {
        self.device_op(true, |dev| Ok(dev.get_adapter_luid()))
            .unwrap_or_else(|e| {
                telio_log_error!("Telio::get_adapter_luid() failed {:?}", e);
                0
            })
    }

    /// Sets private key for started device.
    ///
    /// If private_key is not set, device will never connect.
    ///
    /// # Parameters
    /// - `private_key`: Base64-encoded WireGuard private key.
    ///
    pub fn set_secret_key(&self, private_key: &SecretKey) -> FFIResult<()> {
        telio_log_info!(
            "Telio::set_private_key entry with instance id: {}. Public key: {:?}",
            self.id,
            private_key.public()
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.set_private_key(private_key).map_err(TelioError::from)
            })
        })
    }

    pub fn get_secret_key(&self) -> SecretKey {
        self.device_op(true, |dev| dev.get_private_key().map_err(|e| e.into()))
            .unwrap_or_else(|err| {
                telio_log_error!("Telio::get_secret_key: dev.get_private_key: {}", err);
                SecretKey::default()
            })
    }

    /// Sets fmark for started device.
    ///
    /// This function only does something on linux.
    ///
    /// # Parameters
    /// - `fwmark`: unsigned 32-bit integer
    ///
    pub fn set_fwmark(&self, _fwmark: u32) -> FFIResult<()> {
        telio_log_info!(
            "Telio::set_fwmark entry with instance id: {}. fwmark: {}",
            self.id,
            _fwmark
        );
        #[cfg(not(target_os = "linux"))]
        return Ok(());
        #[cfg(target_os = "linux")]
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.set_fwmark(_fwmark).map_err(TelioError::from)
            })
        })
    }

    /// Notify telio with network state changes.
    ///
    /// # Parameters
    /// - `network_info`: Json-encoded network state info.
    ///                   Format to be decided, pass empty string for now.
    pub fn notify_network_change(&self, network_info: String) -> FFIResult<()> {
        #![allow(unused_variables)]

        telio_log_info!(
            "Telio::notify_network_change entry with instance id: {}.",
            self.id
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.notify_network_change()
                    .log_result("Telio::notify_network_change")
            })
        })
    }

    /// Wrapper for `Telio::connect_to_exit_node_with_id` that doesn't take an identifier
    pub fn connect_to_exit_node(
        &self,
        public_key: PublicKey,
        allowed_ips: Option<Vec<IpNetwork>>,
        endpoint: Option<SocketAddr>,
    ) -> FFIResult<()> {
        telio_log_info!(
            "Telio::connect_to_exit_node entry with instance id :{}. Public Key: {:?}. Allowed IP: {:?}. Endpoint: {:?}",
            self.id,
            public_key,
            allowed_ips,
            endpoint,
        );
        self.connect_to_exit_node_with_id(None, public_key, allowed_ips, endpoint)
    }

    /// Connects to an exit node. (VPN if endpoint is not NULL, Peer if endpoint is NULL)
    ///
    /// Routing should be set by the user accordingly.
    ///
    /// # Parameters
    /// - `identifier`: String that identifies the exit node, will be generated if null is passed.
    /// - `public_key`: WireGuard public key for an exit node.
    /// - `allowed_ips`: List of subnets which will be routed to the exit node.
    ///                  Can be None, same as "0.0.0.0/0".
    /// - `endpoint`: An endpoint to an exit node. Can be None, must contain a port.
    pub fn connect_to_exit_node_with_id(
        &self,
        identifier: Option<String>,
        public_key: PublicKey,
        allowed_ips: Option<Vec<IpNetwork>>,
        endpoint: Option<SocketAddr>,
    ) -> FFIResult<()> {
        telio_log_info!(
            "Telio::connect_to_exit_node_with_id entry with instance id :{}. Identifier: {:?}, Public Key: {:?}. Allowed IP: {:?}. Endpoint: {:?}",
            self.id,
            identifier,
            public_key,
            allowed_ips,
            endpoint,
        );
        let identifier = identifier.unwrap_or_else(|| Uuid::new_v4().to_string());
        let node = ExitNode {
            identifier,
            public_key,
            allowed_ips,
            endpoint,
        };
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.connect_exit_node(&node)
                    .log_result("Telio::connect_to_exit_node")
            })
        })
    }

    /// Enables magic DNS if it was not enabled yet,
    ///
    /// Routing should be set by the user accordingly.
    ///
    /// # Parameters
    /// - 'forward_servers': List of DNS servers to route the requests trough.
    pub fn enable_magic_dns(&self, forward_servers: &[IpAddr]) -> FFIResult<()> {
        telio_log_info!(
            "Telio::enable_magic_dns entry with instance id: {}. DNS Server: {:?}",
            self.id,
            forward_servers
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.enable_magic_dns(forward_servers)
                    .log_result("Telio::enable_magic_dns")
            })
        })
    }

    /// Disables magic DNS if it was enabled.
    pub fn disable_magic_dns(&self) -> FFIResult<()> {
        telio_log_info!(
            "Telio::disable_magic_dns entry with instance id: {}.",
            self.id
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.disable_magic_dns()
                    .log_result("Telio::disable_magic_dns")
            })
        })
    }

    /// Disconnects from specified exit node.
    ///
    /// # Parameters
    /// - `public_key`: WireGuard public key for exit node.
    ///
    pub fn disconnect_from_exit_node(&self, public_key: &PublicKey) -> FFIResult<()> {
        telio_log_info!(
            "Telio::disconnect_from_exit_node entry with instance id: {}. Public Key: {:?}",
            self.id,
            public_key
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.disconnect_exit_node(public_key)
                    .log_result("Telio::disconnect_from_exit_node")
            })
        })
    }

    /// Disconnects from all exit nodes with no parameters required.
    pub fn disconnect_from_exit_nodes(&self) -> FFIResult<()> {
        telio_log_info!(
            "Telio::disconnect_from_exit_nodes entry with instance id: {}.",
            self.id
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.disconnect_exit_nodes()
                    .log_result("Telio::disconnect_from_exit_nodes")
            })
        })
    }

    /// Enables meshnet if it is not enabled yet.
    /// In case meshnet is enabled, this updates the peer map with the specified one.
    ///
    /// # Parameters
    /// - `cfg`: Output of GET /v1/meshnet/machines/{machineIdentifier}/map
    ///
    pub fn set_meshnet(&self, cfg: Config) -> FFIResult<()> {
        telio_log_info!(
            "Telio::set_meshnet entry with instance id: {}. Meshmap: {:?}",
            self.id,
            &cfg
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                let cfg = cfg.clone();
                let cfg = Some(cfg);
                dev.set_config(&cfg).log_result("Telio::set_meshnet")
            })
        })
    }

    /// Disables the meshnet functionality by closing all the connections.
    pub fn set_meshnet_off(&self) -> FFIResult<()> {
        telio_log_info!(
            "Telio::set_meshnet_off entry with instance id: {}.",
            self.id
        );
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.set_config(&None).log_result("Telio::set_meshnet_off")
            })
        })
    }

    pub fn get_status_map(&self) -> Vec<Node> {
        trace!("acquiring dev lock");
        match self.device_op(true, |dev| dev.external_nodes().map_err(|e| e.into())) {
            Ok(d) => d,
            Err(err) => {
                error!("Telio::get_status_map: external_nodes: {}", err);
                vec![]
            }
        }
    }

    /// Get last error's message length, including trailing null
    pub fn get_last_error(&self) -> String {
        error_handling::error_message().unwrap_or_else(|| "".to_owned())
    }

    #[allow(clippy::panic)]
    /// For testing only.
    pub fn generate_stack_panic(&self) -> FFIResult<()> {
        catch_ffi_panic(|| {
            if let Ok(true) = self.device_op(true, |dev| Ok(dev.is_running())) {
                panic!("runtime_panic_test_call_stack");
            }
            telio_log_debug!("Unknown error ( Telio::generate_stack_panic )");
            Err(TelioError::UnknownError(anyhow!("")))
        })
    }

    /// For testing only.
    pub fn generate_thread_panic(&self) -> FFIResult<()> {
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                if dev.is_running() {
                    let res = dev._panic();
                    if res.is_ok() {
                        return Ok(());
                    }
                }
                telio_log_debug!("Unknown error ( Telio::generate_thread_panic )");
                Err(TelioError::UnknownError(anyhow!("")))
            })
        })
    }
}

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

    let features = ffi_try!(deserialize_features(features));
    let ret = telio_new_common(
        dev,
        &features,
        events,
        log_level,
        logger,
        #[cfg(target_os = "android")]
        None,
    );

    log_entry(features, events, log_level, logger, ret, dev);
    ret
}

fn char_to_str<'a>(char_ptr: *const c_char) -> Result<&'a str, telio_result> {
    if !char_ptr.is_null() {
        let cstr = unsafe { CStr::from_ptr(char_ptr) };
        cstr.to_str().map_err(|e| {
            telio_log_error!("{}", e);
            TELIO_RES_INVALID_STRING
        })
    } else {
        telio_log_error!("Null input parameter");
        Err(TELIO_RES_INVALID_STRING)
    }
}

fn deserialize_features(features: *const c_char) -> Result<Features, telio_result> {
    match char_to_str(features) {
        Ok(s) => Ok(serde_json::from_str(s)?),
        Err(_) => Ok(Default::default()),
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
/// Initialize OS certificate store, should be called only once. Without call to telio_init_cert_store
/// telio will not be able to verify https certificates in the system certificate store.
/// # Params
/// - `env`:    see https://developer.android.com/training/articles/perf-jni#javavm-and-jnienv
/// - `ctx`:    see https://developer.android.com/reference/android/content/Context
pub extern "C" fn telio_init_cert_store(
    env: *mut jni::sys::JNIEnv,
    ctx: jni::sys::jobject,
) -> telio_result {
    use once_cell::sync::OnceCell;

    static RESULT: OnceCell<telio_result> = OnceCell::new();
    *RESULT.get_or_init(|| match unsafe { jni::JNIEnv::from_raw(env) } {
        Ok(env) => match rustls_platform_verifier::android::init_hosted(&env, ctx.into()) {
            Err(err) => {
                telio_log_error!("Failed to initialize certificate store {err:?}");
                TELIO_RES_ERROR
            }
            Ok(()) => TELIO_RES_OK,
        },
        Err(err) => {
            telio_log_error!("Couldn't initialize certificate store: {err:?}");
            TELIO_RES_ERROR
        }
    })
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
    let features = ffi_try!(deserialize_features(features));
    let ret = telio_new_common(dev, &features, events, log_level, logger, Some(protect));
    log_entry(features, events, log_level, logger, ret, dev);
    ret
}

fn get_instance_id_from_ptr(dev: *mut *mut telio) -> Option<usize> {
    unsafe { dev.as_ref().and_then(|p| p.as_ref()).map(|p| p.id) }
}

fn log_entry(
    features: Features,
    events: telio_event_cb,
    log_level: telio_log_level,
    logger: telio_logger_cb,
    ret: telio_result,
    dev: *mut *mut telio,
) {
    telio_log_info!(
        "telio_new entry with instance id: {:?}. features: {:?}. Log level: {:?}. Event_ptr: {:?}. Logger_ptr: {:?}. Return value: {}",
        get_instance_id_from_ptr(dev),
        features,
        log_level,
        events,
        logger,
        ret
    );
}

fn telio_new_common(
    dev: *mut *mut telio,
    features: &Features,
    events: telio_event_cb,
    log_level: telio_log_level,
    logger: telio_logger_cb,
    #[cfg(target_os = "android")] protect_cb: Option<telio_protect_cb>,
) -> telio_result {
    let tracing_subscriber = TelioTracingSubscriber {
        callback: SubscriberCallback::Swig(logger),
        max_level: log_level.into(),
    };
    if tracing::subscriber::set_global_default(tracing_subscriber).is_err() {
        telio_log_warn!("Could not set logger, because logger had already been set by previous libtelio instance");
    }

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

    ffi_catch_panic!({
        // TODO: Update windows ffi to take in void*, for protect
        #[cfg(not(target_os = "android"))]
        let protect = None;
        #[cfg(target_os = "android")]
        let protect: Option<Protect> = match protect_cb {
            Some(protect) => Some(Arc::new(move |fd| unsafe {
                (protect.cb)(protect.ctx, fd);
            })),
            None => None,
        };

        let device = ffi_try!(Device::new((*features).clone(), event_dispatcher, protect));

        unsafe {
            *dev = Box::into_raw(Box::new(telio {
                inner: Mutex::new(Some(device)),
                id: rand::thread_rng().gen::<usize>(),
            }))
        };

        TELIO_RES_OK
    })
}

fn telio_device_op<F>(dev: &telio, break_on_lock_error: bool, op: F) -> telio_result
where
    F: Fn(&mut Device) -> telio_result,
{
    let mut dev = match dev.inner.lock() {
        Ok(dev) => dev,
        Err(poisoned) => {
            telio_log_debug!("main telio lock has been poisoned");
            match break_on_lock_error {
                true => return TELIO_RES_LOCK_ERROR,
                false => poisoned.into_inner(),
            }
        }
    };

    match *dev {
        Some(ref mut dev) => op(dev),
        None => TELIO_RES_ERROR,
    }
}

fn telio_device_op_ret<F, R>(
    dev: &telio,
    break_on_lock_error: bool,
    op: F,
) -> Result<R, telio_result>
where
    F: Fn(&mut Device) -> Result<R, telio_result>,
{
    let mut dev = match dev.inner.lock() {
        Ok(dev) => dev,
        Err(poisoned) => {
            telio_log_debug!("main telio lock has been poisoned");
            match break_on_lock_error {
                true => return Err(TELIO_RES_LOCK_ERROR),
                false => poisoned.into_inner(),
            }
        }
    };

    match *dev {
        Some(ref mut dev) => op(dev),
        None => Err(TELIO_RES_ERROR),
    }
}

#[no_mangle]
/// Completely stop and uninit telio lib.
pub extern "C" fn telio_destroy(dev: *mut telio) {
    let dev = unsafe { Box::from_raw(dev) };
    let _ = telio_device_op(dev.as_ref(), false, |dev| {
        dev.stop();
        dev.shutdown_art();
        TELIO_RES_OK
    });
}

#[no_mangle]
/// Explicitly deallocate telio object and shutdown async rt.
pub extern "C" fn telio_destroy_hard(dev: *mut telio) -> telio_result {
    let dev_b = unsafe { Box::from_raw(dev) };
    let mut device = dev_b.inner.lock().unwrap_or_else(|e| e.into_inner());

    let res = device
        .as_mut()
        .map(|ref mut dev| dev.try_shutdown(Duration::from_millis(1000)))
        .ok_or(TELIO_RES_ERROR);
    *device = None;

    if matches!(res, Ok(Ok(_))) {
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
    let private_key = ffi_try!(char_ptr_to_type::<SecretKey>(private_key));
    telio_log_info!(
        "telio_start entry with instance id: {}. Public key: {:?}. Adapter: {:?}",
        dev.id,
        private_key.public(),
        &adapter
    );

    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            dev.start(&DeviceConfig {
                private_key,
                adapter: adapter.into(),
                fwmark: None,
                name: None,
                tun: None,
            })
            .telio_log_result("telio_start")
        })
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
        telio_device_op(dev, true, |dev| {
            let private_key = ffi_try!(char_ptr_to_type::<SecretKey>(private_key));
            let name = ffi_try!(char_ptr_to_type::<String>(name));
            dev.start(&DeviceConfig {
                private_key,
                adapter: adapter.into(),
                fwmark: None,
                name: Some(name),
                tun: None,
            })
            .telio_log_result("telio_start_named")
        })
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
        telio_device_op(dev, true, |dev| {
            let private_key = ffi_try!(char_ptr_to_type::<SecretKey>(private_key));
            dev.start(&DeviceConfig {
                private_key,
                adapter: adapter.into(),
                fwmark: None,
                name: None,
                tun: Some(tun),
            })
            .telio_log_result("telio_start_with_tun")
        })
    })
}

#[no_mangle]
/// Stop telio device.
pub extern "C" fn telio_stop(dev: &telio) -> telio_result {
    telio_log_info!("telio_stop entry with instance id: {}.", dev.id,);
    ffi_catch_panic!({
        telio_device_op(dev, false, |dev| {
            dev.stop();
            TELIO_RES_OK
        })
    })
}

#[no_mangle]
/// get device luid.
pub extern "C" fn telio_get_adapter_luid(dev: &telio) -> u64 {
    telio_device_op_ret(dev, false, |dev| Ok(dev.get_adapter_luid())).unwrap_or_else(|e| {
        telio_log_error!("telio_get_adapter_luid() failed {:?}", e);
        0
    })
}

fn char_ptr_to_type<T: std::str::FromStr>(value: *const c_char) -> Result<T, telio_result>
where
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    char_to_str(value)?.parse().map_err(|e| {
        telio_log_error!("{:?}", e);
        TELIO_RES_INVALID_STRING
    })
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
    let private_key = ffi_try!(char_ptr_to_type::<SecretKey>(private_key));

    telio_log_info!(
        "telio_set_private_key entry with instance id: {}. Public key: {:?}",
        dev.id,
        private_key.public()
    );
    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            ffi_try!(dev.set_private_key(&private_key));
            TELIO_RES_OK
        })
    })
}

#[no_mangle]
pub extern "C" fn telio_get_private_key(dev: &telio) -> *mut c_char {
    let res = telio_device_op_ret(dev, true, |dev| {
        dev.get_private_key()
            .map(|key| key_to_c_zero_terminated_string_unmanaged(key.as_bytes()))
            .map_err(|e| e.into())
    });
    match res {
        Ok(res) => res,
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
        telio_log_info!(
            "telio_set_fwmark entry with instance id: {}. fwmark: {}",
            dev.id,
            fwmark
        );
        match telio_device_op_ret(dev, true, |dev| {
            dev.set_fwmark(fwmark).map_err(telio_result::from)
        }) {
            Ok(_) => TELIO_RES_OK,
            Err(res) => res,
        }
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

    telio_log_info!(
        "telio_notify_network_change entry with instance id: {}.",
        dev.id
    );
    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            dev.notify_network_change()
                .telio_log_result("telio_notify_network_change")
        })
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
    telio_log_info!(
        "telio_connect_to_exit_node entry with instance id :{}. Public Key: {:?}. Allowed IP: {:?}. Endpoint: {:?}",
        dev.id, char_ptr_to_type::<PublicKey>(public_key), char_ptr_to_type::<String>(allowed_ips), char_ptr_to_type::<SocketAddr>(endpoint)
    );
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
        let identifier = if !identifier.is_null() {
            let cstr = ffi_try!(unsafe { CStr::from_ptr(identifier) }
                .to_str()
                .map_err(|_| TELIO_RES_INVALID_STRING));
            cstr.to_owned()
        } else {
            Uuid::new_v4().to_string()
        };

        let public_key = if !public_key.is_null() {
            ffi_try!(char_ptr_to_type::<PublicKey>(public_key))
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
        telio_device_op(dev, true, |dev| {
            dev.connect_exit_node(&node)
                .telio_log_result("telio_connect_to_exit_node")
        })
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
    let servers_str = ffi_try!(char_to_str(forward_servers));
    let servers: Vec<IpAddr> = ffi_try!(serde_json::from_str(servers_str));
    telio_log_info!(
        "telio_enable_magic_dns entry with instance id: {}. DNS Server: {:?}",
        dev.id,
        servers
    );
    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            dev.enable_magic_dns(&servers)
                .telio_log_result("telio_enable_magic_dns")
        })
    })
}

#[no_mangle]
/// Disables magic DNS if it was enabled.
pub extern "C" fn telio_disable_magic_dns(dev: &telio) -> telio_result {
    telio_log_info!(
        "telio_disable_magic_dns entry with instance id: {}.",
        dev.id
    );
    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            dev.disable_magic_dns()
                .telio_log_result("telio_disable_magic_dns")
        })
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
    telio_log_info!(
        "telio_disconnect_from_exit_node entry with instance id: {}. Public Key: {:?}",
        dev.id,
        public_key
    );
    ffi_catch_panic!({
        let public_key = if !public_key.is_null() {
            ffi_try!(char_ptr_to_type::<PublicKey>(public_key))
        } else {
            telio_log_debug!("Public Key is NULL");
            return TELIO_RES_ERROR;
        };

        telio_device_op(dev, true, |dev| {
            dev.disconnect_exit_node(&public_key)
                .telio_log_result("telio_disconnect_from_exit_node")
        })
    })
}

#[no_mangle]
/// Disconnects from all exit nodes with no parameters required.
pub extern "C" fn telio_disconnect_from_exit_nodes(dev: &telio) -> telio_result {
    telio_log_info!(
        "telio_disconnect_from_exit_nodes entry with instance id: {}.",
        dev.id
    );
    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            dev.disconnect_exit_nodes()
                .telio_log_result("telio_disconnect_from_exit_nodes")
        })
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
        telio_device_op(dev, true, |telio_dev| {
            if cfg.is_null() {
                telio_log_debug!("Stopping meshnet due to empty config");
                telio_dev
                    .set_config(&None)
                    .telio_log_result("telio_set_meshnet")
            } else {
                let cfg_str = ffi_try!(unsafe { CStr::from_ptr(cfg) }
                    .to_str()
                    .map_err(|_| TELIO_RES_INVALID_STRING));
                let cfg = match Config::new_from_str(cfg_str) {
                    Ok((cfg, _)) => cfg,
                    Err(e) => {
                        return match e {
                            ConfigParseError::BadConfig => TELIO_RES_BAD_CONFIG,
                            _ => TELIO_RES_INVALID_STRING,
                        }
                    }
                };

                telio_log_info!(
                    "telio_set_meshnet entry with instance id: {}. Meshmap: {:?}",
                    dev.id,
                    &cfg
                );
                telio_dev
                    .set_config(&Some(cfg))
                    .telio_log_result("telio_set_meshnet")
            }
        })
    })
}

#[no_mangle]
/// Disables the meshnet functionality by closing all the connections.
pub extern "C" fn telio_set_meshnet_off(dev: &telio) -> telio_result {
    telio_log_info!("telio_set_meshnet_off entry with instance id: {}.", dev.id);
    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            dev.set_config(&None)
                .telio_log_result("telio_set_meshnet_off")
        })
    })
}

#[no_mangle]
pub extern "C" fn telio_generate_secret_key(_dev: &telio) -> *mut c_char {
    let secret_key = SecretKey::gen();
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

    let secret_key = SecretKey::new(secret_bytes);
    let public_key = secret_key.public();

    key_to_c_zero_terminated_string_unmanaged(&public_key.0) //Managed by swig
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
    trace!("acquiring dev lock and retrieving external nodes");
    let nodes =
        match telio_device_op_ret(dev, true, |dev| dev.external_nodes().map_err(|e| e.into())) {
            Ok(nodes) => nodes,
            Err(err) => {
                error!("telio_get_status_map: external_nodes: {}", err);
                return std::ptr::null_mut();
            }
        };
    trace!("serializing");
    let json = match serde_json::to_string(&nodes) {
        Ok(json) => json,
        Err(err) => {
            error!("telio_get_status_map: to_string: {}", err);
            return std::ptr::null_mut();
        }
    };
    trace!("converting to char pointer");
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
        telio_device_op(dev, true, |dev| {
            if dev.is_running() {
                panic!("runtime_panic_test_call_stack");
            }

            telio_log_debug!("Unknown error ( __telio_generate_stack_panic )");
            TELIO_RES_ERROR
        })
    })
}

#[no_mangle]
/// For testing only.
pub extern "C" fn __telio_generate_thread_panic(dev: &telio) -> telio_result {
    ffi_catch_panic!({
        telio_device_op(dev, true, |dev| {
            if dev.is_running() {
                let res = dev._panic();

                if res.is_ok() {
                    return TELIO_RES_OK;
                }
            }

            telio_log_debug!("Unknown error ( __telio_generate_thread_panic )");
            TELIO_RES_ERROR
        })
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

/// Visitor for `tracing` events that converts one field with name equal to `field_name`
/// value to a message string.
pub struct TraceFieldVisitor<'a> {
    field_name: &'static str,
    metadata: &'a tracing::Metadata<'a>,
    message: String,
}

impl<'a> tracing::field::Visit for TraceFieldVisitor<'a> {
    #[track_caller]
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        // For now we're handling only the message field value, because other fields are not yet used.
        if field.name() == self.field_name {
            self.message = format!(
                "{:#?}:{:#?} {:?}",
                self.metadata.module_path().unwrap_or("unknown module"),
                self.metadata.line().unwrap_or(0),
                value,
            );
        }
    }
}

pub enum SubscriberCallback {
    Swig(telio_logger_cb),
    Uniffi(Box<dyn TelioLoggerCb>),
}

impl SubscriberCallback {
    fn log(&self, level: Level, message: String) {
        match self {
            SubscriberCallback::Swig(cb) => {
                if let Ok(cstr) = CString::new(message) {
                    unsafe { (cb.cb)(cb.ctx, level.into(), cstr.as_ptr()) };
                }
            }
            SubscriberCallback::Uniffi(cb) => {
                cb.log(level.into(), message);
            }
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {
        // TODO
    }

    fn exit(&self, _span: &tracing::span::Id) {
        // TODO
    }
}

pub struct TelioTracingSubscriber {
    callback: SubscriberCallback,
    max_level: tracing::Level,
}

impl TelioTracingSubscriber {
    pub fn new(callback: SubscriberCallback, max_level: tracing::Level) -> Self {
        TelioTracingSubscriber {
            callback,
            max_level,
        }
    }
}

impl Subscriber for TelioTracingSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.level() <= &tracing::level_filters::STATIC_MAX_LEVEL
            && metadata.level() <= &self.max_level
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        // TODO using a placeholder for now
        tracing::span::Id::from_u64(1337)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {
        // TODO
    }

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
        // TODO
    }

    fn event(&self, event: &tracing::Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }

        let level = *event.metadata().level();
        let mut visitor = TraceFieldVisitor {
            // hardcoded name of the field where tracing stores the messages passed to tracing::info! etc
            field_name: "message",
            metadata: event.metadata(),
            message: String::new(),
        };
        event.record(&mut visitor);

        if let Some(filtered_msg) = filter_log_message(visitor.message) {
            self.callback.log(level, filtered_msg);
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {
        // TODO
    }

    fn exit(&self, _span: &tracing::span::Id) {
        // TODO
    }
}

trait FFILog {
    fn telio_log_result(self, caller: &str) -> telio_result;
    fn log_result(self, caller: &str) -> FFIResult<()>;
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

    fn log_result(self, caller: &str) -> FFIResult<()> {
        match &self {
            Ok(_) => {
                telio_log_debug!("{}: {:?}", caller, self);
                Ok(())
            }
            Err(err) => {
                telio_log_error!("{}: {:?}", caller, self);
                Err(err.into())
            }
        }
    }
}

fn key_to_c_zero_terminated_string_unmanaged(key: &[u8; KEY_SIZE]) -> *mut c_char {
    bytes_to_zero_terminated_unmanaged_bytes(base64encode(key).as_bytes())
}

fn bytes_to_zero_terminated_unmanaged_bytes(bytes: &[u8]) -> *mut c_char {
    let buf = unsafe {
        let buf = libc::malloc(bytes.len() + 1) as *mut u8;
        if buf.is_null() {
            // Just like the default allocation failure behaviour of rust std:
            // https://doc.rust-lang.org/std/alloc/fn.set_alloc_error_hook.html
            abort();
        }
        std::slice::from_raw_parts_mut(buf, bytes.len() + 1)
    };
    if let Some((last, elements)) = buf.split_last_mut() {
        elements.copy_from_slice(bytes);
        *last = 0;
    }
    buf.as_ptr() as *mut c_char
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::c_void;
    use std::ptr;
    use telio_model::api_config::Features;

    unsafe extern "C" fn test_telio_event_fn(_: *mut c_void, _: *const c_char) {}

    unsafe extern "C" fn test_telio_logger_fn(
        _: *mut c_void,
        _: telio_log_level,
        _: *const c_char,
    ) {
    }

    const CORRECT_FEATURES_JSON_WITHOUT_IS_TEST_ENV: &str = r#"
        {
            "wireguard":
            {
                "persistent_keepalive": {
                    "vpn": null,
                    "stun": 50
                }
            },
            "nurse":
            {
                "fingerprint": "fingerprint_test"
            },
            "lana":
            {
                "event_path": "path/to/some/event/data",
                "prod": true
            },
            "paths":
            {
                "priority": ["relay", "direct"],
                "force": "relay"
            },
            "direct": {},
            "exit_dns": {}
        }"#;

    const CORRECT_FEATURES_JSON_WITH_IS_TEST_ENV: &str = r#"
        {
            "wireguard":
            {
                "persistent_keepalive": {
                    "vpn": null,
                    "stun": 50
                }
            },
            "nurse":
            {
                "fingerprint": "fingerprint_test"
            },
            "lana":
            {
                "event_path": "path/to/some/event/data",
                "prod": true
            },
            "paths":
            {
                "priority": ["relay", "direct"],
                "force": "relay"
            },
            "direct": {},
            "exit_dns": {},
            "is_test_env": false
        }"#;

    #[test]
    fn telio_set_meshnet_rejects_too_long_configs() -> anyhow::Result<()> {
        let features = Features::default();
        let event_cb = Box::new(|_event| {});
        let telio_dev = telio {
            inner: Mutex::new(Some(Device::new(features, event_cb, None)?)),
            id: rand::thread_rng().gen::<usize>(),
        };

        let cfg = "a".repeat(MAX_CONFIG_LENGTH);
        assert_eq!(
            telio_set_meshnet(&telio_dev, cfg.as_bytes().as_ptr() as *const c_char),
            TELIO_RES_BAD_CONFIG
        );
        let cfg = "a".repeat(MAX_CONFIG_LENGTH + 1);
        assert_eq!(
            telio_set_meshnet(&telio_dev, cfg.as_bytes().as_ptr() as *const c_char),
            TELIO_RES_INVALID_STRING
        );
        Ok(())
    }

    #[test]
    fn test_telio_new_when_is_test_env_flag_is_missing() {
        let mut telio_dev: *mut telio = ptr::null_mut();
        let features_cstr = CString::new(CORRECT_FEATURES_JSON_WITHOUT_IS_TEST_ENV).unwrap();
        let events = telio_event_cb {
            ctx: ptr::null_mut(),
            cb: test_telio_event_fn,
        };
        let log_level = telio_log_level::TELIO_LOG_DEBUG;
        let telio_logger = telio_logger_cb {
            ctx: ptr::null_mut(),
            cb: test_telio_logger_fn,
        };
        let res = telio_new(
            &mut telio_dev,
            features_cstr.as_ptr(),
            events,
            log_level,
            telio_logger,
        );

        assert_eq!(res, TELIO_RES_OK);
        assert!(!telio_dev.is_null());

        // Restore panic hook
        let _ = panic::take_hook();
    }

    #[test]
    fn test_telio_new_when_is_test_env_flag_is_present() {
        let mut telio_dev: *mut telio = ptr::null_mut();
        let features_cstr = CString::new(CORRECT_FEATURES_JSON_WITH_IS_TEST_ENV).unwrap();
        let events = telio_event_cb {
            ctx: ptr::null_mut(),
            cb: test_telio_event_fn,
        };
        let log_level = telio_log_level::TELIO_LOG_DEBUG;
        let telio_logger = telio_logger_cb {
            ctx: ptr::null_mut(),
            cb: test_telio_logger_fn,
        };
        let res = telio_new(
            &mut telio_dev,
            features_cstr.as_ptr(),
            events,
            log_level,
            telio_logger,
        );

        assert_eq!(res, TELIO_RES_OK);
        assert!(!telio_dev.is_null());

        // Restore panic hook
        let _ = panic::take_hook();
    }

    #[test]
    fn test_bytes_to_zero_terminated_unmanaged_bytes() {
        let inputs: [(&[u8], &[u8]); 3] = [(&[], &[0]), (&[0], &[0, 0]), (&[1, 2], &[1, 2, 0])];
        for (input, expected_output) in inputs {
            let output = bytes_to_zero_terminated_unmanaged_bytes(input);
            let output =
                unsafe { Vec::from_raw_parts(output as *mut u8, input.len() + 1, input.len() + 1) };
            assert_eq!(output, expected_output);
        }
    }

    #[test]
    fn test_logging_when_telio_dev_empty() -> anyhow::Result<()> {
        let telio_dev: *mut *mut telio = ptr::null_mut();
        let res = get_instance_id_from_ptr(telio_dev);
        assert_eq!(res, None);

        let telio_dev: *mut *mut telio = Box::into_raw(Box::new(ptr::null_mut()));
        let res = get_instance_id_from_ptr(telio_dev);
        assert_eq!(res, None);

        let features = Features::default();
        let event_cb = Box::new(|_event| {});
        let id = rand::thread_rng().gen::<usize>();
        let telio_dev: *mut *mut telio = Box::into_raw(Box::new(Box::into_raw(Box::new(telio {
            inner: Mutex::new(Some(Device::new(features, event_cb, None)?)),
            id,
        }))));
        let res = get_instance_id_from_ptr(telio_dev);
        assert_eq!(res, Some(id));
        Ok(())
    }

    #[test]
    fn test_string_to_features_empty_string() {
        let actual = string_to_features("".to_owned()).unwrap();
        let expected = Features::default();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_string_to_features_valid_string() {
        let actual = string_to_features(CORRECT_FEATURES_JSON_WITHOUT_IS_TEST_ENV.to_owned());
        assert!(actual.is_ok());
    }
}
