pub mod types;

use anyhow::anyhow;
use ffi_helpers::{error_handling, panic as panic_handling};
use ipnetwork::IpNetwork;
use rand::Rng;
use telio_crypto::{PublicKey, SecretKey};
use telio_wg::AdapterType;
use tracing::{error, trace, Subscriber};

#[cfg(target_os = "android")]
use telio_sockets::Protect;
use uuid::Uuid;

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Mutex, Once},
    time::Duration,
};

use self::types::*;
use crate::device::{Device, DeviceConfig, Result as DevResult};
use telio_model::{
    config::{Config, ConfigParseError},
    event::*,
    features::Features,
    mesh::{ExitNode, Node},
};

// debug tools
use telio_utils::{
    commit_sha, telio_log_debug, telio_log_error, telio_log_info, telio_log_warn, version_tag,
};

const DEFAULT_PANIC_MSG: &str = "libtelio panicked";

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
            let err_string = err.to_string();
            error_handling::update_last_error(anyhow!(err_string.clone()));
            Err(TelioError::UnknownError { inner: err_string })
        }
    }
}

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
        callback: logger,
        max_level: log_level.into(),
    };
    if tracing::subscriber::set_global_default(tracing_subscriber).is_err() {
        telio_log_warn!("Could not set logger, because logger had already been set by previous libtelio instance");
    }
}

/// Get default recommended adapter type for platform.
pub fn get_default_adapter() -> TelioAdapterType {
    AdapterType::default().into()
}

/// Get current version tag.
pub fn get_version_tag() -> String {
    version_tag().to_owned()
}

/// Get current commit sha.
pub fn get_commit_sha() -> String {
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
pub fn deserialize_feature_config(fstr: String) -> FFIResult<Features> {
    if fstr.is_empty() {
        Ok(Features::default())
    } else {
        serde_json::from_str(&fstr).map_err(|_| TelioError::InvalidString)
    }
}

/// Utility function to create a `Config` object from a json-string
pub fn deserialize_meshnet_config(cfg_str: String) -> FFIResult<Config> {
    match Config::new_from_str(&cfg_str) {
        Ok((cfg, _)) => Ok(cfg),
        Err(e) => match e {
            ConfigParseError::BadConfig => Err(TelioError::BadConfig),
            _ => Err(TelioError::InvalidString),
        },
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
/// Initialize OS certificate store, should be called only once. Without call to telio_init_cert_store
/// telio will not be able to verify https certificates in the system certificate store.
/// # Params
/// - `env`:    see https://developer.android.com/training/articles/perf-jni#javavm-and-jnienv
/// - `ctx`:    see https://developer.android.com/reference/android/content/Context
pub extern "C" fn Java_com_nordsec_telio_TelioCert_initCertStore(
    env: *mut jni::sys::JNIEnv,
    ctx: jni::sys::jobject,
) -> u8 {
    use once_cell::sync::OnceCell;

    static RESULT: OnceCell<u8> = OnceCell::new();
    *RESULT.get_or_init(|| match unsafe { jni::JNIEnv::from_raw(env) } {
        Ok(env) => match rustls_platform_verifier::android::init_hosted(&env, ctx.into()) {
            Err(err) => {
                telio_log_error!("Failed to initialize certificate store {err:?}");
                1
            }
            Ok(()) => {
                telio_log_debug!("Successfully initialized certificate store");
                0
            }
        },
        Err(err) => {
            telio_log_error!("Failed to initialize certificate store {err:?}");
            1
        }
    })
}

pub struct Telio {
    inner: Mutex<Option<Device>>,
    id: usize,
}

impl Telio {
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
        let event_dispatcher = move |event: Box<Event>| {
            let event_res = events.event(*event);
            if let Err(err) = event_res {
                telio_log_error!("Could not call event callback due to error: {:?}", err);
            }
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
            Some(protect) => {
                let protect = protect;
                Some(Arc::new(move |fd| {
                    let protect_res = protect.protect(fd);
                    if let Err(err) = protect_res {
                        telio_log_error!("Could not call protect callback due to {:?}", err);
                    }
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

    fn log_entry(features: Features, serialized_event_fn: String, ret: &Result<Telio, TelioError>) {
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
        Err(TelioError::UnknownError {
            inner: "Unknown error - Telio::destroy_hard".to_owned(),
        })
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

    /// Notify telio system is going to sleep.
    pub fn notify_sleep(&self) -> FFIResult<()> {
        telio_log_info!("telio_notify_sleep entry with instance id: {}.", self.id);
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.notify_sleep().log_result("Telio::notify_sleep")
            })
        })
    }

    /// Notify telio system has woken up.
    pub fn notify_wakeup(&self) -> FFIResult<()> {
        telio_log_info!("telio_notify_wakeup entry with instance id: {}.", self.id);
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.notify_wakeup().log_result("Telio::notify_wakeup")
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

    /// Connects to the VPN exit node with post quantum tunnel
    ///
    /// Routing should be set by the user accordingly.
    ///
    /// # Parameters
    /// - `identifier`: String that identifies the exit node, will be generated if null is passed.
    /// - `public_key`: WireGuard public key for an exit node.
    /// - `allowed_ips`: List of subnets which will be routed to the exit node.
    ///                  Can be None, same as "0.0.0.0/0".
    /// - `endpoint`: An endpoint to an exit node. Must contain a port.
    pub fn connect_to_exit_node_postquantum(
        &self,
        identifier: Option<String>,
        public_key: PublicKey,
        allowed_ips: Option<Vec<IpNetwork>>,
        endpoint: SocketAddr,
    ) -> FFIResult<()> {
        telio_log_info!(
            "Telio::connect_to_exit_node_postquantum entry with instance id :{}. Identifier: {:?}, Public Key: {:?}. Allowed IP: {:?}. Endpoint: {:?}",
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
            endpoint: Some(endpoint),
        };
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.connect_vpn_post_quantum(&node)
                    .log_result("Telio::connect_vpn_post_quantum")
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

    pub fn is_running(&self) -> FFIResult<bool> {
        self.device_op(true, |dev| Ok(dev.is_running()))
    }

    pub fn trigger_analytics_event(&self) -> FFIResult<()> {
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.trigger_analytics_event()
                    .log_result("Telio::trigger_analytics_event")
            })
        })
    }

    pub fn trigger_qos_collection(&self) -> FFIResult<()> {
        catch_ffi_panic(|| {
            self.device_op(true, |dev| {
                dev.trigger_qos_collection()
                    .log_result("Telio::trigger_qos_collection")
            })
        })
    }

    #[allow(clippy::panic)]
    /// For testing only.
    pub fn generate_stack_panic(&self) -> FFIResult<()> {
        catch_ffi_panic(|| {
            if let Ok(true) = self.device_op(true, |dev| Ok(dev.is_running())) {
                panic!("runtime_panic_test_call_stack");
            }
            telio_log_debug!("Unknown error ( Telio::generate_stack_panic )");
            Err(TelioError::UnknownError {
                inner: "".to_owned(),
            })
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
                Err(TelioError::UnknownError {
                    inner: "".to_owned(),
                })
            })
        })
    }
}

/// cbindgen:ignore
static PANIC_HOOK: Once = Once::new();

extern "C" {
    fn fortify_source();
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

pub struct TelioTracingSubscriber {
    callback: Box<dyn TelioLoggerCb>,
    max_level: tracing::Level,
}

impl TelioTracingSubscriber {
    pub fn new(callback: Box<dyn TelioLoggerCb>, max_level: tracing::Level) -> Self {
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
            let _ = self.callback.log(level.into(), filtered_msg);
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
    fn log_result(self, caller: &str) -> FFIResult<()>;
}

impl FFILog for DevResult {
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

#[cfg(test)]
mod tests {
    use super::*;
    use telio_model::features::Features;

    // Same as in telio-model/src/config.rs
    const MAX_CONFIG_LENGTH: usize = 16 * 1024 * 1024;

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
    fn telio_set_meshnet_rejects_too_long_configs() {
        let cfg = "a".repeat(MAX_CONFIG_LENGTH);
        assert!(matches!(
            deserialize_meshnet_config(cfg),
            Err(TelioError::BadConfig)
        ));

        let cfg = "a".repeat(MAX_CONFIG_LENGTH + 2);
        assert!(matches!(
            deserialize_meshnet_config(cfg),
            Err(TelioError::InvalidString)
        ));
    }

    #[test]
    fn test_telio_new_when_is_test_env_flag_is_missing() {
        #[derive(Debug)]
        struct Events;
        impl TelioEventCb for Events {
            fn event(&self, _payload: Event) -> std::result::Result<(), TelioError> {
                Ok(())
            }
        }

        let features =
            deserialize_feature_config(CORRECT_FEATURES_JSON_WITHOUT_IS_TEST_ENV.to_owned())
                .unwrap();
        let res = Telio::new(features, Box::new(Events));

        assert!(res.is_ok());

        // Restore panic hook
        let _ = panic::take_hook();
    }

    #[test]
    fn test_telio_new_when_is_test_env_flag_is_present() {
        #[derive(Debug)]
        struct Events;
        impl TelioEventCb for Events {
            fn event(&self, _payload: Event) -> std::result::Result<(), TelioError> {
                Ok(())
            }
        }

        let features =
            deserialize_feature_config(CORRECT_FEATURES_JSON_WITH_IS_TEST_ENV.to_owned()).unwrap();
        let res = Telio::new(features, Box::new(Events));

        assert!(res.is_ok());

        // Restore panic hook
        let _ = panic::take_hook();
    }

    #[test]
    fn test_deserialize_feature_config_empty_string() {
        let actual = deserialize_feature_config("".to_owned()).unwrap();
        let expected = Features::default();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_deserialize_feature_config_valid_string() {
        let actual =
            deserialize_feature_config(CORRECT_FEATURES_JSON_WITHOUT_IS_TEST_ENV.to_owned());
        assert!(actual.is_ok());
    }
}
