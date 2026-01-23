#[warn(missing_docs)]
#[cfg(any(not(windows), doc))]
#[cfg_attr(docsrs, doc(cfg(not(windows))))]
mod neptun;

#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
mod linux_native_wg;

#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
mod windows_native_wg;

#[cfg(not(windows))]
use std::os::fd::OwnedFd;

use async_trait::async_trait;
#[cfg(any(test, feature = "test-adapter"))]
pub use mockall::automock;
use serde::{Deserialize, Serialize};
use std::{
    fmt, io,
    net::{AddrParseError, IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc,
};
use telio_crypto::{KeyDecodeError, PublicKey};
use telio_sockets::{Protect, SocketPool};
use thiserror::Error as TError;

use crate::uapi::{self, Cmd, Response};
use crate::wg::Config;

/// Function pointer to Firewall Inbound Callback
pub type FirewallInboundCb = Option<Arc<dyn Fn(&[u8; 32], &mut [u8]) -> bool + Send + Sync>>;

/// Function pointer to Firewall Outbound Callback
pub type FirewallOutboundCb =
    Option<Arc<dyn Fn(&[u8; 32], &[u8], &mut dyn io::Write) -> bool + Send + Sync>>;

/// Function pointer for reseting all the connections
pub type FirewallResetConnsCb = Option<Arc<dyn Fn(&PublicKey, &mut dyn io::Write) + Send + Sync>>;

/// Tunnel file descriptor
#[cfg(not(target_os = "windows"))]
#[cfg_attr(docsrs, doc(cfg(not(windows))))]
pub type Tun = OwnedFd;
/// Tunnel file descriptor is unused on Windows, thus an empty type alias
#[cfg(target_os = "windows")]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub type Tun = ();

#[cfg(all(not(any(test, feature = "test-adapter")), windows))]
const DEFAULT_NAME: &str = "NordLynx";

#[cfg(all(
    not(any(test, feature = "test-adapter")),
    any(target_os = "macos", target_os = "ios", target_os = "tvos")
))]
const DEFAULT_NAME: &str = "utun10";

#[cfg(all(
    not(any(test, feature = "test-adapter")),
    any(target_os = "linux", target_os = "android")
))]
const DEFAULT_NAME: &str = "nlx0";

/// Generic Adapter
#[cfg_attr(any(test, feature = "test-adapter"), automock)]
#[async_trait]
pub trait Adapter: Send + Sync {
    /// Stop and destroy Driver
    async fn stop(&self);

    /// Get luid for adapter interface.
    fn get_adapter_luid(&self) -> u64;

    /// Send uapi command, and receive response.
    /// Look at [Cross-Platform Userspace Interface](https://www.wireguard.com/xplatform/) for
    /// details.
    async fn send_uapi_cmd(&self, cmd: &Cmd) -> Result<Response, Error>;

    /// Disconnect all connected peer sockets
    async fn drop_connected_sockets(&self) {}

    /// Reset all the connections by injecting packets into the tunnel
    async fn inject_reset_packets(&self, _exit_pubkey: &PublicKey) {}

    /// Set the (u)tun file descriptor to be used by the adapter
    async fn set_tun(&self, tun: Tun) -> Result<(), Error>;

    /// Make a copy of this adapter.
    ///
    /// Only the custom adapters can be cloned this way.
    fn clone_box(&self) -> Option<Box<dyn Adapter>>;
}

/// Enumeration of `Error` types for `Adapter` struct
#[derive(Debug, TError)]
pub enum Error {
    /// Error types from NepTUN implementation
    #[cfg(not(windows))]
    #[error("NepTUN adapter error {0}")]
    NepTUN(#[from] ::neptun::device::Error),

    /// Error types from Linux Native implementation
    #[cfg(target_os = "linux")]
    #[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
    #[error("LinuxNativeWg adapter error {0}")]
    LinuxNativeWg(#[from] linux_native_wg::Error),

    /// Error types from Windows native implementation
    #[cfg(any(windows, doc))]
    #[cfg_attr(docsrs, doc(cfg(windows)))]
    #[error("WindowsNativeWg adapter error {0}")]
    WindowsNativeWg(#[from] windows_native_wg::Error),

    /// Unsupported adapter
    #[error("Unsupported adapter")]
    UnsupportedAdapter,

    /// Unsupported on Windows adapter
    #[error("Mismatched windows adapter")]
    MismatchedWindowsAdapter,

    /// Telio error
    #[error(transparent)]
    Telio(#[from] std::str::Utf8Error),
    /// Serde error
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    /// IO error
    #[error(transparent)]
    IoError(#[from] io::Error),

    /// Failed to restart adapter error
    #[error("Failed to restart internal adapter")]
    RestartFailed,

    /// Port assignment timeout error
    #[error("Timeout while waiting for port to be assigned")]
    PortAssignmentTimeoutError,

    /// Unsupported operation errro
    #[error("Unsupported operation error")]
    UnsupportedOperationError,

    /// Duplicate Allowed IPs error
    #[error("Duplicate AllowedIPs Error")]
    DuplicateAllowedIPsError,

    /// Error retrieving system time
    #[error("Failed to retrieve system time")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    /// Error executing task
    #[error("Runtime error occurred within WireGuard wrapper {0}")]
    ExecError(#[from] telio_task::ExecError),

    /// Uapi error
    #[error("Uapi error: {0}")]
    UapiFailed(#[from] uapi::Error),

    /// Parsing AdapterType from string failed
    #[error("Parsing AdapterType from string failed: {0}")]
    AdapterTypeParsingError(String),

    /// Internal Error
    #[error("Internal error: {0}")]
    InternalError(&'static str),

    /// Key decode error
    #[error("Failed to decode a key: {0}")]
    KeyDecodeError(#[from] KeyDecodeError),

    /// Endpoint parsing error
    #[error("Failed to parse endpoint address: {0}")]
    EndpointParsingError(#[from] AddrParseError),
}

/// Enumeration of types for `Adapter` struct
#[derive(Clone)]
pub enum AdapterType {
    /// NepTUN
    NepTUN,
    /// Linux Native
    LinuxNativeWg,
    /// Windows Native
    WindowsNativeWg,
    /// Custom adapter
    Custom(Arc<dyn Adapter>),
}

impl PartialEq for AdapterType {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (AdapterType::NepTUN, AdapterType::NepTUN)
                | (AdapterType::LinuxNativeWg, AdapterType::LinuxNativeWg)
                | (AdapterType::WindowsNativeWg, AdapterType::WindowsNativeWg)
        )
    }
}

impl std::fmt::Debug for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterType::NepTUN => f.write_str("NepTUN"),
            AdapterType::LinuxNativeWg => f.write_str("LinuxNativeWg"),
            AdapterType::WindowsNativeWg => f.write_str("WindowsNativeWg"),
            AdapterType::Custom(_) => f.write_str("Custom"),
        }
    }
}

impl Default for AdapterType {
    fn default() -> Self {
        if cfg!(any(
            target_os = "ios",
            target_os = "tvos",
            target_os = "macos",
            target_os = "linux"
        )) {
            AdapterType::NepTUN
        } else {
            AdapterType::WindowsNativeWg
        }
    }
}

impl FromStr for AdapterType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(AdapterType::default());
        }
        match s {
            "neptun" => Ok(Self::NepTUN),
            "linux-native" => Ok(Self::LinuxNativeWg),
            "wireguard-nt" => Ok(Self::WindowsNativeWg),
            _ => Err(Error::AdapterTypeParsingError(format!(
                "unrecognised adapter type: {s}"
            ))),
        }
    }
}

#[cfg(not(any(test, feature = "test-adapter")))]
pub(crate) async fn start(cfg: Config) -> Result<Box<dyn Adapter>, Error> {
    #![allow(unused_variables)]

    let name = cfg.name.clone().unwrap_or_else(|| DEFAULT_NAME.to_owned());

    match cfg.adapter {
        AdapterType::NepTUN => {
            #[cfg(windows)]
            return Err(Error::UnsupportedAdapter);

            #[cfg(unix)]
            use std::os::fd::IntoRawFd;

            #[cfg(unix)]
            Ok(Box::new(neptun::NepTUN::start(
                &name,
                cfg.tun.map(|tun| tun.into_raw_fd()),
                cfg.socket_pool.clone(),
                cfg.firewall_process_inbound_callback.clone(),
                cfg.firewall_process_outbound_callback.clone(),
                cfg.firewall_reset_connections.clone(),
                cfg.skt_buffer_size,
                cfg.inter_thread_channel_size,
                cfg.max_inter_thread_batched_pkts,
            )?))
        }
        AdapterType::LinuxNativeWg => {
            #[cfg(not(target_os = "linux"))]
            return Err(Error::UnsupportedAdapter);

            #[cfg(target_os = "linux")]
            Ok(Box::new(linux_native_wg::LinuxNativeWg::start(&name)?))
        }
        AdapterType::WindowsNativeWg => {
            #[cfg(not(windows))]
            return Err(Error::UnsupportedAdapter);

            #[cfg(windows)]
            Ok(Box::new(
                windows_native_wg::WindowsNativeWg::start(&name, cfg.enable_dynamic_wg_nt_control)
                    .await?,
            ))
        }
        AdapterType::Custom(adapter) => adapter.clone_box().ok_or(Error::UnsupportedAdapter),
    }
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use super::*;

    #[test]
    fn test_from_str() {
        let test_input: [&str; 3] = ["neptun", "linux-native", "wireguard-nt"];
        let expected_result: [AdapterType; 3] = [
            AdapterType::NepTUN,
            AdapterType::LinuxNativeWg,
            AdapterType::WindowsNativeWg,
        ];
        for (input, expected_adapter) in zip(test_input, expected_result) {
            let adapter = AdapterType::from_str(input).unwrap();
            assert_eq!(adapter, expected_adapter);
        }
    }

    #[test]
    fn test_from_str_default() {
        let adapter = AdapterType::from_str("").unwrap();
        assert_eq!(adapter, AdapterType::default());
    }

    #[test]
    fn test_from_str_wrong() {
        let test_input: [&str; 3] = ["NepTUN", "linux-native-wg", "whatever_completely_wrong"];

        for input in test_input {
            let err = AdapterType::from_str(input).unwrap_err();
            match err {
                Error::AdapterTypeParsingError(_) => {}
                _ => {
                    panic!("wrong error {}", err);
                }
            }
        }
    }
}
