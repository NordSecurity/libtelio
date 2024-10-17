#[warn(missing_docs)]
#[cfg(any(not(windows), doc))]
#[cfg_attr(docsrs, doc(cfg(not(windows))))]
mod boring;

#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
mod linux_native_wg;

#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
mod wireguard_go;

#[cfg(any(windows, doc))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
mod windows_native_wg;

use async_trait::async_trait;
#[cfg(any(test, feature = "test-adapter"))]
pub use mockall::automock;
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc,
};
use telio_crypto::PublicKey;
use telio_sockets::{Protect, SocketPool};
use thiserror::Error as TError;

use crate::uapi::{self, Cmd, Response};

/// Function pointer to Firewall Callback
pub type FirewallCb = Option<Arc<dyn Fn(&[u8; 32], &[u8]) -> bool + Send + Sync>>;

/// Function pointer for reseting all the connections
pub type FirewallResetConnsCb =
    Option<Arc<dyn Fn(&PublicKey, Ipv4Addr, &mut dyn io::Write, &mut dyn io::Write) + Send + Sync>>;

/// Tunnel file descriptor
#[cfg(not(target_os = "windows"))]
#[cfg_attr(docsrs, doc(cfg(not(windows))))]
pub type Tun = std::os::unix::io::RawFd;
/// Tunnel file descriptor is unused on Windows, thus an empty type alias
#[cfg(target_os = "windows")]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub type Tun = ();

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

    /// Get WireGuard adapter file descriptor. Overridable
    fn get_wg_socket(&self, _ipv6: bool) -> Result<Option<i32>, Error> {
        Ok(None)
    }

    /// Disconnect all connected peer sockets
    async fn drop_connected_sockets(&self) {}

    /// Reset all the connections by injecting packets into the tunnel
    async fn inject_reset_packets(&self, _exit_pubkey: &PublicKey, _exit_ipv4_addr: Ipv4Addr) {}
}

/// Enumeration of `Error` types for `Adapter` struct
#[derive(Debug, TError)]
pub enum Error {
    /// Error types from BoringTun implementation
    #[cfg(not(windows))]
    #[error("BoringTun adapter error {0}")]
    BoringTun(#[from] boringtun::device::Error),

    /// Error types from Linux Native implementation
    #[cfg(target_os = "linux")]
    #[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
    #[error("LinuxNativeWg adapter error {0}")]
    LinuxNativeWg(#[from] linux_native_wg::Error),

    /// Error types from WireGuard Go implementation
    #[cfg(any(windows, doc))]
    #[cfg_attr(docsrs, doc(cfg(windows)))]
    #[error("WireguardGo adapter error {0}")]
    WireguardGo(#[from] wireguard_go::Error),

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
    #[error("Parsing AdapterType from string failed")]
    AdapterTypeParsingError,

    /// Internal Error
    #[error("Internal error: {0}")]
    InternalError(&'static str),
}

/// Enumeration of types for `Adapter` struct
#[derive(Debug, Copy, Clone)]
pub enum AdapterType {
    /// BoringTun
    BoringTun,
    /// Linux Native
    LinuxNativeWg,
    /// Wireguard Go
    WireguardGo,
    /// Windows Native
    WindowsNativeWg,
}

impl Default for AdapterType {
    fn default() -> Self {
        if cfg!(any(
            target_os = "ios",
            target_os = "tvos",
            target_os = "macos",
            target_os = "linux"
        )) {
            AdapterType::BoringTun
        } else {
            // TODO: Use AdapterType::WindowsNativeWg on Windows
            AdapterType::WireguardGo
        }
    }
}

impl FromStr for AdapterType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "boringtun" => Ok(AdapterType::BoringTun),
            "wireguard-go" => Ok(AdapterType::WireguardGo),
            "linux-native" => Ok(AdapterType::LinuxNativeWg),
            "wireguard-nt" => Ok(AdapterType::WindowsNativeWg),
            "" => Ok(AdapterType::default()),
            _ => Err(Error::AdapterTypeParsingError),
        }
    }
}

pub(crate) fn start(
    adapter: AdapterType,
    name: &str,
    tun: Option<Tun>,
    socket_pool: Arc<SocketPool>,
    firewall_process_inbound_callback: FirewallCb,
    firewall_process_outbound_callback: FirewallCb,
    firewall_reset_conns_callback: FirewallResetConnsCb,
) -> Result<Box<dyn Adapter>, Error> {
    #![allow(unused_variables)]

    match adapter {
        AdapterType::BoringTun => {
            #[cfg(windows)]
            return Err(Error::UnsupportedAdapter);

            #[cfg(unix)]
            Ok(Box::new(boring::BoringTun::start(
                name,
                tun,
                socket_pool,
                firewall_process_inbound_callback,
                firewall_process_outbound_callback,
                firewall_reset_conns_callback,
            )?))
        }
        AdapterType::LinuxNativeWg => {
            #[cfg(not(target_os = "linux"))]
            return Err(Error::UnsupportedAdapter);

            #[cfg(target_os = "linux")]
            Ok(Box::new(linux_native_wg::LinuxNativeWg::start(name, tun)?))
        }
        AdapterType::WireguardGo => {
            #[cfg(not(windows))]
            return Err(Error::UnsupportedAdapter);

            #[cfg(windows)]
            Ok(Box::new(wireguard_go::WireguardGo::start(name, tun)?))
        }
        AdapterType::WindowsNativeWg => {
            #[cfg(not(windows))]
            return Err(Error::UnsupportedAdapter);

            #[cfg(windows)]
            Ok(Box::new(windows_native_wg::WindowsNativeWg::start(
                name, tun,
            )?))
        }
    }
}
