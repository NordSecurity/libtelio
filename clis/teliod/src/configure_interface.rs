use crate::TeliodError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use tracing::{error, info};

pub trait ConfigureInterface {
    /// Configure the IP address and routes for a given interface
    fn set_ip(&self, _adapter_name: &str, _ip_address: &IpAddr) -> Result<(), TeliodError>;
}

/// Helper function to execute a system command
fn execute(command: &mut Command) -> Result<(), TeliodError> {
    let output = command
        .output()
        .map_err(|e| TeliodError::SystemCommandFailed(e.to_string()))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Error executing command {:?}: {:?}", command, stderr);
        Err(TeliodError::SystemCommandFailed(stderr.into()))
    }
}

#[derive(Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceConfigurationProvider {
    #[default]
    Manual,
    Ifconfig,
    Iproute,
}

// TODO(tomasz-grz): Try using enum_dispatch instead of dynamic dyspatch
impl InterfaceConfigurationProvider {
    /// Create a dynamic instance of a configuration provider
    pub fn create(&self) -> Box<dyn ConfigureInterface> {
        info!("Creating interface config provider for {:?}", self);
        match self {
            Self::Manual => Box::new(Manual),
            Self::Ifconfig => Box::new(Ifconfig),
            Self::Iproute => Box::new(Iproute),
        }
    }
}

/// Empty implementation for manual configuration
#[derive(Debug, PartialEq, Eq)]
pub struct Manual;

impl ConfigureInterface for Manual {
    fn set_ip(&self, _adapter_name: &str, _ip_address: &IpAddr) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }
}

/// Implementation using `ifconfig`
#[derive(Debug, PartialEq, Eq)]
pub struct Ifconfig;

impl ConfigureInterface for Ifconfig {
    fn set_ip(&self, adapter_name: &str, ip_address: &IpAddr) -> Result<(), TeliodError> {
        let ip_string = ip_address.to_string();
        let cidr_suffix = if ip_address.is_ipv4() { "/10" } else { "/64" };
        let cidr_string = format!("{}{}", ip_string, cidr_suffix);
        let ip_type = if ip_address.is_ipv4() {
            "inet"
        } else {
            "inet6"
        };

        info!(
            "Assigning IP address for {} to {}",
            adapter_name, cidr_string
        );

        match std::env::consts::OS {
            "macos" => {
                execute(Command::new("ifconfig").args([
                    adapter_name,
                    ip_type,
                    &cidr_string,
                    &ip_string,
                ]))?;

                if ip_address.is_ipv4() {
                    execute(Command::new("route").args(["add", "100.64/10", &ip_string]))?;
                } else {
                    execute(Command::new("route").args([
                        "add",
                        "-inet6",
                        "fd74:656c:696f::/64",
                        &ip_string,
                    ]))?;
                }
            }
            _ => {
                execute(Command::new("ifconfig").args([adapter_name, ip_type, &cidr_string]))?;
            }
        }

        execute(Command::new("ifconfig").args([adapter_name, "mtu", "1420"]))?;
        execute(Command::new("ifconfig").args([adapter_name, "up"]))
    }
}

/// Implementation using `iproute2`
#[derive(Debug, PartialEq, Eq)]
pub struct Iproute;

impl ConfigureInterface for Iproute {
    fn set_ip(&self, adapter_name: &str, ip_address: &IpAddr) -> Result<(), TeliodError> {
        let cidr_suffix = if ip_address.is_ipv4() { "/10" } else { "/64" };
        let cidr_string = format!("{}{}", ip_address, cidr_suffix);

        info!(
            "Assigning IP address for {} to {}",
            adapter_name, cidr_string
        );

        execute(Command::new("ip").args(["addr", "add", &cidr_string, "dev", adapter_name]))?;
        execute(Command::new("ip").args(["link", "set", "dev", adapter_name, "mtu", "1420"]))?;
        execute(Command::new("ip").args(["link", "set", "dev", adapter_name, "up"]))
    }
}
