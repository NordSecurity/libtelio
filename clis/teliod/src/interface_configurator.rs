use crate::TeliodError;
use serde::Deserialize;
use std::net::IpAddr;
use std::process::Command;
use tracing::{error, info};

pub trait InterfaceConfigurator {
    /// Configure the IP address and routes for a given interface
    fn set_ip(&self, _adapter_name: &str, _ip_address: &IpAddr) -> Result<(), TeliodError> {
        Ok(())
    }

    /// Helper function to execute a system command
    fn execute(&self, command: &mut Command) -> Result<(), TeliodError> {
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
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceConfigurationProvider {
    Manual,
    Ifconfig,
    Iproute,
}

impl InterfaceConfigurationProvider {
    /// Create a concrete instance of a configuration provider
    pub fn create(&self) -> Box<dyn InterfaceConfigurator> {
        info!("Creating interface config provider for {:?}", self);
        match self {
            Self::Manual => Box::new(ManualconfigProvider),
            Self::Ifconfig => Box::new(IfconfigProvider),
            Self::Iproute => Box::new(IprouteProvider),
        }
    }
}

/// Emmpty implementation for manual configuration
pub struct ManualconfigProvider;

impl InterfaceConfigurator for ManualconfigProvider {}

/// Implementation using `ifconfig`
pub struct IfconfigProvider;

impl InterfaceConfigurator for IfconfigProvider {
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
                self.execute(Command::new("ifconfig").args([
                    adapter_name,
                    ip_type,
                    &cidr_string,
                    &ip_string,
                ]))?;

                if ip_address.is_ipv4() {
                    self.execute(Command::new("route").args(["add", "100.64/10", &ip_string]))?;
                } else {
                    self.execute(Command::new("route").args([
                        "add",
                        "-inet6",
                        "fd74:656c:696f::/64",
                        &ip_string,
                    ]))?;
                }
            }
            _ => {
                self.execute(Command::new("ifconfig").args([adapter_name, ip_type, &cidr_string]))?;
            }
        }

        self.execute(Command::new("ifconfig").args([adapter_name, "mtu", "1420"]))?;
        self.execute(Command::new("ifconfig").args([adapter_name, "up"]))
    }
}

/// Implementation using `iproute2`
pub struct IprouteProvider;

impl InterfaceConfigurator for IprouteProvider {
    fn set_ip(&self, adapter_name: &str, ip_address: &IpAddr) -> Result<(), TeliodError> {
        let cidr_suffix = if ip_address.is_ipv4() { "/10" } else { "/64" };
        let cidr_string = format!("{}{}", ip_address, cidr_suffix);

        info!(
            "Assigning IP address for {} to {}",
            adapter_name, cidr_string
        );

        self.execute(Command::new("ip").args(["addr", "add", &cidr_string, "dev", adapter_name]))?;
        self.execute(Command::new("ip").args(["link", "set", "dev", adapter_name, "mtu", "1420"]))?;
        self.execute(Command::new("ip").args(["link", "set", "dev", adapter_name, "up"]))
    }
}
