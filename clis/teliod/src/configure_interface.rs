use crate::TeliodError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::{net::IpAddr, str::FromStr};
use tracing::{debug, error, info};

pub trait ConfigureInterface {
    /// Initialize the interface
    fn initialize(&self, adapter_name: &str) -> Result<(), TeliodError>;
    /// Configure the IP address and routes for a given interface
    fn set_ip(&self, adapter_name: &str, ip_address: &IpAddr) -> Result<(), TeliodError>;
    /// Configure routes for exit routing
    fn set_exit_routes(&self, adapter_name: &str, exit_node: &IpAddr) -> Result<(), TeliodError>;
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

#[derive(Default, Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
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
            Self::Ifconfig => Box::new(Ifconfig::new()),
            Self::Iproute => Box::new(Iproute::new()),
        }
    }
}

/// Empty implementation for manual configuration
#[derive(Debug, PartialEq, Eq)]
pub struct Manual;

impl ConfigureInterface for Manual {
    fn initialize(&self, _adapter_name: &str) -> Result<(), TeliodError> {
        Ok(()) // No-op implementaiton
    }

    fn set_ip(&self, _adapter_name: &str, _ip_address: &IpAddr) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }

    fn set_exit_routes(&self, _adapter_name: &str, _exit_node: &IpAddr) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }
}

/// Implementation using `ifconfig`
#[derive(Debug, PartialEq, Eq)]
pub struct Ifconfig {
    default_gateway_ipv4: Option<IpAddr>,
    default_gateway_ipv6: Option<IpAddr>,
}

impl Ifconfig {
    pub fn new() -> Self {
        Self {
            default_gateway_ipv4: Self::get_default_gateway("inet"),
            default_gateway_ipv6: Self::get_default_gateway("inet6"),
        }
    }

    fn get_default_gateway(family: &str) -> Option<IpAddr> {
        let output = Command::new("netstat")
            .args(["-nr", "-f", family])
            .output()
            .inspect_err(|e| {
                error!("failed to execute netstat: {e}");
            })
            .ok()?;

        if !output.status.success() {
            error!("netstat failed for {}: {}", family, output.status);
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 {
                continue;
            }

            let destination = fields[0];
            let gateway = fields[1];

            if destination == "default" && !gateway.starts_with("link#") {
                debug!("default gateway for {}: {}", family, gateway);
                return IpAddr::from_str(gateway).ok();
            }
        }

        None
    }
}

impl ConfigureInterface for Ifconfig {
    fn initialize(&self, adapter_name: &str) -> Result<(), TeliodError> {
        execute(Command::new("ifconfig").args([adapter_name, "mtu", "1420"]))?;
        execute(Command::new("ifconfig").args([adapter_name, "up"]))
    }

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
                    execute(Command::new("route").args(["-n", "add", "100.64/10", &ip_string]))?;
                } else {
                    execute(Command::new("route").args([
                        "add",
                        "-n",
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
        Ok(())
    }

    fn set_exit_routes(&self, adapter_name: &str, exit_node: &IpAddr) -> Result<(), TeliodError> {
        if exit_node.is_ipv4() {
            execute(Command::new("route").args(["-n", "add", "-inet", "0.0.0.0/1", adapter_name]))?;
            execute(Command::new("route").args([
                "-n",
                "add",
                "-inet",
                "128.0.0.0/1",
                adapter_name,
            ]))?;

            let gateway = self.default_gateway_ipv4.unwrap().to_string();
            execute(Command::new("route").args([
                "-n",
                "add",
                "-inet",
                exit_node.to_string().as_str(),
                "-gateway",
                &gateway,
            ]))?;
        }
        Ok(())
    }
}

/// Implementation using `iproute2`
#[derive(Debug, PartialEq, Eq)]
pub struct Iproute {
    default_gateway_ipv4: Option<String>,
    default_gateway_ipv6: Option<String>,
}

impl Iproute {
    pub fn new() -> Self {
        Self {
            default_gateway_ipv4: Self::get_default_gateway("-4"),
            default_gateway_ipv6: Self::get_default_gateway("-6"),
        }
    }

    fn get_default_gateway(family: &str) -> Option<String> {
        let output = Command::new("ip")
            .args([family, "route", "show", "default"])
            .output()
            .inspect_err(|e| {
                error!("failed to execute ip command: {e}");
            })
            .ok()?;

        if !output.status.success() {
            error!("ip command failed for {}: {}", family, output.status);
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        let metric_pattern = Regex::new("metric ([0-9]+)").expect("Failed to compile metric regex");
        let via_pattern = Regex::new("via ([0-9\\.\\/]+)").expect("Failed to compile via regex");
        let dev_pattern = Regex::new("dev ([A-Za-z0-9]+)").expect("Failed to compile dev regex");

        stdout
            .lines()
            .filter_map(|line| {
                let metric = metric_pattern
                    .find(line)
                    .and_then(|m| m.as_str().split_whitespace().nth(1))
                    .and_then(|m| m.parse::<u16>().ok())
                    .unwrap_or(0);
                let gateway = via_pattern
                    .find(line)
                    .or(dev_pattern.find(line))
                    .and_then(|m| m.as_str().split_whitespace().nth(1));
                gateway.map(|gateway| (metric, gateway.to_owned()))
            })
            .min_by_key(|(m, _)| *m)
            .map(|(_, g)| g)
    }
}

impl ConfigureInterface for Iproute {
    fn initialize(&self, adapter_name: &str) -> Result<(), TeliodError> {
        execute(Command::new("ip").args(["link", "set", "dev", adapter_name, "mtu", "1420"]))?;
        execute(Command::new("ip").args(["link", "set", "dev", adapter_name, "up"]))
    }

    fn set_ip(&self, adapter_name: &str, ip_address: &IpAddr) -> Result<(), TeliodError> {
        let cidr_suffix = if ip_address.is_ipv4() { "/10" } else { "/64" };
        let cidr_string = format!("{}{}", ip_address, cidr_suffix);

        info!(
            "Assigning IP address for {} to {}",
            adapter_name, cidr_string
        );
        execute(Command::new("ip").args(["addr", "add", &cidr_string, "dev", adapter_name]))
    }

    fn set_exit_routes(&self, adapter_name: &str, exit_node: &IpAddr) -> Result<(), TeliodError> {
        if exit_node.is_ipv4() {
            execute(Command::new("ip").args([
                "route",
                "add",
                "0.0.0.0/0",
                "dev",
                adapter_name,
                "metric",
                u16::MAX.to_string().as_str(), // Setting a high metric forces this route to take precedence over existing default routes
            ]))?;

            let gateway = self.default_gateway_ipv4.as_deref().unwrap_or("");
            execute(Command::new("ip").args([
                "route",
                "add",
                exit_node.to_string().as_str(),
                "via",
                gateway,
            ]))?;
        }
        Ok(())
    }
}
