use crate::TeliodError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
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
    /// Some of the configured routes are not cleared when the adapter is removed and must be removed manually
    fn cleanup_exit_routes(&self) -> Result<(), TeliodError>;
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

/// Helper function to execute a system command with output
fn execute_with_output(command: &mut Command) -> Result<String, TeliodError> {
    let output = command
        .output()
        .map_err(|e| TeliodError::SystemCommandFailed(e.to_string()))?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .map_err(|e| TeliodError::SystemCommandFailed(e.to_string()))
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

    fn cleanup_exit_routes(&self) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }
}

/// Implementation using `ifconfig`
#[derive(Debug)]
pub struct Ifconfig {
    default_gateway_ipv4: Option<IpAddr>,
    exit_route_ip: Cell<Option<IpAddr>>,
    ipv6_disabler: Ipv6Disabler,
}

impl Ifconfig {
    pub fn new() -> Self {
        Self {
            default_gateway_ipv4: Self::get_default_gateway("inet"),
            exit_route_ip: Cell::new(None),
            ipv6_disabler: Ipv6Disabler::default(),
        }
    }

    #[allow(index_access_check)]
    fn get_default_gateway(family: &str) -> Option<IpAddr> {
        let stdout =
            execute_with_output(Command::new("netstat").args(["-nr", "-f", family])).ok()?;
        for line in stdout.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 {
                continue;
            }

            let destination = fields[0];
            let gateway = fields[1];

            if (destination == "default" || destination == "0.0.0.0")
                && !gateway.starts_with("link#")
            {
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
                execute(Command::new("ifconfig").args([
                    adapter_name,
                    "inet",
                    "add",
                    ip_address.to_string().as_str(),
                    "netmask",
                    "255.255.0.0",
                ]))?;
            }
        }
        Ok(())
    }

    fn set_exit_routes(&self, adapter_name: &str, exit_node: &IpAddr) -> Result<(), TeliodError> {
        if exit_node.is_ipv4() {
            match std::env::consts::OS {
                "macos" => {
                    execute(Command::new("ifconfig").args([adapter_name, "add", "10.5.0.1/32"]))?;
                    execute(Command::new("route").args([
                        "-n",
                        "add",
                        "-inet",
                        "0.0.0.0/1",
                        adapter_name,
                    ]))?;
                    execute(Command::new("route").args([
                        "-n",
                        "add",
                        "-inet",
                        "128.0.0.0/1",
                        adapter_name,
                    ]))?;

                    if let Some(gateway) = &self.default_gateway_ipv4 {
                        execute(Command::new("route").args([
                            "-n",
                            "add",
                            "-inet",
                            exit_node.to_string().as_str(),
                            "-gateway",
                            gateway.to_string().as_str(),
                        ]))?;
                    }
                    // We later disable IPv6 on all interfaces (except the tunnel interface)
                    // but interfaces that get added later could still have IPv6 enabled.
                    // As a backup solution we route all IPv6 packets into the tunnel
                    execute(Command::new("route").args([
                        "-n",
                        "add",
                        "-inet6",
                        "default",
                        "-interface",
                        adapter_name,
                    ]))?;
                }
                _ => {
                    execute(Command::new("ifconfig").args([
                        adapter_name,
                        "inet",
                        "10.5.0.1",
                        "netmask",
                        "255.255.255.255",
                    ]))?;
                    execute(Command::new("route").args(["delete", "default"]))?;
                    execute(Command::new("route").args([
                        "add",
                        "default",
                        "gw",
                        "10.5.0.1",
                        adapter_name,
                    ]))?;
                    if let Some(gateway) = &self.default_gateway_ipv4 {
                        execute(Command::new("route").args([
                            "-4",
                            "add",
                            exit_node.to_string().as_str(),
                            "gw",
                            gateway.to_string().as_str(),
                        ]))?;
                    }
                    // We later disable IPv6 on all interfaces (except the tunnel interface)
                    // but interfaces that get added later could still have IPv6 enabled.
                    // As a backup solution we route all IPv6 packets into the tunnel
                    execute(Command::new("route").args([
                        "-6",
                        "add",
                        "::/128",
                        "dev",
                        adapter_name,
                    ]))?;
                }
            }
            self.exit_route_ip.set(Some(*exit_node));
            self.ipv6_disabler.disable(adapter_name)?;
        }
        Ok(())
    }

    fn cleanup_exit_routes(&self) -> Result<(), TeliodError> {
        if let Some(exit_node) = self.exit_route_ip.get() {
            match std::env::consts::OS {
                "macos" => {
                    execute(Command::new("route").args([
                        "delete",
                        "-inet",
                        exit_node.to_string().as_str(),
                    ]))?;
                }
                _ => {
                    execute(
                        Command::new("route").args(["delete", exit_node.to_string().as_str()]),
                    )?;
                }
            }
        }
        self.ipv6_disabler.reenable()
    }
}

/// Implementation using `iproute2`
#[derive(Debug)]
pub struct Iproute {
    default_gateway_ipv4: Option<String>,
    exit_route_ip: Cell<Option<IpAddr>>,
    ipv6_disabler: Ipv6Disabler,
}

impl Iproute {
    pub fn new() -> Self {
        Self {
            default_gateway_ipv4: Self::get_default_gateway("-4"),
            exit_route_ip: Cell::new(None),
            ipv6_disabler: Ipv6Disabler::default(),
        }
    }

    #[allow(clippy::expect_used)]
    fn get_default_gateway(family: &str) -> Option<String> {
        let metric_pattern = Regex::new("metric ([0-9]+)").expect("Failed to compile metric regex");
        let via_pattern = Regex::new("via ([0-9\\.\\/]+)").expect("Failed to compile via regex");
        let dev_pattern = Regex::new("dev ([A-Za-z0-9]+)").expect("Failed to compile dev regex");

        let stdout =
            execute_with_output(Command::new("ip").args([family, "route", "show", "default"]))
                .ok()?;
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
            execute(Command::new("ip").args(["addr", "add", "10.5.0.1", "dev", adapter_name]))?;
            execute(Command::new("ip").args(["route", "add", "0.0.0.0/0", "dev", adapter_name]))?;
            if let Some(gateway) = &self.default_gateway_ipv4 {
                execute(Command::new("ip").args([
                    "route",
                    "add",
                    exit_node.to_string().as_str(),
                    "via",
                    gateway.as_str(),
                ]))?;
            }
            self.exit_route_ip.set(Some(*exit_node));
            self.ipv6_disabler.disable(adapter_name)?;
            // We have already disabled IPv6 on all interfaces (except the tunnel interface)
            // but interfaces that get added later could still have IPv6 enabled.
            // As a backup solution we route all IPv6 packets into the tunnel
            execute(Command::new("ip").args([
                "-6",
                "route",
                "add",
                "default",
                "dev",
                adapter_name,
            ]))?;
        }
        Ok(())
    }

    fn cleanup_exit_routes(&self) -> Result<(), TeliodError> {
        if let Some(exit_node) = self.exit_route_ip.get() {
            if let Some(gateway) = &self.default_gateway_ipv4 {
                execute(Command::new("ip").args([
                    "route",
                    "del",
                    exit_node.to_string().as_str(),
                    "via",
                    gateway.as_str(),
                ]))?;
            }
        }
        self.ipv6_disabler.reenable()
    }
}

#[derive(Debug)]
enum InitialIpv6State {
    Macos { interfaces: Vec<String> },
    Linux { interfaces: Vec<(String, u8)> },
}

#[derive(Debug, Default)]
struct Ipv6Disabler {
    initial_state: RefCell<Option<InitialIpv6State>>,
}

impl Ipv6Disabler {
    fn disable(&self, skip_interface: &str) -> Result<(), TeliodError> {
        let initial_state = match std::env::consts::OS {
            "macos" => {
                let interfaces = execute_with_output(
                    Command::new("networksetup").args(["-listallnetworkservices"]),
                )?;
                let mut previously_enabled = Vec::new();
                for interface in interfaces
                    .lines()
                    .skip(1)
                    .filter(|i| !i.starts_with('*') && *i != skip_interface)
                {
                    let interface_info = execute_with_output(
                        Command::new("networksetup").args(["-getinfo", interface]),
                    )?;
                    let ipv6_enabled = interface_info.contains("IPv6: Automatic")
                        || interface_info.contains("IPv6: On");

                    if ipv6_enabled {
                        previously_enabled.push(interface.to_string());

                        // Disable IPv6 for this service
                        execute(Command::new("networksetup").args(["-setv6off", interface]))?;
                    }
                }

                InitialIpv6State::Macos {
                    interfaces: previously_enabled,
                }
            }
            _ => {
                #[allow(clippy::expect_used)]
                let sysctl_regex =
                    Regex::new("net\\.ipv6\\.conf\\.(\\S*)\\.disable_ipv6\\s*=\\s*(0|1)")
                        .expect("Failed to compile sysctl regex");
                let mut interfaces = execute_with_output(Command::new("sysctl").arg("-a"))?
                    .lines()
                    .filter_map(|l| {
                        let vals = sysctl_regex.captures(l).map(|c| {
                            (
                                c.get(1).map(|m| m.as_str()),
                                c.get(2).and_then(|m| m.as_str().parse::<u8>().ok()),
                            )
                        });
                        match vals {
                            Some((Some(interface), Some(value))) => {
                                Some((interface.to_owned(), value))
                            }
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>();

                let ipv6_default_status = execute_with_output(
                    Command::new("sysctl").args(["-n", "net.ipv6.conf.default.disable_ipv6"]),
                )?;
                let ipv6_default_status = ipv6_default_status.trim().parse::<u8>().unwrap_or(0);
                interfaces.insert(0, ("default".to_owned(), ipv6_default_status));

                for (interface, _) in &interfaces {
                    let val = if interface.as_str() == skip_interface {
                        0
                    } else {
                        1
                    };
                    let cmd = format!("net.ipv6.conf.{interface}.disable_ipv6={val}");
                    execute(Command::new("sysctl").args(["-w", &cmd]))?;
                }

                InitialIpv6State::Linux { interfaces }
            }
        };
        self.initial_state.replace(Some(initial_state));
        Ok(())
    }

    fn reenable(&self) -> Result<(), TeliodError> {
        let initial_state = self.initial_state.borrow_mut().take();
        match initial_state {
            Some(InitialIpv6State::Macos { interfaces }) => {
                for interface in interfaces {
                    let _ =
                        execute(Command::new("networksetup").args(["-setv6automatic", &interface]));
                }
            }
            Some(InitialIpv6State::Linux { interfaces }) => {
                for (interface, value) in interfaces {
                    let sysctl_cmd = format!("net.ipv6.conf.{interface}.disable_ipv6={value}");
                    execute(Command::new("sysctl").args(["-w", &sysctl_cmd]))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
