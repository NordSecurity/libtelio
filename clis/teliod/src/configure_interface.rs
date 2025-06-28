use crate::TeliodError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, error, info};

pub trait ConfigureInterface {
    /// Initialize the interface
    fn initialize(&mut self) -> Result<(), TeliodError>;
    /// Configure the IP address and routes for a given interface
    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), TeliodError>;
    /// Configure routes for exit routing
    fn set_exit_routes(&mut self, exit_node: &IpAddr) -> Result<(), TeliodError>;
    /// Some of the configured routes are not cleared when the adapter is removed and must be removed manually
    fn cleanup_exit_routes(&mut self) -> Result<(), TeliodError>;
}

/// Helper function to execute a system command
fn execute(command: &mut Command) -> Result<(), TeliodError> {
    debug!("Executing command '{command:?}'");
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
    debug!("Executing command with output '{command:?}'");
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
    pub fn create(&self, adapter_name: String) -> Box<dyn ConfigureInterface> {
        info!("Creating interface config provider for {:?}", self);
        match self {
            Self::Manual => Box::new(Manual),
            Self::Ifconfig => Box::new(Ifconfig::new(adapter_name)),
            Self::Iproute => Box::new(Iproute::new(adapter_name)),
        }
    }
}

/// Empty implementation for manual configuration
#[derive(Debug, PartialEq, Eq)]
pub struct Manual;

impl ConfigureInterface for Manual {
    fn initialize(&mut self) -> Result<(), TeliodError> {
        Ok(()) // No-op implementaiton
    }

    fn set_ip(&mut self, _ip_address: &IpAddr) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }

    fn set_exit_routes(&mut self, _exit_node: &IpAddr) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }

    fn cleanup_exit_routes(&mut self) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }
}

/// Implementation using `ifconfig`
#[derive(Debug)]
pub struct Ifconfig {
    adapter_name: String,
}

impl Ifconfig {
    fn new(adapter_name: String) -> Self {
        Self { adapter_name }
    }
}

impl ConfigureInterface for Ifconfig {
    fn initialize(&mut self) -> Result<(), TeliodError> {
        execute(Command::new("ifconfig").args([&self.adapter_name, "mtu", "1420"]))?;
        execute(Command::new("ifconfig").args([&self.adapter_name, "up"]))
    }

    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), TeliodError> {
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
            self.adapter_name, cidr_string
        );

        match std::env::consts::OS {
            "macos" => {
                execute(Command::new("ifconfig").args([
                    &self.adapter_name,
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
                    &self.adapter_name,
                    "inet",
                    "add",
                    ip_address.to_string().as_str(),
                    "netmask",
                    "255.192.0.0",
                ]))?;
            }
        }
        Ok(())
    }

    fn set_exit_routes(&mut self, _exit_node: &IpAddr) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }

    fn cleanup_exit_routes(&mut self) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }
}

/// Implementation using `iproute2`
#[derive(Debug)]
pub struct Iproute {
    adapter_name: String,
    default_gateway_ipv4: Option<String>,
    exit_route_ip: Option<IpAddr>,
    ipv6_support_manager: Ipv6SupportManager,
}

impl Iproute {
    pub fn new(adapter_name: String) -> Self {
        Self {
            adapter_name,
            default_gateway_ipv4: Self::get_default_gateway("-4"),
            exit_route_ip: None,
            ipv6_support_manager: Ipv6SupportManager::default(),
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
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<u16>().ok())
                    .unwrap_or(0);
                let gateway = via_pattern
                    .captures(line)
                    .or(dev_pattern.captures(line))
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str());
                gateway.map(|gateway| (metric, gateway.to_owned()))
            })
            .min_by_key(|(m, _)| *m)
            .map(|(_, g)| g)
    }

    // Some ip commands will return "RNETLINK answers: File exists" which means that the command was already executed and we can ignore the error
    fn ignore_file_exists_error(res: Result<(), TeliodError>) -> Result<(), TeliodError> {
        match res {
            Err(TeliodError::SystemCommandFailed(message)) if message.contains("File exists") => {
                Ok(())
            }
            _ => res,
        }
    }
}

impl ConfigureInterface for Iproute {
    fn initialize(&mut self) -> Result<(), TeliodError> {
        execute(Command::new("ip").args([
            "link",
            "set",
            "dev",
            &self.adapter_name,
            "mtu",
            "1420",
        ]))?;
        execute(Command::new("ip").args(["link", "set", "dev", &self.adapter_name, "up"]))
    }

    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), TeliodError> {
        let cidr_suffix = if ip_address.is_ipv4() { "/10" } else { "/64" };
        let cidr_string = format!("{}{}", ip_address, cidr_suffix);

        info!(
            "Assigning IP address for {} to {}",
            self.adapter_name, cidr_string
        );
        Self::ignore_file_exists_error(execute(Command::new("ip").args([
            "addr",
            "add",
            &cidr_string,
            "dev",
            &self.adapter_name,
        ])))
    }

    fn set_exit_routes(&mut self, exit_node: &IpAddr) -> Result<(), TeliodError> {
        if exit_node.is_ipv4() {
            execute(Command::new("ip").args([
                "route",
                "add",
                "0.0.0.0/0",
                "dev",
                &self.adapter_name,
            ]))?;
            if let Some(gateway) = &self.default_gateway_ipv4 {
                Self::ignore_file_exists_error(execute(Command::new("ip").args([
                    "route",
                    "add",
                    exit_node.to_string().as_str(),
                    "via",
                    gateway.as_str(),
                ])))?;
            }
            self.exit_route_ip = Some(*exit_node);
            self.ipv6_support_manager.disable(&self.adapter_name)?;
            // We have already disabled IPv6 on all interfaces (except the tunnel interface)
            // but interfaces that get added later could still have IPv6 enabled.
            // As a backup solution we route all IPv6 packets into the tunnel
            execute(Command::new("ip").args([
                "-6",
                "route",
                "add",
                "default",
                "dev",
                &self.adapter_name,
            ]))?;
        }
        Ok(())
    }

    fn cleanup_exit_routes(&mut self) -> Result<(), TeliodError> {
        if let Some(exit_node) = self.exit_route_ip {
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
        self.ipv6_support_manager.reenable()
    }
}

/// This hold the initial IPv6 state of the machine, so that we can accurately re-enable
/// IPv6 support when disconnecting from VPN/exit node
/// For macos it holds the names of the interfaces where IPv6 was enabled
/// For linux we store the names of the interfaces along with if IPv6 was enabled. We need to store
/// the initial state for each interface here because setting the all.disable_ipv6 option affects
/// all interfaces and we need to know what value to set them to.
#[derive(Debug)]
enum InitialIpv6State {
    Macos { interfaces: Vec<String> },
    Linux { interfaces: Vec<(String, u8)> },
}

/// We don't have VPN servers that support IPv6 and IPv6 support in libtelio as a whole is not fully battle tested,
/// so for now we need to disable IPv6 while connected to VPN/exit node to prevent leaks.
///
/// Disabling of IPv6 is done in two steps:
/// 1. Disable IPv6 on all interfaces except the tunnel interface we create for libtelio.
///    On linux this includes setting the all.disable_ipv6 and default.disable_ipv6 options.
///    We leave IPv6 enabled on the tunnel interface so that we can do the next step.
/// 2. Setting the tunnel interface as the default route for IPv6 traffic.
///    Disabling IPv6 on all current interfaces doesn't help if a new interface is added with IPv6 enabled.
///    To get around this, the tunnel interface is set as the default route for IPv6 so that any potential IPv6
///    traffic goes into the tunnel and is then dropped there because we don't support it.
///
/// When disconnecting from VPN/exit node we need to restore IPv6 support to the state it was before.
/// This struct handles both those tasks.
#[derive(Debug, Default)]
struct Ipv6SupportManager {
    initial_state: Option<InitialIpv6State>,
}

impl Ipv6SupportManager {
    fn disable(&mut self, skip_interface: &str) -> Result<(), TeliodError> {
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
                let mut interfaces = execute_with_output(Command::new("sysctl").arg("--all"))?
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
                    Command::new("sysctl").args(["--values", "net.ipv6.conf.default.disable_ipv6"]),
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
                    execute(Command::new("sysctl").args(["--write", &cmd]))?;
                }

                InitialIpv6State::Linux { interfaces }
            }
        };
        self.initial_state = Some(initial_state);
        Ok(())
    }

    fn reenable(&mut self) -> Result<(), TeliodError> {
        let initial_state = self.initial_state.take();
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
                    execute(Command::new("sysctl").args(["--write", &sysctl_cmd]))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
