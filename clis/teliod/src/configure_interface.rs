use crate::TeliodError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, error, info};

#[cfg(target_os = "linux")]
use telio::telio_utils::LIBTELIO_FWMARK;

// Copied from NordVPN Linux app
const DEFAULT_ROUTING_TABLE_ID: u32 = 205;

pub trait ConfigureInterface {
    /// Initialize the interface
    fn initialize(&mut self) -> Result<(), TeliodError>;
    /// Configure the IP address and routes for a given interface
    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), TeliodError>;
    /// Configure routes for exit routing
    fn set_exit_routes(&mut self, exit_node: &IpAddr) -> Result<(), TeliodError>;
    /// Some of the configured routes are not cleared when the adapter is removed and must be removed manually
    fn cleanup_exit_routes(&mut self) -> Result<(), TeliodError>;
    /// Manually cleanup the interface before the adapter is removed
    fn cleanup_interface(&mut self) -> Result<(), TeliodError> {
        Ok(()) // No-op implementation
    }
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
    Uci,
}

// TODO(tomasz-grz): Try using enum_dispatch instead of dynamic dyspatch
impl InterfaceConfigurationProvider {
    /// Create a dynamic instance of a configuration provider
    pub fn create(&self, interface_name: String) -> Box<dyn ConfigureInterface> {
        info!("Creating interface config provider for {:?}", self);
        match self {
            Self::Manual => Box::new(Manual),
            Self::Ifconfig => Box::new(Ifconfig::new(interface_name)),
            Self::Iproute => Box::new(Iproute::new(interface_name)),
            Self::Uci => Box::new(Uci::new(interface_name)),
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
    interface_name: String,
}

impl Ifconfig {
    fn new(interface_name: String) -> Self {
        Self { interface_name }
    }
}

impl ConfigureInterface for Ifconfig {
    fn initialize(&mut self) -> Result<(), TeliodError> {
        execute(Command::new("ifconfig").args([&self.interface_name, "mtu", "1420"]))?;
        execute(Command::new("ifconfig").args([&self.interface_name, "up"]))
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
            self.interface_name, cidr_string
        );

        match std::env::consts::OS {
            "macos" => {
                execute(Command::new("ifconfig").args([
                    &self.interface_name,
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
                    &self.interface_name,
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
    interface_name: String,
    table: Option<String>,
    fw_rule_prio: Option<String>,
    ipv6_support_manager: Ipv6SupportManager,
}

impl Iproute {
    pub fn new(interface_name: String) -> Self {
        Self {
            interface_name,
            table: None,
            fw_rule_prio: None,
            ipv6_support_manager: Ipv6SupportManager::default(),
        }
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

    // Based on the implementation from the NordVPN Linux app
    // When setting routing information on linux we set a default route on a custom routing table
    // and an IP rule to make sure that the correct packets go through that table.
    #[allow(clippy::expect_used)]
    pub fn find_available_table() -> Result<u32, TeliodError> {
        let table_pattern = Regex::new("table ([0-9]+)").expect("Failed to compile ip table regex");
        let mut existing =
            execute_with_output(Command::new("ip").args(["route", "show", "table", "all"]))?
                .lines()
                .filter_map(|line| {
                    table_pattern
                        .captures(line)
                        .and_then(|c| c.get(1))
                        .and_then(|m| m.as_str().parse::<u32>().ok())
                })
                .collect::<Vec<_>>();
        existing.sort_unstable();
        existing.dedup();

        // Find first available table ID starting from default
        for table_id in DEFAULT_ROUTING_TABLE_ID..=60_000 {
            if !existing.contains(&table_id) {
                return Ok(table_id);
            }
        }
        Err(TeliodError::IpRoute)
    }

    // Based on the implementation from the NordVPN Linux app
    // Finds the main rule priority and the list of assigned priorities
    fn find_main_and_assigned_rule_priorities() -> Result<(u32, Vec<u32>), TeliodError> {
        let mut main_prio = 0;
        let existing_prios = execute_with_output(Command::new("ip").args(["rule", "list"]))?
            .lines()
            .filter_map(|line| {
                let prio = line
                    .split_once(':')
                    .and_then(|(prio, _)| prio.parse::<u32>().ok());
                if let Some(prio) = prio {
                    if line.contains("from all lookup main") {
                        main_prio = prio;
                    }
                }
                prio
            })
            .collect::<Vec<_>>();
        Ok((main_prio, existing_prios))
    }

    // Iterate over existing_prios until we find the next available lower priority
    fn find_available_lower_rule_priority() -> Result<u32, TeliodError> {
        let (start_prio, existing_prios) = Self::find_main_and_assigned_rule_priorities()?;
        for prio in (1..start_prio).rev() {
            if !existing_prios.contains(&prio) {
                return Ok(prio);
            }
        }
        Err(TeliodError::IpRule)
    }

    // Iterate over existing_prios until we find the number of available lower priorities
    pub fn find_available_lower_rule_priorities(count: usize) -> Result<Vec<u32>, TeliodError> {
        let (start_prio, existing_prios) = Self::find_main_and_assigned_rule_priorities()?;
        let available_prios: Vec<u32> = (1..start_prio)
            .rev()
            .filter(|prio| !existing_prios.contains(prio))
            .take(count)
            .collect();

        if available_prios.len() == count {
            Ok(available_prios)
        } else {
            Err(TeliodError::IpRule)
        }
    }
}

impl ConfigureInterface for Iproute {
    fn initialize(&mut self) -> Result<(), TeliodError> {
        execute(Command::new("ip").args([
            "link",
            "set",
            "dev",
            &self.interface_name,
            "mtu",
            "1420",
        ]))?;
        execute(Command::new("ip").args(["link", "set", "dev", &self.interface_name, "up"]))
    }

    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), TeliodError> {
        let cidr_suffix = if ip_address.is_ipv4() { "/10" } else { "/64" };
        let cidr_string = format!("{}{}", ip_address, cidr_suffix);

        info!(
            "Assigning IP address for {} to {}",
            self.interface_name, cidr_string
        );
        Self::ignore_file_exists_error(execute(Command::new("ip").args([
            "addr",
            "add",
            &cidr_string,
            "dev",
            &self.interface_name,
        ])))
    }

    fn set_exit_routes(&mut self, exit_node: &IpAddr) -> Result<(), TeliodError> {
        #[cfg(target_os = "linux")]
        if exit_node.is_ipv4() {
            let table = Self::find_available_table()?.to_string();
            let fw_rule_prio = Self::find_available_lower_rule_priority()?.to_string();

            execute(Command::new("ip").args([
                "route",
                "add",
                "0.0.0.0/0",
                "dev",
                &self.interface_name,
                "table",
                &table,
            ]))?;
            execute(Command::new("ip").args([
                "rule",
                "add",
                "priority",
                &fw_rule_prio,
                "not",
                "from",
                "all",
                "fwmark",
                &LIBTELIO_FWMARK.to_string(),
                "lookup",
                &table,
            ]))?;
            self.table = Some(table);
            self.fw_rule_prio = Some(fw_rule_prio);

            self.ipv6_support_manager.disable(&self.interface_name)?;
            // We have already disabled IPv6 on all interfaces (except the tunnel interface)
            // but interfaces that get added later could still have IPv6 enabled.
            // As a backup solution we route all IPv6 packets into the tunnel
            execute(Command::new("ip").args([
                "-6",
                "route",
                "add",
                "default",
                "dev",
                &self.interface_name,
            ]))?;
        }
        Ok(())
    }

    fn cleanup_exit_routes(&mut self) -> Result<(), TeliodError> {
        if let Some(fw_rule_prio) = &self.fw_rule_prio {
            execute(Command::new("ip").args(["rule", "del", "priority", fw_rule_prio]))?;
        }
        if let Some(table) = &self.table {
            execute(Command::new("ip").args(["route", "flush", "table", table]))?;
        }
        self.ipv6_support_manager.reenable()
    }
}

/// Implementation using `uci` for OpenWRT devices
#[derive(Debug)]
pub struct Uci {
    interface_name: String,
    ipv6_enabled: Option<bool>,
    wan6_disabled: Option<bool>,
}

impl Uci {
    fn new(interface_name: String) -> Self {
        let wan6_disabled = execute(Command::new("uci").args(["get", "network.wan6"]))
            .ok()
            .and_then(|_| {
                execute_with_output(Command::new("uci").args(["get", "network.wan6.disabled"]))
                    .map(|res| res.contains("1"))
                    .ok()
            });

        let ipv6_enabled = execute(Command::new("uci").args(["get", "network.wan"]))
            .ok()
            .map(|_| {
                execute_with_output(Command::new("uci").args(["get", "network.wan.ipv6"]))
                    .map(|res| res.contains("1"))
                    .unwrap_or(true) // Assume ipv6 enabled by default
            });

        Self {
            interface_name,
            ipv6_enabled,
            wan6_disabled,
        }
    }

    // Helper to disable IPv6
    fn disable_ipv6(&self) -> Result<(), TeliodError> {
        if self.wan6_disabled.is_some() {
            execute(Command::new("uci").args(["set", "network.wan6.disabled=1"]))?;
        }
        if self.ipv6_enabled.is_some() {
            execute(Command::new("uci").args(["set", "network.wan.ipv6=0"]))?;
        }
        Ok(())
    }

    // Helper to restore settings IPv6 to initial state
    fn restore_ipv6(&self) -> Result<(), TeliodError> {
        if let Err(e) = execute(Command::new("uci").args(["del", "network.teliod_route6"])) {
            error!("Error removing route6: {e}");
        }

        if let Some(disabled) = self.wan6_disabled {
            if !disabled {
                if let Err(e) = execute(Command::new("uci").args(["del", "network.wan6.disabled"]))
                {
                    error!("Error removing wan6 disabled: {e}");
                }
            }
        }
        if let Some(enabled) = self.ipv6_enabled {
            if enabled {
                if let Err(e) = execute(Command::new("uci").args(["del", "network.wan.ipv6"])) {
                    error!("Error removing wan ipv6: {e}");
                }
            }
        }

        Ok(())
    }

    // Helper to reload network service
    fn reload_network(&self) -> Result<(), TeliodError> {
        execute(Command::new("uci").args(["commit", "network"]))?;
        execute(Command::new("/etc/init.d/network").args(["reload"]))?;
        Ok(())
    }

    // Helper to reload firewall service
    fn reload_firewall(&self) -> Result<(), TeliodError> {
        execute(Command::new("uci").args(["commit", "firewall"]))?;
        execute(Command::new("/etc/init.d/firewall").args(["reload"]))?;
        Ok(())
    }
}

impl ConfigureInterface for Uci {
    fn initialize(&mut self) -> Result<(), TeliodError> {
        // add new interface if not present
        match execute(Command::new("uci").args(["get", "network.tun"])) {
            Ok(()) => {
                debug!("interface present");
            }
            Err(_) => {
                debug!("adding new interface");
                execute(Command::new("uci").args(["add", "network", "interface"]))?;
                execute(Command::new("uci").args(["rename", "network.@interface[-1]=tun"]))?;
            }
        }
        execute(Command::new("uci").args(["set", "network.tun.mtu=1420"]))?;

        Ok(())
    }

    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), TeliodError> {
        info!(
            "Assigning IP address for {} to {}",
            self.interface_name, ip_address
        );

        // set options
        execute(Command::new("uci").args([
            "set",
            &format!("network.tun.device={}", self.interface_name),
        ]))?;
        execute(Command::new("uci").args(["set", "network.tun.proto=static"]))?;
        execute(Command::new("uci").args(["set", &format!("network.tun.ipaddr={ip_address}")]))?;
        execute(Command::new("uci").args(["set", "network.tun.netmask=255.192.0.0"]))?;

        // save and apply
        self.reload_network()?;

        Ok(())
    }

    fn set_exit_routes(&mut self, _exit_node: &IpAddr) -> Result<(), TeliodError> {
        let table = Iproute::find_available_table()?;
        let (vpn_rule_prio, lan_rule_prio) = {
            let priorities = Iproute::find_available_lower_rule_priorities(2)?;
            // this is ok because find_available_lower_rule_priorities()
            // returns an error on wrong size
            #[allow(index_access_check)]
            (priorities[0], priorities[1])
        };

        // Set route and rules for VPN
        execute(Command::new("uci").args(["add", "network", "route"]))?;
        execute(Command::new("uci").args(["rename", "network.@route[-1]=teliod_route"]))?;
        execute(Command::new("uci").args(["set", "network.teliod_route.interface=tun"]))?;
        execute(Command::new("uci").args(["set", "network.teliod_route.target=0.0.0.0/0"]))?;
        execute(
            Command::new("uci").args(["set", &format!("network.teliod_route.table={}", table)]),
        )?;

        execute(Command::new("uci").args(["add", "network", "route6"]))?;
        execute(Command::new("uci").args(["rename", "network.@route6[-1]=teliod_route6"]))?;
        execute(Command::new("uci").args(["set", "network.teliod_route6.interface=tun"]))?;
        execute(Command::new("uci").args(["set", "network.teliod_route6.target=::/0"]))?;

        execute(Command::new("uci").args(["add", "network", "rule"]))?;
        execute(Command::new("uci").args(["rename", "network.@rule[-1]=teliod_vpn_rule"]))?;
        execute(
            Command::new("uci").args(["set", &format!("network.teliod_vpn_rule.lookup={}", table)]),
        )?;
        #[cfg(target_os = "linux")] // LIBTELIO_FWMARK is compile flagged
        execute(Command::new("uci").args([
            "set",
            &format!("network.teliod_vpn_rule.mark={LIBTELIO_FWMARK}"),
        ]))?;
        execute(Command::new("uci").args([
            "set",
            &format!("network.teliod_vpn_rule.priority={}", vpn_rule_prio),
        ]))?;
        execute(Command::new("uci").args(["set", "network.teliod_vpn_rule.invert=1"]))?;
        execute(Command::new("uci").args(["set", "network.teliod_vpn_rule.src=0.0.0.0/0"]))?;

        // Exception for LAN traffic accessing Gateway
        execute(Command::new("uci").args(["add", "network", "rule"]))?;
        execute(Command::new("uci").args(["rename", "network.@rule[-1]=teliod_lan_rule"]))?;
        execute(Command::new("uci").args(["set", "network.teliod_lan_rule.src=0.0.0.0/0"]))?;
        execute(Command::new("uci").args(["set", "network.teliod_lan_rule.lookup=main"]))?;
        execute(
            Command::new("uci").args(["set", "network.teliod_lan_rule.suppress_prefixlength=0"]),
        )?;
        execute(Command::new("uci").args([
            "set",
            &format!("network.teliod_lan_rule.priority={}", lan_rule_prio),
        ]))?;

        // Set firewall zones
        execute(Command::new("uci").args(["add", "firewall", "zone"]))?;
        execute(Command::new("uci").args(["rename", "firewall.@zone[-1]=teliod_vpn_zone"]))?;
        execute(Command::new("uci").args(["set", "firewall.teliod_vpn_zone.name=vpn"]))?;
        execute(Command::new("uci").args(["set", "firewall.teliod_vpn_zone.network=tun"]))?;
        execute(Command::new("uci").args(["set", "firewall.teliod_vpn_zone.masq=1"]))?;

        // Set firewall forwarding
        execute(Command::new("uci").args(["add", "firewall", "forwarding"]))?;
        execute(
            Command::new("uci").args(["rename", "firewall.@forwarding[-1]=teliod_vpn_forwarding"]),
        )?;
        execute(Command::new("uci").args(["set", "firewall.teliod_vpn_forwarding.src=lan"]))?;
        execute(Command::new("uci").args(["set", "firewall.teliod_vpn_forwarding.dest=vpn"]))?;

        // Disable IPv6
        self.disable_ipv6()?;

        // Save and apply
        self.reload_firewall()?;
        self.reload_network()?;

        Ok(())
    }

    fn cleanup_exit_routes(&mut self) -> Result<(), TeliodError> {
        debug!("Removing exit routes");
        if let Err(e) = execute(Command::new("uci").args(["del", "network.teliod_route"])) {
            error!("Error removing route: {e}");
        }
        if let Err(e) = execute(Command::new("uci").args(["del", "network.teliod_vpn_rule"])) {
            error!("Error removing vpn rule: {e}");
        }
        if let Err(e) = execute(Command::new("uci").args(["del", "network.teliod_lan_rule"])) {
            error!("Error removing lan rule: {e}");
        }
        if let Err(e) = execute(Command::new("uci").args(["del", "firewall.teliod_vpn_zone"])) {
            error!("Error removing zone: {e}");
        }
        if let Err(e) = execute(Command::new("uci").args(["del", "firewall.teliod_vpn_forwarding"]))
        {
            error!("Error removing forwarding: {e}");
        }

        // Restore IPv6
        self.restore_ipv6()?;

        // Save and apply
        self.reload_firewall()?;
        self.reload_network()?;

        Ok(())
    }

    fn cleanup_interface(&mut self) -> Result<(), TeliodError> {
        debug!("Removing interface");
        if let Err(e) = execute(Command::new("uci").args(["del", "network.tun"])) {
            error!("Error removing interface: {e}");
        }

        // Save and apply
        self.reload_network()?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    // This test exists as a way to catch any issues with the regex in VpnIpInfo::find_available_table
    // Specifically, the test is not checking that the regex works as expected, just that it doesn't panic
    #[test]
    #[cfg(target_os = "linux")]
    fn test_find_available_table_doesnt_panic() {
        let _ = Iproute::find_available_table();
    }

    #[test]
    fn test_find_available_lower_rule_priority() {
        let result = Iproute::find_available_lower_rule_priority();
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_available_lower_rule_priorities() {
        let result = Iproute::find_available_lower_rule_priorities(2);
        assert_eq!(result.unwrap().len(), 2);
    }
}
