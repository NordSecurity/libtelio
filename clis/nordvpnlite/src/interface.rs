use crate::NordVpnLiteError;
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, error, info, warn};

#[cfg(target_os = "linux")]
use telio::telio_utils::LIBTELIO_FWMARK;

// Copied from NordVPN Linux app
const DEFAULT_ROUTING_TABLE_ID: u32 = 205;

pub trait ConfigureInterface {
    /// Initialize the interface
    fn initialize(&mut self) -> Result<(), NordVpnLiteError>;
    /// Configure the IP address and routes for a given interface
    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), NordVpnLiteError>;
    /// Get the configured IP address for the interface
    fn get_ip(&self) -> Option<IpAddr>;
    /// Configure routes for exit routing
    fn set_exit_routes(
        &mut self,
        exit_node: &IpAddr,
        dns: &[IpAddr],
    ) -> Result<(), NordVpnLiteError>;
    /// Some of the configured routes are not cleared when the adapter is removed and must be removed manually
    fn cleanup_exit_routes(&mut self) -> Result<(), NordVpnLiteError>;
    /// Manually cleanup the interface before the adapter is removed
    fn cleanup_interface(&mut self) -> Result<(), NordVpnLiteError> {
        Ok(()) // No-op implementation
    }
}

/// Helper function to execute a system command
fn execute(command: &mut Command) -> Result<(), NordVpnLiteError> {
    debug!("Executing command '{command:?}'");
    let output = command
        .output()
        .map_err(|e| NordVpnLiteError::SystemCommandFailed(e.to_string()))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Error executing command {:?}: {:?}", command, stderr);
        Err(NordVpnLiteError::SystemCommandFailed(stderr.into()))
    }
}

/// Helper function to execute a system command with output
fn execute_with_output(command: &mut Command) -> Result<String, NordVpnLiteError> {
    debug!("Executing command with output '{command:?}'");
    let output = command
        .output()
        .map_err(|e| NordVpnLiteError::SystemCommandFailed(e.to_string()))?;

    if output.status.success() {
        String::from_utf8(output.stdout).map_err(|e| {
            NordVpnLiteError::SystemCommandFailed(format!(
                "Command executed but couldn't convert output to string: {}",
                e
            ))
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Error executing command {:?}: {:?}", command, stderr);
        Err(NordVpnLiteError::SystemCommandFailed(stderr.into()))
    }
}

/// Helper to find the lower available priorities in descending order
fn get_available_priorities(
    count: usize,
    start_prio: u32,
    existing_prios: &[u32],
) -> Result<Vec<u32>, NordVpnLiteError> {
    let available_prios: Vec<u32> = (1..start_prio)
        .rev()
        .filter(|prio| !existing_prios.contains(prio))
        .take(count)
        .collect();

    if available_prios.len() == count {
        Ok(available_prios)
    } else {
        Err(NordVpnLiteError::IpRule)
    }
}

#[derive(Default, Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceConfigurationProvider {
    #[default]
    Manual,
    Iproute,
    Uci,
}

#[derive(Default, PartialEq, Eq, Deserialize, Serialize, Debug, Clone)]
pub struct InterfaceConfig {
    pub name: String,
    pub config_provider: InterfaceConfigurationProvider,
    /// Set the maximum routing rule priority
    pub max_route_priority: Option<u32>,
}

impl InterfaceConfig {
    pub fn get_config_provider(&self) -> Box<dyn ConfigureInterface> {
        info!(
            "Creating interface config provider for {:?} on interface {}",
            self.config_provider, self.name
        );
        match &self.config_provider {
            InterfaceConfigurationProvider::Manual => Box::new(Manual),
            InterfaceConfigurationProvider::Iproute => Box::new(Iproute {
                interface_name: self.name.clone(),
                max_route_priority: self.max_route_priority,
                ..Default::default()
            }),
            InterfaceConfigurationProvider::Uci => {
                Box::new(Uci::new(&self.name, self.max_route_priority))
            }
        }
    }
}

/// Empty implementation for manual configuration
#[derive(Debug, PartialEq, Eq)]
pub struct Manual;

impl ConfigureInterface for Manual {
    fn initialize(&mut self) -> Result<(), NordVpnLiteError> {
        Ok(()) // No-op implementation
    }

    fn set_ip(&mut self, _ip_address: &IpAddr) -> Result<(), NordVpnLiteError> {
        Ok(()) // No-op implementation
    }
    /// For manual configuration, we still use ifconfig to query the interface
    /// This is a fallback for when the interface is configured manually
    fn get_ip(&self) -> Option<IpAddr> {
        None
    }

    fn set_exit_routes(
        &mut self,
        _exit_node: &IpAddr,
        _dns: &[IpAddr],
    ) -> Result<(), NordVpnLiteError> {
        Ok(()) // No-op implementation
    }

    fn cleanup_exit_routes(&mut self) -> Result<(), NordVpnLiteError> {
        Ok(()) // No-op implementation
    }
}

/// Implementation using `iproute2`
#[derive(Debug, Default)]
pub struct Iproute {
    interface_name: String,
    table: Option<String>,
    fw_rule_prio: Option<String>,
    ipv6_support_manager: Ipv6SupportManager,
    /// Set the maximum routing rule priority
    max_route_priority: Option<u32>,
}

impl Iproute {
    // Some ip commands will return "RNETLINK answers: File exists" which means that the command was already executed and we can ignore the error
    fn ignore_file_exists_error(res: Result<(), NordVpnLiteError>) -> Result<(), NordVpnLiteError> {
        match res {
            Err(NordVpnLiteError::SystemCommandFailed(message))
                if message.contains("File exists") =>
            {
                Ok(())
            }
            _ => res,
        }
    }

    // Based on the implementation from the NordVPN Linux app
    // When setting routing information on linux we set a default route on a custom routing table
    // and an IP rule to make sure that the correct packets go through that table.
    #[allow(clippy::expect_used)]
    pub fn find_available_table() -> Result<u32, NordVpnLiteError> {
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
        Err(NordVpnLiteError::IpRoute)
    }

    // Based on the implementation from the NordVPN Linux app
    // Finds the main rule priority and the list of assigned priorities
    fn find_main_and_assigned_rule_priorities() -> Result<(u32, Vec<u32>), NordVpnLiteError> {
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
    fn find_available_lower_rule_priority(
        max_route_priority: Option<u32>,
    ) -> Result<u32, NordVpnLiteError> {
        let (main_rule_priority, existing_prios) = Self::find_main_and_assigned_rule_priorities()?;
        // start either from the lookup main priority or max_route_priority when given
        let start_prio = max_route_priority.unwrap_or(main_rule_priority);
        // this is ok because get_available_priorities()
        // returns an error on wrong size
        #[allow(clippy::indexing_slicing)]
        get_available_priorities(1, start_prio, &existing_prios).map(|r| r[0])
    }

    // Iterate over existing_prios until we find the number of available lower priorities
    pub fn find_available_lower_rule_priorities(
        count: usize,
        max_route_priority: Option<u32>,
    ) -> Result<Vec<u32>, NordVpnLiteError> {
        let (main_rule_priority, existing_prios) = Self::find_main_and_assigned_rule_priorities()?;
        // start either from the lookup main priority or max_route_priority when given
        let start_prio = max_route_priority.unwrap_or(main_rule_priority);
        get_available_priorities(count, start_prio, &existing_prios)
    }
}

impl ConfigureInterface for Iproute {
    fn initialize(&mut self) -> Result<(), NordVpnLiteError> {
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

    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), NordVpnLiteError> {
        let cidr_suffix = if ip_address.is_ipv4() { "/30" } else { "/64" };
        let cidr_string = format!("{ip_address}{cidr_suffix}");

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

    fn get_ip(&self) -> Option<IpAddr> {
        let output = execute_with_output(Command::new("ip").args([
            "-4",
            "addr",
            "show",
            "dev",
            &self.interface_name,
        ]))
        .ok()?;

        for line in output.lines() {
            let line = line.trim();
            if line.contains("inet ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(ip_idx) = parts.iter().position(|&s| s == "inet") {
                    if let Some(ip_cidr) = parts.get(ip_idx + 1) {
                        if let Ok(net) = ip_cidr.parse::<IpNet>() {
                            return Some(net.addr());
                        }
                    }
                }
            }
        }
        None
    }

    fn set_exit_routes(
        &mut self,
        exit_node: &IpAddr,
        _dns: &[IpAddr],
    ) -> Result<(), NordVpnLiteError> {
        #[cfg(target_os = "linux")]
        if exit_node.is_ipv4() {
            let table = Self::find_available_table()?.to_string();
            let fw_rule_prio =
                Self::find_available_lower_rule_priority(self.max_route_priority)?.to_string();

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

    fn cleanup_exit_routes(&mut self) -> Result<(), NordVpnLiteError> {
        if let Some(fw_rule_prio) = &self.fw_rule_prio {
            execute(Command::new("ip").args(["rule", "del", "priority", fw_rule_prio]))?;
        }
        if let Some(table) = &self.table {
            execute(Command::new("ip").args(["route", "flush", "table", table]))?;
        }
        self.ipv6_support_manager.reenable()
    }
}

/// UCI-based implementation for managing network configuration on OpenWRT devices.
#[derive(Debug)]
pub struct Uci {
    interface_name: String,

    /// Set the maximum routing rule priority
    max_route_priority: Option<u32>,

    /// Initial IPv6 setting on WAN interface
    ///
    /// This reflects the value of `network.wan.ipv6` at the time of loading.
    /// If the option is unset, IPv6 is enabled by default.
    wan_ipv6_initial_setting: Option<UciBoolOption>,

    /// Initial enabled/disabled state of WAN6 interface, if it exists
    ///
    /// Reflects the value of `network.wan6.disabled`.
    /// If the option is unset, the interface is enabled by default.
    wan6_disabled_initial_setting: Option<UciBoolOption>,

    /// Initial dnsmasq noresolv value
    initial_setting_dnsmasq_noresolv: Option<UciBoolOption>,

    /// Initial dnsmasq server value
    initial_setting_dnsmasq_server: Option<Vec<String>>,
}

/// Represents a boolean option in the UCI configuration system.
///
/// - `True` -> Option is set to `1`
/// - `False` -> Option is set to `0`
/// - `Default` -> Option is unset in UCI (default behavior applies)
///
/// When restoring configuration, `Default` implies the option should be deleted from UCI.
#[derive(Debug)]
enum UciBoolOption {
    True,
    False,
    Default,
}

impl UciBoolOption {
    /// Helper function to convert a result of a `uci get` command into a UciBoolOption.
    ///
    /// Returns:
    /// - `True` for "1"
    /// - `False` for "0"
    /// - `Default` for anything else
    fn from_str(str: &str) -> Self {
        match str.trim() {
            "1" => Self::True,
            "0" => Self::False,
            _ => Self::Default,
        }
    }

    /// Returns true if the option is set to `1`.
    fn is_true(&self) -> bool {
        matches!(self, Self::True)
    }
}

impl Uci {
    fn new(interface_name: &str, max_route_priority: Option<u32>) -> Self {
        // TODO: LLT-6485: Add support for multiple WANs

        // In OpenWRT, each network interface is declared using UCI syntax like:
        //     `network.wan=interface`
        // Interfaces can optionally include an IPv6 setting:
        //     `network.wan.ipv6=0` disables IPv6
        //     `network.wan.ipv6=1` enables IPv6 (default if not set)
        //
        // In addition to primary interfaces (like WAN), OpenWRT may define separate
        // IPv6-specific interfaces with names ending in "*6", such as:
        //     `network.wan6=interface`
        //     `network.wwan6=interface`
        // These are typically handle IPv6 independently.
        //
        // To fully disable IPv6, we must:
        // 1. Explicitly disable IPv6 on the primary interfaces:
        //     `network.wan.ipv6=0`
        // 2. Disable any IPv6-only interfaces entirely by setting:
        //     `network.wan6.disabled=1`

        // Check if IPv6 is enabled on the primary WAN interface.
        // If `network.wan.ipv6` is not set, IPv6 is considered enabled by default.
        //     `network.wan.ipv6=1` -> IPv6 enabled
        //     `network.wan.ipv6=0` -> IPv6 disabled
        let wan_ipv6_initial_setting = execute(Command::new("uci").args(["get", "network.wan"]))
            .map(|_| {
                execute_with_output(Command::new("uci").args(["get", "network.wan.ipv6"]))
                    .map(|res| UciBoolOption::from_str(&res))
                    .unwrap_or(UciBoolOption::Default)
            })
            .ok();

        // Check whether the WAN6 interface exists and whether it is disabled.
        // If `network.wan6.disabled` is not set, the interface is enabled by default.
        //     `network.wan6.disabled=0` -> enabled
        //     `network.wan6.disabled=1` -> disabled
        let wan6_disabled_initial_setting =
            execute(Command::new("uci").args(["get", "network.wan6"]))
                .map(|_| {
                    execute_with_output(Command::new("uci").args(["get", "network.wan6.disabled"]))
                        .map(|res| UciBoolOption::from_str(&res))
                        .unwrap_or(UciBoolOption::Default)
                })
                .ok();

        let initial_setting_dnsmasq_noresolv =
            execute(Command::new("uci").args(["get", "dhcp.@dnsmasq[0]"]))
                .map(|_| {
                    execute_with_output(
                        Command::new("uci").args(["get", "dhcp.@dnsmasq[0].noresolv"]),
                    )
                    .map(|res| UciBoolOption::from_str(&res))
                    .unwrap_or(UciBoolOption::Default)
                })
                .ok();

        let initial_setting_dnsmasq_server =
            execute_with_output(Command::new("uci").args(["get", "dhcp.@dnsmasq[0].server"]))
                .map(|res| {
                    Some(
                        res.split_whitespace()
                            .map(|s| s.to_owned())
                            .collect::<Vec<String>>(),
                    )
                })
                .unwrap_or(None);

        debug!("Initial network.wan.ipv6 state {wan_ipv6_initial_setting:?}");
        debug!("Initial network.wan6.disabled state {wan6_disabled_initial_setting:?}");
        debug!("Initial dhcp.@dnsmasq[0].noresolv {initial_setting_dnsmasq_noresolv:?}");
        debug!("Initial dhcp.@dnsmasq[0].server {initial_setting_dnsmasq_server:?}");

        Self {
            interface_name: interface_name.to_string(),
            wan_ipv6_initial_setting,
            wan6_disabled_initial_setting,
            initial_setting_dnsmasq_noresolv,
            initial_setting_dnsmasq_server,
            max_route_priority,
        }
    }

    fn configure_dnsmasq(&mut self, ips: &[IpAddr]) -> Result<(), NordVpnLiteError> {
        debug!("Configuring dnsmasq servers: {:?}", ips);

        execute(Command::new("uci").args(["set", "dhcp.@dnsmasq[0].noresolv=1"]))?;
        execute(Command::new("uci").args(["delete", "dhcp.@dnsmasq[0].server"]))
            .map_err(|e| {
                debug!("uci couldn't delete dnsmasq server entry: {}", e);
            })
            .ok();

        for ip in ips {
            execute(
                Command::new("uci").args(["add_list", &format!("dhcp.@dnsmasq[0].server={}", ip)]),
            )?;
        }

        execute(Command::new("uci").args(["commit", "dhcp"]))?;
        execute(Command::new("/etc/init.d/dnsmasq").args(["reload"]))?;

        Ok(())
    }

    fn restore_dnsmasq(&self) -> Result<(), NordVpnLiteError> {
        debug!("Restoring dnsmasq settings");

        match self.initial_setting_dnsmasq_noresolv {
            Some(ref v) => {
                let state = if v.is_true() { "1" } else { "0" };
                if let Err(e) = execute(
                    Command::new("uci")
                        .args(["set", &format!("dhcp.@dnsmasq[0].noresolv={}", state)]),
                ) {
                    error!("Error restoring dhcp.@dnsmasq[0].noresolv: {}", e);
                }
            }
            None => warn!("No value stored for dhcp.@dnsmasq[0].noresolv. Ignoring."),
        }

        // Adding servers works in append mode, we must delete first
        execute(Command::new("uci").args(["delete", "dhcp.@dnsmasq[0].server"]))?;

        if let Some(ips) = &self.initial_setting_dnsmasq_server {
            for ip in ips {
                execute(
                    Command::new("uci")
                        .args(["add_list", &format!("dhcp.@dnsmasq[0].server={}", ip)]),
                )?;
            }
        }

        execute(Command::new("uci").args(["commit", "dhcp"]))?;
        execute(Command::new("/etc/init.d/dnsmasq").args(["reload"]))?;

        Ok(())
    }

    // Helper to disable IPv6
    fn disable_ipv6(&self) -> Result<(), NordVpnLiteError> {
        if self.wan_ipv6_initial_setting.is_some() {
            execute(Command::new("uci").args(["set", "network.wan.ipv6=0"]))?;
        }
        if self.wan6_disabled_initial_setting.is_some() {
            execute(Command::new("uci").args(["set", "network.wan6.disabled=1"]))?;
        }
        Ok(())
    }

    // Helper to restore settings IPv6 to initial state
    fn restore_ipv6(&self) -> Result<(), NordVpnLiteError> {
        // Remove rule routing all IPv6 into the tunnel
        if let Err(e) = execute(Command::new("uci").args(["del", "network.nordvpnlite_route6"])) {
            error!("Error removing network.nordvpnlite_route6: {e}");
        }

        // Restore the IPv6 setting for WAN interface to it's original value.
        // If network.wan.ipv6 was not present, delete it to restore to Default state
        if let Some(enabled) = &self.wan_ipv6_initial_setting {
            debug!("Removing network.wan.ipv6");
            if matches!(enabled, UciBoolOption::Default) {
                if let Err(e) = execute(Command::new("uci").args(["del", "network.wan.ipv6"])) {
                    error!("Error removing network.wan.ipv6: {e}");
                }
            } else {
                let state = if enabled.is_true() { "1" } else { "0" };
                debug!("Restoring network.wan.ipv6 to {state}");
                execute(Command::new("uci").args(["set", &format!("network.wan.ipv6={state}")]))?;
            }
        }

        // Restore the disabled setting for WAN6 interface to it's original value.
        // If network.wan6.disabled was not present, delete it to restore to Default state
        if let Some(disabled) = &self.wan6_disabled_initial_setting {
            debug!("Removing network.wan6.disabled");
            if matches!(disabled, UciBoolOption::Default) {
                if let Err(e) = execute(Command::new("uci").args(["del", "network.wan6.disabled"]))
                {
                    error!("Error removing network.wan6.disabled: {e}");
                }
            } else {
                let state = if disabled.is_true() { "1" } else { "0" };
                debug!("Restoring network.wan6.disabled to {state}");
                execute(
                    Command::new("uci").args(["set", &format!("network.wan6.disabled={state}")]),
                )?;
            }
        }

        Ok(())
    }

    // Helper to reload network service
    fn reload_network(&self) -> Result<(), NordVpnLiteError> {
        execute(Command::new("uci").args(["commit", "network"]))?;
        execute(Command::new("/etc/init.d/network").args(["reload"]))?;
        Ok(())
    }

    // Helper to reload firewall service
    fn reload_firewall(&self) -> Result<(), NordVpnLiteError> {
        execute(Command::new("uci").args(["commit", "firewall"]))?;
        execute(Command::new("/etc/init.d/firewall").args(["reload"]))?;
        Ok(())
    }
}

impl ConfigureInterface for Uci {
    fn initialize(&mut self) -> Result<(), NordVpnLiteError> {
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

    fn set_ip(&mut self, ip_address: &IpAddr) -> Result<(), NordVpnLiteError> {
        info!(
            "Assigning IP address for {} to {}",
            self.interface_name, ip_address
        );

        // set options
        execute(Command::new("uci").args([
            "set",
            &format!("network.tun.device={}", &self.interface_name),
        ]))?;
        execute(Command::new("uci").args(["set", "network.tun.proto=static"]))?;
        execute(Command::new("uci").args(["set", &format!("network.tun.ipaddr={ip_address}")]))?;
        execute(Command::new("uci").args(["set", "network.tun.netmask=255.255.255.252"]))?;

        // save and apply
        self.reload_network()?;

        Ok(())
    }

    fn get_ip(&self) -> Option<IpAddr> {
        let output =
            execute_with_output(Command::new("uci").args(["get", "network.tun.ipaddr"])).ok()?;

        output.trim().parse::<IpAddr>().ok()
    }

    fn set_exit_routes(
        &mut self,
        _exit_node: &IpAddr,
        dns: &[IpAddr],
    ) -> Result<(), NordVpnLiteError> {
        let table = Iproute::find_available_table()?;
        let (vpn_rule_prio, lan_rule_prio) = {
            let priorities =
                Iproute::find_available_lower_rule_priorities(2, self.max_route_priority)?;
            // this is ok because find_available_lower_rule_priorities()
            // returns an error on wrong size
            #[allow(clippy::indexing_slicing)]
            (priorities[0], priorities[1])
        };

        // Set route and rules for VPN
        execute(Command::new("uci").args(["add", "network", "route"]))?;
        execute(Command::new("uci").args(["rename", "network.@route[-1]=nordvpnlite_route"]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_route.interface=tun"]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_route.target=0.0.0.0/0"]))?;
        execute(
            Command::new("uci").args(["set", &format!("network.nordvpnlite_route.table={table}")]),
        )?;

        execute(Command::new("uci").args(["add", "network", "route6"]))?;
        execute(Command::new("uci").args(["rename", "network.@route6[-1]=nordvpnlite_route6"]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_route6.interface=tun"]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_route6.target=::/0"]))?;

        execute(Command::new("uci").args(["add", "network", "rule"]))?;
        execute(Command::new("uci").args(["rename", "network.@rule[-1]=nordvpnlite_vpn_rule"]))?;
        execute(Command::new("uci").args([
            "set",
            &format!("network.nordvpnlite_vpn_rule.lookup={table}"),
        ]))?;
        #[cfg(target_os = "linux")] // LIBTELIO_FWMARK is compile time flagged
        execute(Command::new("uci").args([
            "set",
            &format!("network.nordvpnlite_vpn_rule.mark={LIBTELIO_FWMARK}"),
        ]))?;
        execute(Command::new("uci").args([
            "set",
            &format!("network.nordvpnlite_vpn_rule.priority={vpn_rule_prio}"),
        ]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_vpn_rule.invert=1"]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_vpn_rule.src=0.0.0.0/0"]))?;

        // Exception for LAN traffic accessing Gateway
        execute(Command::new("uci").args(["add", "network", "rule"]))?;
        execute(Command::new("uci").args(["rename", "network.@rule[-1]=nordvpnlite_lan_rule"]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_lan_rule.src=0.0.0.0/0"]))?;
        execute(Command::new("uci").args(["set", "network.nordvpnlite_lan_rule.lookup=main"]))?;
        execute(Command::new("uci").args([
            "set",
            "network.nordvpnlite_lan_rule.suppress_prefixlength=0",
        ]))?;
        execute(Command::new("uci").args([
            "set",
            &format!("network.nordvpnlite_lan_rule.priority={lan_rule_prio}"),
        ]))?;

        // Set firewall zones
        execute(Command::new("uci").args(["add", "firewall", "zone"]))?;
        execute(Command::new("uci").args(["rename", "firewall.@zone[-1]=nordvpnlite_vpn_zone"]))?;
        execute(Command::new("uci").args(["set", "firewall.nordvpnlite_vpn_zone.name=vpn"]))?;
        execute(Command::new("uci").args(["set", "firewall.nordvpnlite_vpn_zone.network=tun"]))?;
        execute(Command::new("uci").args(["set", "firewall.nordvpnlite_vpn_zone.masq=1"]))?;
        execute(Command::new("uci").args(["set", "firewall.nordvpnlite_vpn_zone.mtu_fix=1"]))?;

        // Set firewall forwarding
        execute(Command::new("uci").args(["add", "firewall", "forwarding"]))?;
        execute(Command::new("uci").args([
            "rename",
            "firewall.@forwarding[-1]=nordvpnlite_vpn_forwarding",
        ]))?;
        execute(Command::new("uci").args(["set", "firewall.nordvpnlite_vpn_forwarding.src=lan"]))?;
        execute(Command::new("uci").args(["set", "firewall.nordvpnlite_vpn_forwarding.dest=vpn"]))?;

        // Disable IPv6
        self.disable_ipv6()?;

        // Configure DNS
        self.configure_dnsmasq(dns)?;

        // Save and apply
        self.reload_firewall()?;
        self.reload_network()?;

        Ok(())
    }

    fn cleanup_exit_routes(&mut self) -> Result<(), NordVpnLiteError> {
        debug!("Removing exit routes");
        if let Err(e) = execute(Command::new("uci").args(["del", "network.nordvpnlite_route"])) {
            error!("Error removing route: {e}");
        }
        if let Err(e) = execute(Command::new("uci").args(["del", "network.nordvpnlite_vpn_rule"])) {
            error!("Error removing vpn rule: {e}");
        }
        if let Err(e) = execute(Command::new("uci").args(["del", "network.nordvpnlite_lan_rule"])) {
            error!("Error removing lan rule: {e}");
        }
        if let Err(e) = execute(Command::new("uci").args(["del", "firewall.nordvpnlite_vpn_zone"]))
        {
            error!("Error removing zone: {e}");
        }
        if let Err(e) =
            execute(Command::new("uci").args(["del", "firewall.nordvpnlite_vpn_forwarding"]))
        {
            error!("Error removing forwarding: {e}");
        }

        // Restore DNS settings
        self.restore_dnsmasq()?;

        // Restore IPv6
        self.restore_ipv6()?;

        // Save and apply
        self.reload_firewall()?;
        self.reload_network()?;

        Ok(())
    }

    fn cleanup_interface(&mut self) -> Result<(), NordVpnLiteError> {
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
    fn disable(&mut self, skip_interface: &str) -> Result<(), NordVpnLiteError> {
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

    fn reenable(&mut self) -> Result<(), NordVpnLiteError> {
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
    #[cfg(target_os = "linux")]
    fn test_find_available_lower_rule_priority() {
        let result = Iproute::find_available_lower_rule_priority(None);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_find_available_max_rule_priority() {
        let max_rule_priority = 100;
        let result = Iproute::find_available_lower_rule_priority(Some(max_rule_priority));
        assert!(result.unwrap() < max_rule_priority);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_find_unavailable_max_rule_priority() {
        let result = Iproute::find_available_lower_rule_priority(Some(0));
        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_find_available_lower_rule_priorities() {
        let result = Iproute::find_available_lower_rule_priorities(2, None);
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_find_available_max_rule_priorities() {
        let max_rule_priority = 100;
        let result =
            Iproute::find_available_lower_rule_priorities(2, Some(max_rule_priority)).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0] < max_rule_priority);
        assert!(result[1] < max_rule_priority);
    }

    #[test]
    fn test_available_priorities_skipping_existing() {
        let existing_prios = vec![5, 3];
        let result = get_available_priorities(3, 6, &existing_prios).unwrap();
        assert_eq!(result, vec![4, 2, 1]);
    }

    #[test]
    fn test_enough_priorities_existing() {
        let existing_prios = vec![0];
        let result = get_available_priorities(3, 5, &existing_prios).unwrap();
        assert_eq!(result, vec![4, 3, 2]);
    }

    #[test]
    fn test_not_enough_priorities_available() {
        let existing_prios = vec![1, 2, 3, 4];
        let result = get_available_priorities(2, 5, &existing_prios);
        assert!(matches!(result, Err(NordVpnLiteError::IpRule)));
    }
}
