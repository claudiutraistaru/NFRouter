/*
# This file is part of NFRouter.
 *
 * Copyright (C) 2024 Claudiu Trăistaru
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
use crate::config::RunningConfig;
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

pub fn unset_interface_ip(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let ip_exists = running_config
        .get_value_from_node(&["interface", &interface], "address")
        .is_some();

    if !ip_exists {
        return Err(format!("No IP address is set on interface {}", interface));
    }
    if cfg!(test) {
        running_config.remove_value_from_node(&["interface", &interface], "address")?;
        return Ok(format!("Unset IP address on interface {}", interface));
    }
    // Flush all IP addresses from the specified interface
    let output = Command::new("ip")
        .arg("addr")
        .arg("flush")
        .arg("dev")
        .arg(&interface)
        .output()
        .map_err(|e| format!("Failed to flush IP addresses: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to unset IP address on interface {}: {}",
            interface,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    running_config.remove_value_from_node(&["interface", &interface], "ip")?;

    Ok(format!("Unset IP address on interface {}", interface))
}

pub fn unset_interface_speed(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let speed_exists = running_config
        .get_value_from_node(&["interface", &interface, "options"], "speed")
        .is_some();

    if !speed_exists {
        return Err(format!("Speed is not set on interface {}", &interface));
    }
    if cfg!(test) {
        running_config.remove_value_from_node(&["interface", &interface, "options"], "speed");
        return Ok(format!(
            "Unset speed on interface {}, auto-negotiation enabled",
            interface
        ));
    }

    // Reset the speed to auto-negotiation or remove it, depending on system support
    let result = Command::new("ethtool")
        .arg("-s")
        .arg(&interface)
        .arg("autoneg")
        .arg("on")
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            running_config
                .remove_value_from_node(&["interface", &interface, "options"], "speed")?;
            Ok(format!(
                "Unset speed on interface {}, auto-negotiation enabled",
                interface
            ))
        } else {
            Err(format!(
                "Failed to unset speed on interface {}: {}",
                interface,
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute unset speed command: {}",
            result.unwrap_err()
        ))
    }
}
pub fn unset_interface_mtu(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let mtu_exists = running_config
        .get_value_from_node(&["interface", &interface, "options"], "mtu")
        .is_some();

    if !mtu_exists {
        return Err(format!("MTU is not set on interface {}", &interface));
    }
    if cfg!(test) {
        running_config.remove_value_from_node(&["interface", &interface, "options"], "mtu")?;
        return Ok(format!(
            "Unset MTU on interface {}, reset to default",
            interface
        ));
    }

    let result = Command::new("ip")
        .arg("link")
        .arg("set")
        .arg(&interface)
        .arg("mtu")
        .arg("1500") // Common default MTU value; adjust if necessary
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            running_config.remove_value_from_node(&["interface", &interface, "options"], "mtu")?;
            Ok(format!(
                "Unset MTU on interface {}, reset to default",
                interface
            ))
        } else {
            Err(format!(
                "Failed to unset MTU on interface {}: {}",
                interface,
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute unset MTU command: {}",
            result.unwrap_err()
        ))
    }
}
pub fn unset_interface_duplex(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if duplex exists in the running configuration
    let duplex_exists = running_config
        .get_value_from_node(&["interface", &interface, "options"], "duplex")
        .is_some();

    if !duplex_exists {
        return Err(format!("Duplex is not set on interface {}", &interface));
    }
    if cfg!(test) {
        running_config.remove_value_from_node(&["interface", &interface, "options"], "duplex")?;
        return Ok(format!("Unset duplex on interface {}", interface));
    }

    // Reset the duplex to auto-negotiation or default (this command might vary depending on the system)
    let result = Command::new("ethtool")
        .arg("-s")
        .arg(&interface)
        .arg("autoneg")
        .arg("on")
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            running_config
                .remove_value_from_node(&["interface", &interface, "options"], "duplex")?;
            Ok(format!(
                "Unset duplex on interface {}, auto-negotiation enabled",
                interface
            ))
        } else {
            Err(format!(
                "Failed to unset duplex on interface {}: {}",
                interface,
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute unset duplex command: {}",
            result.unwrap_err()
        ))
    }
}
pub fn unset_interface_vlan(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let vlan_exists = running_config
        .get_value_from_node(&["interface", &interface, "vlan"], "id")
        .is_some();

    if !vlan_exists {
        return Err(format!("No VLAN is set on interface {}", interface));
    }
    if cfg!(test) {
        running_config.remove_value_from_node(&["interface", &interface], "vlan")?;
        return Ok(format!("Unset VLAN on interface {}", interface));
    }
    // Remove VLAN interface
    let output = Command::new("ip")
        .arg("link")
        .arg("delete")
        .arg(&interface)
        .output()
        .map_err(|e| format!("Failed to delete VLAN interface: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to delete VLAN interface {}: {}",
            interface,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Remove the VLAN from the running configuration
    running_config.remove_value_from_node(&["interface", &interface], "vlan")?;

    Ok(format!("Unset VLAN on interface {}", interface))
}

pub fn unset_interface_zone(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let zone_exists = running_config
        .get_value_from_node(&["interface", &interface], "zone")
        .is_some();

    if !zone_exists {
        return Err(format!("No zone is set on interface {}", interface));
    }

    // Remove the zone from the running configuration
    running_config.remove_value_from_node(&["interface", &interface], "zone")?;

    Ok(format!("Unset zone on interface {}", interface))
}

pub fn unset_interface_description(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let description_exists = running_config
        .get_value_from_node(&["interface", &interface], "description")
        .is_some();

    if !description_exists {
        return Err(format!("No description is set on interface {}", interface));
    }

    // Remove the description from the running configuration
    running_config.remove_value_from_node(&["interface", &interface], "description")?;

    Ok(format!("Unset description on interface {}", interface))
}
pub fn unset_interface_adjustmss(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let adjust_mss_exists = running_config
        .get_value_from_node(&["interface", &interface, "ip"], "adjust-mss")
        .is_some();

    if !adjust_mss_exists {
        return Err(format!(
            "No TCP MSS adjustment is set on interface {}",
            interface
        ));
    }

    // Remove the MSS adjustment from the running configuration
    running_config.remove_value_from_node(&["interface", &interface, "ip"], "adjust-mss")?;

    Ok(format!(
        "Unset TCP MSS adjustment on interface {}",
        interface
    ))
}

pub fn unset_interface_enable_proxyarp(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let proxy_arp_exists = running_config
        .get_value_from_node(&["interface", &interface, "ip"], "enable-proxy-arp")
        .is_some();

    if !proxy_arp_exists {
        return Err(format!(
            "Proxy ARP is not enabled on interface {}",
            interface
        ));
    }

    if cfg!(test) {
        running_config
            .remove_value_from_node(&["interface", &interface, "ip"], "enable-proxy-arp")?;
        return Ok(format!("Unset proxy ARP on interface {}", interface));
    }
    // Disable proxy ARP
    let proxy_arp_path = format!("/proc/sys/net/ipv4/conf/{}/proxy_arp", interface);
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("echo {} > {}", 0, proxy_arp_path))
        .output()
        .map_err(|e| format!("Failed to disable proxy ARP: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to disable proxy ARP on interface {}: {}",
            interface,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Remove the proxy ARP setting from the running configuration
    running_config.remove_value_from_node(&["interface", &interface, "ip"], "enable-proxy-arp")?;

    Ok(format!("Unset proxy ARP on interface {}", interface))
}

pub fn unset_interface_firewall(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let firewall_exists = running_config
        .get_value_from_node(&["interface", &interface], "firewall")
        .is_some();

    if !firewall_exists {
        return Err(format!(
            "No firewall rules are set on interface {}",
            interface
        ));
    }

    // Remove the firewall setting from the running configuration
    running_config.remove_value_from_node(&["interface", &interface], "firewall")?;

    Ok(format!("Unset firewall rules on interface {}", interface))
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "unset interface <interface> ip",
            "Removes  the IP address for a specified interface.",
        ),
        (
            "unset interface <interface> options speed",
            "Removes the speed entry from configuration.",
        ),
        (
            "unset interface <interface> options mtu",
            "Resets the MTU of an interface to 1500 and removes the configuration entry.",
        ),
        (
            "unset interface <interface> options duplex",
            "Removes the duplex mode of a network interface from configuration and sets that interface to autonegotation.",
        ),
        (
            "unset interface <interface> vlan",
            "Removes VLAN configuration from the interface.",
        ),
        (
            "unset interface <interface> zone",
            "Removes the zone associated with the interface.",
        ),
        (
            "unset interface <interface> description",
            "Removes the description from the interface.",
        ),
        (
            "unset interface <interface> options adjust-mss",
            "Removes the TCP MSS adjustment for the interface.",
        ),
        (
            "unset interface <interface> enable-proxy-arp",
            "Disables proxy ARP on the interface.",
        ),
        (
            "unset interface <interface> firewall",
            "Removes firewall rules associated with the interface.",
        )
    ]
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unset_interface_ip() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(
                &["interface", &interface],
                "address",
                json!("192.168.1.10/24"),
            )
            .unwrap();

        let result = unset_interface_ip(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface], "address")
            .is_none());
    }

    #[test]
    fn test_unset_interface_ip_not_set() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();

        let result = unset_interface_ip(interface.clone(), &mut running_config);
        assert!(
            result.is_err(),
            "Test should have failed since IP is not set"
        );
    }

    #[test]
    fn test_unset_interface_speed() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(&["interface", &interface, "options"], "speed", json!(1000))
            .unwrap();

        let result = unset_interface_speed(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface, "options"], "speed")
            .is_none());
    }

    #[test]
    fn test_unset_interface_mtu() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(&["interface", &interface, "options"], "mtu", json!(1500))
            .unwrap();

        let result = unset_interface_mtu(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface, "options"], "mtu")
            .is_none());
    }

    #[test]
    fn test_unset_interface_duplex() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(
                &["interface", &interface, "options"],
                "duplex",
                json!("full"),
            )
            .unwrap();

        let result = unset_interface_duplex(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface, "options"], "duplex")
            .is_none());
    }

    #[test]
    fn test_unset_interface_vlan() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0.100".to_string();
        running_config
            .add_value_to_node(&["interface", &interface, "vlan"], "id", json!(100))
            .unwrap();

        let result = unset_interface_vlan(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface], "vlan")
            .is_none());
    }

    #[test]
    fn test_unset_interface_zone() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(&["interface", &interface], "zone", json!("trusted"))
            .unwrap();

        let result = unset_interface_zone(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface], "zone")
            .is_none());
    }

    #[test]
    fn test_unset_interface_description() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(
                &["interface", &interface],
                "description",
                json!("Main uplink interface"),
            )
            .unwrap();

        let result = unset_interface_description(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface], "description")
            .is_none());
    }

    #[test]
    fn test_unset_interface_adjustmss() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(&["interface", &interface, "ip"], "adjust-mss", json!(1400))
            .unwrap();

        let result = unset_interface_adjustmss(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface, "ip"], "adjust-mss")
            .is_none());
    }

    #[test]
    fn test_unset_interface_enable_proxyarp() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(
                &["interface", &interface, "ip"],
                "enable-proxy-arp",
                json!(true),
            )
            .unwrap();

        let result = unset_interface_enable_proxyarp(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface, "ip"], "enable-proxy-arp")
            .is_none());
    }

    #[test]
    fn test_unset_interface_firewall() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        running_config
            .add_value_to_node(&["interface", &interface], "firewall", json!("ruleset"))
            .unwrap();

        let result = unset_interface_firewall(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert!(running_config
            .get_value_from_node(&["interface", &interface], "firewall")
            .is_none());
    }
}
