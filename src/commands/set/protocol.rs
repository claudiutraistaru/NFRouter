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
use libc;
use serde_json::json;
use std::process::Command;

pub fn parse_set_protocol_rip_command(
    parts: &[&str],
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    match parts {
        // Enable RIP protocol
        ["set", "protocol", "rip", "enabled"] => set_rip_enabled(running_config),
        ["set", "protocol", "rip", "network", network] => set_rip_network(network, running_config),
        _ => Err("Invalid protocol command".to_string()),
    }
}
pub fn set_rip_enabled(running_config: &mut RunningConfig) -> Result<String, String> {
    // Check if any interfaces are configured
    // let interfaces_configured = running_config
    //     .get_value_from_node(&["interface"], "")
    //     .is_some();

    // if !interfaces_configured {
    //     return Err("No interfaces are configured. Please configure at least one interface before enabling RIP.".to_string());
    // }

    if running_config.get_value_from_node(&["protocol", "rip"], "enabled")
        == Some(&serde_json::Value::Bool(true))
    {
        return Ok("RIP protocol is already enabled.".to_string());
    }
    running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));
    if !cfg!(test) {
        // Execute the vtysh command to enable RIP
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to enable RIP protocol: {}",
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }
    // Update the running configuration
    running_config.add_value_to_node(&["protocol"], "rip", json!(true))?;

    Ok("RIP protocol enabled.".to_string())
}
pub fn set_rip_network(
    network: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if RIP is enabled
    if running_config
        .get_value_from_node(&["protocol", "rip"], "enabled")
        .is_none()
    {
        return Err(
            "RIP protocol is not enabled. Enable it with 'set protocol rip enabled'.".to_string(),
        );
    }

    // Ensure 'network' is an array
    if running_config
        .get_value_from_node(&["protocol", "rip"], "network")
        .is_none()
    {
        running_config.add_value_to_node(&["protocol", "rip"], "network", json!([]))?;
    }

    // Access 'network' as a mutable array
    let networks_array = running_config
        .get_value_from_node_mut(&["protocol", "rip"], "network")
        .and_then(|v| v.as_array_mut())
        .ok_or("Failed to access networks array in the running configuration.")?;

    // Check if the network is already in the array to avoid duplicates
    if networks_array.contains(&json!(network)) {
        return Ok(format!("Network {} is already added to RIP.", network));
    }

    // Add the new network to the array
    networks_array.push(json!(network));

    // Execute the vtysh command to add the network to RIP
    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg(format!("network {}", network.to_string()))
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to add network {} to RIP: {}",
                network,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    Ok(format!("Network {} added to RIP.", network))
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "set protocol rip enabled",
            "Enable the RIP routing protocol.",
        ),
        (
            "set protocol rip network <network-ip/prefix>",
            "Add a network to the RIP routing protocol.",
        ),
        (
            "set protocol rip version <1|2>",
            "Set the RIP version (1 or 2).",
        ),
        (
            "set protocol rip passive-interface <interface-name>",
            "Set an interface to be passive in RIP, meaning it will not send RIP updates.",
        ),
        (
            "set protocol rip redistribute static",
            "Redistribute static routes into RIP.",
        ),
        (
            "set protocol rip redistribute connected",
            "Redistribute connected routes into RIP.",
        ),
        // (
        //     "set protocol rip redistribute ospf",
        //     "Redistribute OSPF routes into RIP.",
        // ),
        // (
        //     "set protocol rip redistribute bgp",
        //     "Redistribute BGP routes into RIP.",
        // ),
        (
            "set protocol rip distance <distance>",
            "Set the administrative distance for RIP routes.",
        ),
        (
            "set protocol rip default-information originate",
            "Advertise a default route in RIP.",
        ),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    #[test]
    fn test_set_rip_enabled_success() {
        let mut running_config = RunningConfig::new();

        // Call the function to enable RIP protocol
        let result = set_rip_enabled(&mut running_config);

        // Check if the result is successful
        assert!(result.is_ok(), "Failed to enable RIP: {:?}", result.err());

        // Ensure the running config is updated to reflect that RIP is enabled
        assert_eq!(
            running_config.get_value_from_node(&["protocol"], "rip"),
            Some(&json!(true)),
            "RIP protocol was not enabled in the running configuration"
        );
    }

    #[test]
    fn test_set_rip_enabled_already_enabled() {
        let mut running_config = RunningConfig::new();

        // Simulate that RIP is already enabled in the running config
        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));
        // Call the function to enable RIP protocol again
        let result = set_rip_enabled(&mut running_config);

        // Check if it returns that RIP is already enabled
        assert_eq!(
            result.unwrap(),
            "RIP protocol is already enabled.",
            "RIP should return already enabled message"
        );
    }

    #[test]
    fn test_set_rip_network_success() {
        let mut running_config = RunningConfig::new();

        // First enable RIP in the configuration
        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        // Call the function to add a network to RIP
        let network = "192.168.1.0/24";
        let result = set_rip_network(network, &mut running_config);

        // Check if the result is successful
        assert!(
            result.is_ok(),
            "Failed to add network to RIP: {:?}",
            result.err()
        );

        // Check if the network was added to the array in the running config
        let networks = running_config
            .get_value_from_node(&["protocol", "rip"], "network")
            .unwrap();
        assert!(
            networks.as_array().unwrap().contains(&json!(network)),
            "Network was not added to RIP"
        );
    }

    #[test]
    fn test_set_rip_network_already_added() {
        let mut running_config = RunningConfig::new();

        // Simulate that RIP is enabled and the network is already added
        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        // Call the function to add the same network again
        let network = "192.168.1.0/24";
        set_rip_network(network, &mut running_config);
        let result = set_rip_network(network, &mut running_config);

        // Check if the result says the network is already added
        assert_eq!(
            result.unwrap(),
            format!("Network {} is already added to RIP.", network),
            "RIP should return network already added message"
        );
    }

    #[test]
    fn test_set_rip_network_rip_not_enabled() {
        let mut running_config = RunningConfig::new();

        // Try to add a network to RIP without enabling RIP first
        let network = "192.168.1.0/24";
        let result = set_rip_network(network, &mut running_config);

        // Check if the function fails because RIP is not enabled
        assert_eq!(
            result.unwrap_err(),
            "RIP protocol is not enabled. Enable it with 'set protocol rip enabled'.",
            "RIP should return an error when adding network without enabling RIP"
        );
    }

    #[test]
    fn test_parse_set_protocol_rip_command_enable() {
        let mut running_config = RunningConfig::new();

        // Call the parser with the command to enable RIP
        let parts = vec!["set", "protocol", "rip", "enabled"];
        let result = parse_set_protocol_rip_command(&parts, &mut running_config);

        // Check if the result is successful
        assert!(
            result.is_ok(),
            "Failed to parse and enable RIP: {:?}",
            result.err()
        );

        // Check if the RIP protocol was enabled in the configuration
        assert_eq!(
            running_config.get_value_from_node(&["protocol"], "rip"),
            Some(&json!(true)),
            "RIP protocol was not enabled in the running configuration"
        );
    }

    #[test]
    fn test_parse_set_protocol_rip_command_network() {
        let mut running_config = RunningConfig::new();

        // First, enable RIP in the configuration
        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        // Call the parser with the command to add a network to RIP
        let parts = vec!["set", "protocol", "rip", "network", "192.168.1.0/24"];
        let result = parse_set_protocol_rip_command(&parts, &mut running_config);

        // Check if the result is successful
        assert!(
            result.is_ok(),
            "Failed to parse and add network to RIP: {:?}",
            result.err()
        );

        // Check if the network was added to the configuration
        let networks = running_config
            .get_value_from_node(&["protocol", "rip"], "network")
            .unwrap();
        assert!(
            networks
                .as_array()
                .unwrap()
                .contains(&json!("192.168.1.0/24")),
            "Network was not added to RIP"
        );
    }
}
