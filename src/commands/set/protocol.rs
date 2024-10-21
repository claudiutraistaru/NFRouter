/*
 * This file is part of NFRouter.
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
use regex::Regex;
use serde_json::json;
use std::process::Command;

/// Parse a "set protocol rip" command and update the running configuration accordingly.
///
/// # Parameters
///
/// * `parts`: The parts of the command to parse, as an array of strings.
/// * `running_config`: A mutable reference to the running configuration.
///
/// # Returns
///
/// A `Result` containing a JSON string representing the updated running configuration,
/// or an error message if the command is invalid.

pub fn parse_set_protocol_rip_command(
    parts: &[&str],
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    match parts {
        // Enable RIP protocol
        //["set", "protocol", "rip", "enabled"] => set_rip_enabled(running_config),
        ["set", "protocol", "rip", "network", network] => set_rip_network(network, running_config),
        ["set", "protocol", "rip", "version", version] => {
            set_rip_version(version.parse::<u8>().unwrap(), running_config)
        }
        ["set", "protocol", "rip", "passive-interface", interface] => {
            set_rip_passive_interface(interface, running_config)
        }
        ["set", "protocol", "rip", "distance", distance] => {
            set_rip_distance(distance, running_config)
        }
        ["set", "protocol", "rip", "redistribute", "static"] => {
            set_rip_redistribute_static(running_config)
        }
        ["set", "protocol", "rip", "redistribute", "connected"] => {
            set_rip_redistribute_connected(running_config)
        }
        ["set", "protocol", "rip", "authentication", authentication] => {
            set_rip_authentication(authentication, None, None, running_config)
        }
        ["set", "protocol", "rip", "send-version", version] => {
            set_rip_send_version(version, running_config)
        }
        ["set", "protocol", "rip", "receive-version", version] => {
            set_rip_receive_version(version, running_config)
        }
        _ => Err("Invalid protocol command".to_string()),
    }
}
/// Set the RIP network.
///
/// This function sets a new network for the RIP protocol. If the RIP protocol is not enabled,
/// it will be enabled first.
///
/// # Parameters
///
/// * `network`: The new network to add to the RIP protocol.
///
/// # Returns
///
/// A `Result` containing a success message if the operation was successful, or an error message otherwise.

pub fn set_rip_network(
    network_or_interface: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    println!("Current running config: {:?}", running_config.config);

    // Determine if the input is a network (IP with prefix) or an interface
    let is_network = Regex::new(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
        .unwrap()
        .is_match(network_or_interface);
    let is_interface = Regex::new(r"^[a-zA-Z0-9\-]+$")
        .unwrap()
        .is_match(network_or_interface);

    if !is_network && !is_interface {
        return Err(format!(
            "Invalid input: {}. It must be a network in CIDR format or a valid interface name.",
            network_or_interface
        ));
    }

    if running_config
        .get_value_from_node(&["protocol", "rip"], "network")
        .is_none()
    {
        running_config.add_value_to_node(&["protocol", "rip"], "network", json!([]))?;
    }

    let networks_array = running_config
        .get_value_from_node_mut(&["protocol", "rip"], "network")
        .and_then(|v| v.as_array_mut())
        .ok_or("Failed to access networks array in the running configuration.")?;

    if networks_array.contains(&json!(network_or_interface)) {
        return Ok(format!(
            "Network {} is already added to RIP.",
            network_or_interface
        ));
    }

    networks_array.push(json!(network_or_interface));

    if !cfg!(test) {
        // Determine the correct vtysh command
        let vtysh_command = if is_network {
            format!("network {}", network_or_interface)
        } else if is_interface {
            format!("network interface {}", network_or_interface)
        } else {
            return Err("Invalid input for RIP configuration.".to_string());
        };

        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg(vtysh_command)
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to add {} to RIP: {}",
                network_or_interface,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    Ok(format!("{} added to RIP.", network_or_interface))
}

pub fn set_rip_version(version: u8, running_config: &mut RunningConfig) -> Result<String, String> {
    if version != 1 && version != 2 {
        return Err("Invalid RIP version. Only version 1 or 2 is supported.".to_string());
    }

    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg(format!("version {}", version))
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to set RIP version {}: {}",
                version,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    // Update the running configuration
    running_config.add_value_to_node(&["protocol", "rip"], "version", json!(version))?;

    Ok(format!("RIP version {} set.", version))
}

/// Set the RIP passive interface.
///
/// This function sets a specific interface as passive for the RIP protocol. If the
/// RIP protocol is not enabled, it will be enabled first.
///
/// # Parameters
///
/// * `interface`: The interface to set as passive for RIP.
///
/// # Returns
///
/// A `Result` containing a success message if the operation was successful, or an error message otherwise.

pub fn set_rip_passive_interface(
    interface: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if running_config
        .get_value_from_node(&["interface"], interface)
        .is_none()
    {
        return Err(format!("Interface {} is not configured.", interface));
    }

    // Execute the vtysh command to set the interface as passive in RIP
    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg(format!("passive-interface {}", interface))
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to set passive interface {} in RIP: {}",
                interface,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    if running_config
        .get_value_from_node(&["protocol", "rip"], "passive-interface")
        .is_none()
    {
        running_config.add_value_to_node(&["protocol", "rip"], "passive-interface", json!([]))?;
    }

    let mut passive_interfaces_array = running_config
        .get_value_from_node(&["protocol", "rip"], "passive-interface")
        .and_then(|v| v.as_array().cloned())
        .ok_or("Failed to access passive-interfaces array in the running configuration.")?;

    if passive_interfaces_array.contains(&json!(interface)) {
        return Ok(format!(
            "Interface {} is already a passive interface in RIP.",
            interface
        ));
    }

    passive_interfaces_array.push(json!(interface));
    running_config.add_value_to_node(
        &["protocol", "rip"],
        "passive-interface",
        json!(passive_interfaces_array),
    )?;

    Ok(format!("Interface {} set as passive in RIP.", interface))
}

/// Set the RIP redistribute static routes.
///
/// This function sets the RIP protocol to redistribute static routes. If the
/// RIP protocol is not enabled, it will be enabled first.
///
/// # Parameters
///
/// None.
///
/// # Returns
///
/// A `Result` containing a success message if the operation was successful, or an error message otherwise.

pub fn set_rip_redistribute_static(running_config: &mut RunningConfig) -> Result<String, String> {
    // Execute vtysh command to configure RIP redistribution (only if not in test mode)
    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg("redistribute static")
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to configure RIP to redistribute static routes: {}",
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    // Update the running configuration
    running_config.add_value_to_node(
        &["protocol", "rip", "redistribute"],
        "static",
        json!(true),
    )?;

    Ok("RIP configured to redistribute static routes.".to_string())
}

pub fn set_rip_redistribute_connected(
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if connected routes are already being redistributed
    if running_config
        .get_value_from_node(&["protocol", "rip"], "redistribute_connected")
        .is_some()
    {
        return Ok("Connected route redistribution is already enabled.".to_string());
    }

    if !cfg!(test) {
        // Execute the vtysh command to redistribute connected routes into RIP
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg("redistribute connected")
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to redistribute connected routes into RIP: {}",
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    // Update the running configuration to indicate that connected routes are being redistributed
    running_config.add_value_to_node(
        &["protocol", "rip", "redistribute"],
        "connected",
        json!(true),
    )?;

    Ok("Connected routes redistributed into RIP.".to_string())
}

pub fn set_rip_distance(
    distance: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Step 1: Parse the distance value and handle errors
    let distance: u32 = match distance.parse() {
        Ok(val) => val,
        Err(_) => return Err("Invalid distance value. It should be a number.".to_string()),
    };

    if cfg!(test) {
        running_config.add_value_to_node(&["protocol", "rip"], "distance", json!(distance));
        return Ok(format!(
            "RIP administrative distance set to {} and applied in FRR.",
            distance
        ));
    }

    let output = Command::new("vtysh")
        .arg("-c")
        .arg("configure terminal")
        .arg("-c")
        .arg("router rip")
        .arg("-c")
        .arg(format!("distance {}", distance))
        .output();

    match output {
        Ok(output) if output.status.success() => {
            // Return success message if the command executed successfully
            running_config.add_value_to_node(&["protocol", "rip"], "distance", json!(distance));
            Ok(format!(
                "RIP administrative distance set to {} and applied in FRR.",
                distance
            ))
        }
        Ok(output) => {
            // If the command failed, return the error from the stderr output
            Err(format!(
                "Failed to execute FRR command: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
        Err(e) => {
            // If an error occurred while invoking the command
            Err(format!("Error executing FRR command: {}", e))
        }
    }
}

pub fn set_rip_default_information_originate(
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Step 1: Modify the running configuration to set "default-information originate"
    if cfg!(test) {
        running_config.add_value_to_node(
            &["protocol", "rip"],
            "default-information",
            json!("originate"),
        );
        return Ok("RIP default-information originate set and executed in FRR.".to_string());
    }
    // Step 2: Execute the corresponding FRR command using vtysh
    let output = Command::new("vtysh")
        .arg("-c")
        .arg("configure terminal")
        .arg("-c")
        .arg("router rip")
        .arg("-c")
        .arg("default-information originate")
        .output();

    // Step 3: Check for errors during FRR command execution
    match output {
        Ok(output) if output.status.success() => {
            running_config.add_value_to_node(
                &["protocol", "rip"],
                "default-information",
                json!("originate"),
            );
            // Return success message if command executed successfully
            Ok("RIP default-information originate set and executed in FRR.".to_string())
        }
        Ok(output) => {
            // If command failed, return error with the stderr output
            Err(format!(
                "Failed to execute FRR command: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
        Err(e) => {
            // If an error occurred while invoking the command
            Err(format!("Error executing FRR command: {}", e))
        }
    }
}

pub fn set_rip_authentication(
    mode: &str,
    key_chain: Option<&str>,
    password: Option<&str>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if mode != "text" && mode != "md5" {
        return Err(
            "Invalid RIP authentication mode. Only 'text' or 'md5' are supported.".to_string(),
        );
    }

    if let Some(password) = password {
        if password.len() > 16 {
            return Err("Authentication string must be shorter than 16 characters.".to_string());
        }
    }
    if !cfg!(test) {
        let mut vtysh_command = Command::new("vtysh");
        vtysh_command.arg("-c").arg("configure terminal");
        vtysh_command.arg("-c").arg("router rip");
        vtysh_command
            .arg("-c")
            .arg(format!("ip rip authentication mode {}", mode));

        if let Some(key_chain) = key_chain {
            vtysh_command
                .arg("-c")
                .arg(format!("ip rip authentication key-chain {}", key_chain));
        }

        if let Some(password) = password {
            vtysh_command
                .arg("-c")
                .arg(format!("ip rip authentication string {}", password));
        }

        let auth_result = vtysh_command.output();
        match auth_result {
            Ok(output) => {
                if !output.status.success() {
                    return Err(format!(
                        "Failed to set RIP authentication: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
            Err(e) => return Err(format!("Failed to execute vtysh command: {}", e)),
        }
    }

    // Update the running configuration
    let mut auth_config = json!({ "mode": mode });
    if let Some(key_chain) = key_chain {
        auth_config["key_chain"] = json!(key_chain);
    }
    if let Some(password) = password {
        auth_config["password"] = json!(password);
    }
    running_config.add_value_to_node(&["protocol", "rip"], "authentication", auth_config);

    Ok(format!(
        "RIP authentication set to mode: {}, key_chain: {:?}, password: {:?}",
        mode, key_chain, password
    ))
}

/// Set the RIP send version for a specific interface.
///
/// This function sets the version of RIP packets to send for a particular interface.
/// The `VERSION` can be 1, 2, or both (1 2).
///
/// # Parameters
///
/// * `interface`: The name of the interface.
/// * `version`: The RIP version to send (1, 2, or both).
/// * `running_config`: A mutable reference to the running configuration.
///
/// # Returns
///
/// A `Result` containing a success message if the operation was successful, or an error message otherwise.
pub fn set_rip_send_version(
    version: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if version != "1" && version != "2" && version != "1 2" {
        return Err("Invalid RIP send version. Only '1', '2', or '1 2' are supported.".to_string());
    }

    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("-c")
            .arg(format!("ip rip send version {}", version))
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to set RIP send version {} : {}",
                version,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }
    let version_value = if version == "1" || version == "2" || version == "1 2" {
        json!(version.parse::<u8>().unwrap())
    } else {
        json!(version) // This handles the "1 2" case
    };

    running_config.add_value_to_node(&["protocol", "rip"], "send-version", version_value)?;

    Ok(format!("RIP send version {} set.", version))
}

/// Set the RIP receive version for a specific interface.
///
/// This function sets the version of RIP packets to receive for a particular interface.
/// The `VERSION` can be 1, 2, or both (1 2).
///
/// # Parameters
///
/// * `interface`: The name of the interface.
/// * `version`: The RIP version to receive (1, 2, or both).
/// * `running_config`: A mutable reference to the running configuration.
///
/// # Returns
///
/// A `Result` containing a success message if the operation was successful, or an error message otherwise.
pub fn set_rip_receive_version(
    version: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if version != "1" && version != "2" && version != "1 2" {
        return Err(
            "Invalid RIP receive version. Only '1', '2', or '1 2' are supported.".to_string(),
        );
    }

    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("-c")
            .arg(format!("ip rip receive version {}", version))
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to set RIP receive version {}: {}",
                version,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }
    let version_value = if version == "1" || version == "2" || version == "1 2" {
        json!(version.parse::<u8>().unwrap())
    } else {
        json!(version) // This handles the "1 2" case
    };

    running_config.add_value_to_node(&["protocol", "rip"], "receive-version", version_value)?;

    Ok(format!("RIP receive version {}.", version))
}
/// Set the default administrative distance for RIP routes.
///
/// # Parameters
///
/// * `distance`: The RIP administrative distance (1-255).
/// * `running_config`: A mutable reference to the running configuration.
///
/// # Returns
///
/// A `Result` containing a success message if the operation was successful, or an error message otherwise.
pub fn set_rip_distance_default(
    distance: u8,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if distance < 1 || distance > 255 {
        return Err("Invalid RIP distance value. Must be between 1 and 255.".to_string());
    }

    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg(format!("distance {}", distance))
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to set RIP distance {}: {}",
                distance,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    running_config.add_value_to_node(&["protocol", "rip"], "distance", json!(distance))?;

    Ok(format!("RIP default distance set to {}.", distance))
}
/// Set the RIP administrative distance for routes when the route's source IP address matches a specified prefix.
///
/// # Parameters
///
/// * `distance`: The RIP administrative distance (1-255).
/// * `source_prefix`: The source IP prefix.
/// * `running_config`: A mutable reference to the running configuration.
///
/// # Returns
///
/// A `Result` containing a success message if the operation was successful, or an error message otherwise.
pub fn set_rip_distance_with_prefix(
    distance: u8,
    source_prefix: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if distance < 1 || distance > 255 {
        return Err("Invalid RIP distance value. Must be between 1 and 255.".to_string());
    }

    if !cfg!(test) {
        let vtysh_result = Command::new("vtysh")
            .arg("-c")
            .arg("configure terminal")
            .arg("-c")
            .arg("router rip")
            .arg("-c")
            .arg(format!("distance {} {}", distance, source_prefix))
            .output()
            .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

        if !vtysh_result.status.success() {
            return Err(format!(
                "Failed to set RIP distance {} for prefix {}: {}",
                distance,
                source_prefix,
                String::from_utf8_lossy(&vtysh_result.stderr)
            ));
        }
    }

    running_config.add_value_to_node(
        &["protocol", "rip", "distance"],
        source_prefix,
        json!(distance),
    )?;

    Ok(format!(
        "RIP distance {} set for prefix {}.",
        distance, source_prefix
    ))
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "set protocol rip network <network-ip/prefix>",
            "Add a network to the RIP routing protocol.",
        ),
        (
            "set protocol rip network <interface>",
            "Add a network matching the interface to the RIP routing protocol.",
        ),
        (
            //will add also 12
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
        (
            "set protocol rip authentication <text|md5> [key-chain <KEY-CHAIN>] [string <STRING>]",
            "Set the RIP authentication mode, with an optional key-chain or password.",
        ),
        (
            "set protocol rip send-version <1|2|12>",
            "Override the global RIP version setting for sending packets.",
        ),
        (
            "set protocol rip receive-version <1|2|12>",
            "Override the global RIP version setting for receiving packets.",
        ),
        (
            "set protocol rip distance <distance>",
            "Set the default administrative distance for RIP routes (value between 1 and 255).",
        ),
        (
            "set protocol rip distance <distance> <source-ip/prefix>",
            "Set the RIP distance for routes when the route's source IP address matches the specified prefix.",
        )
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    #[test]
    fn test_set_rip_network_success() {
        let mut running_config = RunningConfig::new();

        // First enable RIP in the configuration
        // running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

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
    fn test_set_rip_interface_success() {
        let mut running_config = RunningConfig::new();

        // Call the function to add an interface to RIP
        let interface = "eth0";
        let result = set_rip_network(interface, &mut running_config);

        // Check if the result is successful
        assert!(
            result.is_ok(),
            "Failed to add interface to RIP: {:?}",
            result.err()
        );

        // Check if the interface was added to the array in the running config
        let networks = running_config
            .get_value_from_node(&["protocol", "rip"], "network")
            .unwrap();
        assert!(
            networks.as_array().unwrap().contains(&json!(interface)),
            "Interface was not added to RIP"
        );
    }

    #[test]
    fn test_set_rip_network_already_added() {
        let mut running_config = RunningConfig::new();

        // Simulate that RIP is enabled and the network is already added
        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        let network = "192.168.1.0/24";
        set_rip_network(network, &mut running_config);
        let result = set_rip_network(network, &mut running_config);

        assert_eq!(
            result.unwrap(),
            format!("Network {} is already added to RIP.", network),
            "RIP should return network already added message"
        );
    }

    #[test]
    fn test_set_rip_interface_already_added() {
        let mut running_config = RunningConfig::new();

        // Simulate that RIP is enabled and the interface is already added
        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        let interface = "eth0";
        set_rip_network(interface, &mut running_config);
        let result = set_rip_network(interface, &mut running_config);

        assert_eq!(
            result.unwrap(),
            format!("Network {} is already added to RIP.", interface),
            "RIP should return interface already added message"
        );
    }

    #[test]
    fn test_parse_set_protocol_rip_command_network() {
        let mut running_config = RunningConfig::new();

        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        let parts = vec!["set", "protocol", "rip", "network", "192.168.1.0/24"];
        let result = parse_set_protocol_rip_command(&parts, &mut running_config);

        assert!(
            result.is_ok(),
            "Failed to parse and add network to RIP: {:?}",
            result.err()
        );

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

    #[test]
    fn test_parse_set_protocol_rip_command_interface() {
        let mut running_config = RunningConfig::new();

        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        let parts = vec!["set", "protocol", "rip", "network", "eth0"];
        let result = parse_set_protocol_rip_command(&parts, &mut running_config);

        assert!(
            result.is_ok(),
            "Failed to parse and add interface to RIP: {:?}",
            result.err()
        );

        let networks = running_config
            .get_value_from_node(&["protocol", "rip"], "network")
            .unwrap();
        assert!(
            networks.as_array().unwrap().contains(&json!("eth0")),
            "Interface was not added to RIP"
        );
    }
    #[test]
    fn test_set_rip_version_success_version_1() {
        let mut running_config = RunningConfig::new();

        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        let result = set_rip_version(1, &mut running_config);

        assert!(
            result.is_ok(),
            "Failed to set RIP version: {:?}",
            result.err()
        );

        let version = running_config
            .get_value_from_node(&["protocol", "rip"], "version")
            .unwrap();
        assert_eq!(version, &json!(1), "RIP version was not set correctly");
    }

    #[test]
    fn test_set_rip_version_success_version_2() {
        let mut running_config = RunningConfig::new();

        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        let result = set_rip_version(2, &mut running_config);

        assert!(
            result.is_ok(),
            "Failed to set RIP version: {:?}",
            result.err()
        );

        let version = running_config
            .get_value_from_node(&["protocol", "rip"], "version")
            .unwrap();
        assert_eq!(version, &json!(2), "RIP version was not set correctly");
    }

    #[test]
    fn test_set_rip_version_invalid_version() {
        let mut running_config = RunningConfig::new();

        running_config.add_value_to_node(&["protocol", "rip"], "enabled", json!(true));

        let result = set_rip_version(3, &mut running_config);

        assert!(result.is_err(), "Expected an error for invalid RIP version");
        assert_eq!(
            result.unwrap_err(),
            "Invalid RIP version. Only version 1 or 2 is supported.",
            "Unexpected error message for invalid version"
        );
    }

    #[test]
    fn test_set_rip_passive_interface_success() {
        let mut running_config = RunningConfig::new();

        running_config
            .add_value_to_node(&["interface"], "eth0", json!({}))
            .unwrap();

        let result = set_rip_passive_interface("eth0", &mut running_config);

        assert!(
            result.is_ok(),
            "Failed to set passive interface for RIP: {:?}",
            result.err()
        );

        let passive_interfaces = running_config
            .get_value_from_node(&["protocol", "rip"], "passive-interface")
            .unwrap();
        assert!(
            passive_interfaces
                .as_array()
                .unwrap()
                .contains(&json!("eth0")),
            "Interface was not set as passive in RIP"
        );
    }

    #[test]
    fn test_set_rip_passive_interface_interface_not_configured() {
        let mut running_config = RunningConfig::new();

        running_config
            .add_value_to_node(&["protocol", "rip"], "enabled", json!(true))
            .unwrap();

        let result = set_rip_passive_interface("eth1", &mut running_config);

        assert!(
            result.is_err(),
            "Expected an error for non-configured interface"
        );
        assert_eq!(
            result.unwrap_err(),
            "Interface eth1 is not configured.",
            "Unexpected error message for non-configured interface"
        );
    }

    #[test]
    fn test_set_rip_passive_interface_already_passive() {
        let mut running_config = RunningConfig::new();

        running_config
            .add_value_to_node(&["protocol", "rip"], "enabled", json!(true))
            .unwrap();

        running_config
            .add_value_to_node(&["interface"], "eth0", json!({}))
            .unwrap();

        running_config
            .add_value_to_node(&["protocol", "rip"], "passive-interface", json!(["eth0"]))
            .unwrap();

        let result = set_rip_passive_interface("eth0", &mut running_config);

        assert!(
            result.is_ok(),
            "Expected a successful result for already passive interface"
        );
        assert_eq!(
            result.unwrap(),
            "Interface eth0 is already a passive interface in RIP.",
            "Unexpected message for already passive interface"
        );
    }
    #[test]
    fn test_set_rip_redistribute_static_success() {
        let mut running_config = RunningConfig::new();

        let result = set_rip_redistribute_static(&mut running_config);

        assert!(
            result.is_ok(),
            "Failed to redistribute static routes: {:?}",
            result.err()
        );

        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip", "redistribute"], "static"),
            Some(&json!(true)),
            "Static route redistribution was not enabled in the RIP configuration"
        );
    }

    #[test]
    fn test_set_rip_redistribute_static_already_set() {
        let mut running_config = RunningConfig::new();

        running_config
            .add_value_to_node(&["protocol", "rip"], "enabled", json!(true))
            .unwrap();
        running_config.add_value_to_node(
            &["protocol", "rip", "redistribute"],
            "static",
            json!(true),
        );

        let result = set_rip_redistribute_static(&mut running_config);

        assert!(
            result.is_ok(),
            "Failed to redistribute static routes: {:?}",
            result.err()
        );
    }
    #[test]
    fn test_set_rip_redistribute_connected_success() {
        let mut running_config = RunningConfig::new();

        let result = set_rip_redistribute_connected(&mut running_config);

        assert!(
            result.is_ok(),
            "Failed to redistribute connected routes: {:?}",
            result.err()
        );

        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip", "redistribute"], "connected"),
            Some(&json!(true)),
            "Connected route redistribution was not enabled in the RIP configuration"
        );
    }

    #[test]
    fn test_set_rip_redistribute_connected_already_set() {
        let mut running_config = RunningConfig::new();

        running_config
            .add_value_to_node(
                &["protocol", "rip", "redistribute"],
                "connected",
                json!(true),
            )
            .unwrap();

        let result = set_rip_redistribute_connected(&mut running_config);

        assert!(
            result.is_ok(),
            "Failed to redistribute connected routes: {:?}",
            result.err()
        );
    }
    #[test]
    fn test_set_rip_distance_success() {
        let mut running_config = RunningConfig::new();
        let distance = "120";

        let result = set_rip_distance(distance, &mut running_config);

        // Verificăm dacă funcția returnează un rezultat Ok
        assert!(
            result.is_ok(),
            "Expected success but got error: {:?}",
            result.err()
        );

        // Verificăm dacă valoarea distanței a fost setată corect în configurație
        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip"], "distance"),
            Some(&json!(120)),
            "RIP distance was not set correctly"
        );
    }

    #[test]
    fn test_set_rip_distance_invalid_value() {
        let mut running_config = RunningConfig::new();
        let distance = "invalid_value"; // Valoare invalidă pentru distanță

        let result = set_rip_distance(distance, &mut running_config);

        // Verificăm dacă funcția returnează o eroare pentru valoare invalidă
        assert!(result.is_err(), "Expected error but got success");
        assert_eq!(
            result.err().unwrap(),
            "Invalid distance value. It should be a number.",
            "Unexpected error message"
        );
    }

    #[test]
    fn test_set_rip_distance_negative_value() {
        let mut running_config = RunningConfig::new();
        let distance = "-10"; // Valoare negativă pentru distanță

        let result = set_rip_distance(distance, &mut running_config);

        // Verificăm dacă funcția returnează o eroare pentru valoare negativă
        assert!(result.is_err(), "Expected error but got success");
        assert_eq!(
            result.err().unwrap(),
            "Invalid distance value. It should be a number.",
            "Unexpected error message for negative number"
        );
    }

    #[test]
    fn test_set_rip_distance_float_value() {
        let mut running_config = RunningConfig::new();
        let distance = "10.5"; // Valoare decimală pentru distanță

        let result = set_rip_distance(distance, &mut running_config);

        // Verificăm dacă funcția returnează o eroare pentru valoare zecimală
        assert!(result.is_err(), "Expected error but got success");
        assert_eq!(
            result.err().unwrap(),
            "Invalid distance value. It should be a number.",
            "Unexpected error message for float number"
        );
    }
    #[test]
    fn test_set_rip_default_information_originate_success() {
        let mut running_config = RunningConfig::new();

        // Call the function
        let result = set_rip_default_information_originate(&mut running_config);

        // Verificăm dacă funcția returnează un rezultat Ok
        assert!(
            result.is_ok(),
            "Expected success but got error: {:?}",
            result.err()
        );

        // Verificăm dacă valoarea a fost setată corect în configurație
        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip"], "default-information"),
            Some(&json!("originate")),
            "RIP default-information originate was not set correctly"
        );
    }

    #[test]
    fn test_set_rip_default_information_originate_updates_existing_config() {
        let mut running_config = RunningConfig::new();

        // Set an initial value for "default-information"
        running_config.add_value_to_node(
            &["protocol", "rip"],
            "default-information",
            json!("none"),
        );

        // Call the function
        let result = set_rip_default_information_originate(&mut running_config);

        // Verificăm dacă funcția returnează un rezultat Ok
        assert!(
            result.is_ok(),
            "Expected success but got error: {:?}",
            result.err()
        );

        // Verificăm dacă valoarea a fost actualizată corect în configurație
        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip"], "default-information"),
            Some(&json!("originate")),
            "RIP default-information originate was not updated correctly"
        );
    }

    #[test]
    fn test_set_rip_default_information_originate_no_unexpected_changes() {
        let mut running_config = RunningConfig::new();

        // Set another value in the config to ensure it is not affected
        running_config.add_value_to_node(&["protocol", "rip"], "distance", json!(120));

        // Call the function
        let result = set_rip_default_information_originate(&mut running_config);

        // Verificăm dacă funcția returnează un rezultat Ok
        assert!(
            result.is_ok(),
            "Expected success but got error: {:?}",
            result.err()
        );

        // Verificăm dacă valoarea default-information a fost setată corect
        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip"], "default-information"),
            Some(&json!("originate")),
            "RIP default-information originate was not set correctly"
        );

        // Verificăm dacă restul configurației a rămas neafectată
        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip"], "distance"),
            Some(&json!(120)),
            "Other configuration values should not be changed"
        );
    }

    #[test]
    fn test_set_rip_authentication_md5() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result = set_rip_authentication("md5", None, None, &mut running_config);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "RIP authentication set to mode: md5, key_chain: None, password: None"
        );

        let auth = running_config
            .config
            .get("protocol")
            .unwrap()
            .get("rip")
            .unwrap()
            .get("authentication")
            .unwrap();
        assert_eq!(auth["mode"], "md5");
    }

    #[test]
    fn test_set_rip_authentication_invalid() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result = set_rip_authentication("invalid", None, None, &mut running_config);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid RIP authentication mode. Only 'text' or 'md5' are supported."
        );
    }

    #[test]
    fn test_set_rip_authentication_text() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result = set_rip_authentication("text", None, Some("simplepass"), &mut running_config);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "RIP authentication set to mode: text, key_chain: None, password: Some(\"simplepass\")"
        );

        let auth = running_config
            .config
            .get("protocol")
            .unwrap()
            .get("rip")
            .unwrap()
            .get("authentication")
            .unwrap();
        assert_eq!(auth["mode"], "text");
        assert_eq!(auth["password"], "simplepass");
    }

    #[test]
    fn test_set_rip_authentication_md5_with_key_chain() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result = set_rip_authentication("md5", Some("test-chain"), None, &mut running_config);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "RIP authentication set to mode: md5, key_chain: Some(\"test-chain\"), password: None"
        );

        let auth = running_config
            .config
            .get("protocol")
            .unwrap()
            .get("rip")
            .unwrap()
            .get("authentication")
            .unwrap();
        assert_eq!(auth["mode"], "md5");
        assert_eq!(auth["key_chain"], "test-chain");
    }

    #[test]
    fn test_set_rip_authentication_invalid_mode() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result = set_rip_authentication("invalid", None, None, &mut running_config);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid RIP authentication mode. Only 'text' or 'md5' are supported."
        );
    }

    #[test]
    fn test_set_rip_authentication_password_too_long() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result = set_rip_authentication(
            "text",
            None,
            Some("thispasswordiswaytoolong"),
            &mut running_config,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Authentication string must be shorter than 16 characters."
        );
    }
    #[test]
    fn test_set_rip_send_version_success() {
        let mut running_config = RunningConfig::new();

        // Simulate that the interface is configured
        running_config.add_value_to_node(&["protocol", "rip"], "send-version", json!({}));

        let result = set_rip_send_version("1", &mut running_config);

        // Check if the result is successful
        assert!(
            result.is_ok(),
            "Failed to set RIP send version: {:?}",
            result.err()
        );

        // Check if the send version was set in the running configuration
        let send_version = running_config
            .get_value_from_node(&["protocol", "rip"], "send-version")
            .unwrap();
        assert_eq!(send_version, 1, "RIP send version was not set correctly");
    }

    #[test]
    fn test_set_rip_send_version_invalid() {
        let mut running_config = RunningConfig::new();

        // Simulate that the interface is configured
        running_config.add_value_to_node(&["interface"], "eth0", json!({}));

        let result = set_rip_send_version("3", &mut running_config);

        // Check if the result is an error due to an invalid version
        assert!(
            result.is_err(),
            "Expected an error for invalid RIP send version"
        );
        assert_eq!(
            result.unwrap_err(),
            "Invalid RIP send version. Only '1', '2', or '1 2' are supported.",
            "Unexpected error message for invalid send version"
        );
    }

    #[test]
    fn test_set_rip_distance_default_success() {
        let mut running_config = RunningConfig::new();
        let distance = 120;

        let result = set_rip_distance_default(distance, &mut running_config);

        assert!(
            result.is_ok(),
            "Expected success but got error: {:?}",
            result.err()
        );
        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip"], "distance"),
            Some(&json!(distance)),
            "RIP default distance was not set correctly"
        );
    }

    #[test]
    #[test]
    fn test_set_rip_distance_with_prefix_success() {
        let mut running_config = RunningConfig::new();
        let distance = 150;
        let source_prefix = "192.168.1.0/24";

        let result = set_rip_distance_with_prefix(distance, source_prefix, &mut running_config);

        assert!(
            result.is_ok(),
            "Expected success but got error: {:?}",
            result.err()
        );
        assert_eq!(
            running_config.get_value_from_node(&["protocol", "rip", "distance"], source_prefix),
            Some(&json!(distance)),
            "RIP distance for prefix was not set correctly"
        );
    }

    #[test]
    fn test_set_rip_distance_with_prefix_invalid_value() {
        let mut running_config = RunningConfig::new();
        let distance = 0; // Invalid value
        let source_prefix = "192.168.1.0/24";

        let result = set_rip_distance_with_prefix(distance, source_prefix, &mut running_config);

        assert!(result.is_err(), "Expected an error but got success");
        assert_eq!(
            result.unwrap_err(),
            "Invalid RIP distance value. Must be between 1 and 255.",
            "Unexpected error message for invalid distance value"
        );
    }
}
