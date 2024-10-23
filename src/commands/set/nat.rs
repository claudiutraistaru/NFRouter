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
use crate::{commands::show::currentconfig, config::RunningConfig};
use ipnetwork::IpNetwork;
use serde_json::{json, Value};
use std::{net::IpAddr, process::Command};

pub fn parse_set_nat(parts: &[&str], running_config: &mut RunningConfig) -> Result<String, String> {
    match parts {
        ["set", "nat", "masquerade", "from", from_zone, "to", to_zone] => {
            set_nat_masquerade(from_zone.to_string(), to_zone.to_string(), running_config)
        }
        //"set nat snat from zone <trust|untrust> to <public_ip>",
        ["set", "nat", "snat", "from", "zone", from_zone, "to", to_public_ip] => set_nat_snat(
            from_zone.to_string(),
            to_public_ip.to_string(),
            running_config,
        ),
        //set nat dnat from <public_ip>:<public_port> to <private_ip>:<private_port>
        ["set", "nat", "dnat", "from", from_public_ip, from_public_port, "to", to_private_ip, to_private_port] => {
            set_nat_dnat(
                from_public_ip.to_string(),
                from_public_port
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid public port: '{}'", from_public_port))?,
                to_private_ip.to_string(),
                to_private_port
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid public port: '{}'", from_public_port))?,
                running_config,
            )
        }
        //"set nat snat from zone <private_ip> to <public_ip>",
        ["set", "nat", "snat", "from", "zone", from_zone, private_ip, "to", public_ip] => {
            set_nat_snat_private_to_public(
                from_zone.to_string(),
                private_ip.to_string(),
                public_ip.to_string(),
                running_config,
            )
        }

        _ => Err("Invalid nat command".to_string()),
    }
}
pub fn set_nat_masquerade(
    from_zone: String,
    to_zone: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if IP forwarding is enabled in the running configuration
    let ip_forwarding_enabled = running_config
        .get_value_from_node(&["system", "ipforwarding"], "enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !ip_forwarding_enabled {
        return Err("IP forwarding is not enabled. Please enable it with 'set system ipforwarding enabled'.".to_string());
    }

    // Check if both zones are defined on interfaces and find the interface name for to_zone
    let interfaces = running_config.config["interface"]
        .as_object()
        .ok_or("No interfaces configured")?;

    let mut from_zone_defined = false;
    let mut to_zone_defined = false;
    let mut to_zone_interface = None;

    for (interface, config) in interfaces.iter() {
        if let Some(zone) = config["zone"].as_str() {
            if zone == from_zone {
                from_zone_defined = true;
            }
            if zone == to_zone {
                to_zone_defined = true;
                to_zone_interface = Some(interface.clone());
            }
        }
    }

    if !from_zone_defined {
        return Err(format!(
            "Zone '{}' is not defined on any interface.",
            from_zone
        ));
    }

    if !to_zone_defined {
        return Err(format!(
            "Zone '{}' is not defined on any interface.",
            to_zone
        ));
    }

    let to_zone_interface = to_zone_interface.ok_or_else(|| {
        format!(
            "No interface found for zone '{}'. Ensure the zone is correctly associated with an interface.",
            to_zone
        )
    })?;
    // Update the running configuration
    let nat_config = json!({
        "from": from_zone,
        "to": to_zone,
    });
    let command_args = vec![
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        "POSTROUTING".to_string(),
        "-o".to_string(),
        to_zone_interface.clone(), // Clone because Command::new() takes ownership
        "-j".to_string(),
        "MASQUERADE".to_string(),
    ];

    // Display the command for debugging or logging purposes
    println!("Executing command: iptables {}", command_args.join(" "));
    if cfg!(test) {
        running_config.add_value_to_node(&["nat"], &format!("masquerade"), nat_config)?;

        return Ok(format!(
            "Enabled NAT masquerade from zone '{}' to zone '{}' (interface: '{}')",
            from_zone, to_zone, to_zone_interface
        ));
    }
    // Set up NAT masquerade using iptables with the identified interface for to_zone
    let nat_result = Command::new("iptables")
        .args(&command_args)
        .output()
        .map_err(|e| format!("Failed to set up NAT masquerade: {}", e))?;

    if !nat_result.status.success() {
        return Err(format!(
            "Failed to set up NAT masquerade: {}",
            String::from_utf8_lossy(&nat_result.stderr)
        ));
    }

    running_config.add_value_to_node(&["nat"], &format!("masquerade"), nat_config)?;

    Ok(format!(
        "Enabled NAT masquerade from zone '{}' to zone '{}' (interface: '{}')",
        from_zone, to_zone, to_zone_interface
    ))
}
pub fn set_nat_snat(
    from_zone: String,
    to_public_ip: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if IP forwarding is enabled in the running configuration
    let ip_forwarding_enabled = running_config
        .get_value_from_node(&["system", "ipforwarding"], "enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !ip_forwarding_enabled {
        return Err("IP forwarding is not enabled. Please enable it with 'set system ipforwarding enabled'.".to_string());
    }

    // Check if the from_zone is defined on any interface
    let interfaces = running_config.config["interface"]
        .as_object()
        .ok_or("No interfaces configured")?;

    let mut from_zone_defined = false;
    let mut from_zone_interface = None;

    for (interface, config) in interfaces.iter() {
        if let Some(zone) = config["zone"].as_str() {
            if zone == from_zone {
                from_zone_defined = true;
                from_zone_interface = Some(interface.clone());
            }
        }
    }

    if !from_zone_defined {
        return Err(format!(
            "Zone '{}' is not defined on any interface.",
            from_zone
        ));
    }

    let from_zone_interface = from_zone_interface.ok_or_else(|| {
        format!(
            "No interface found for zone '{}'. Ensure the zone is correctly associated with an interface.",
            from_zone
        )
    })?;

    // Update the running configuration by appending the new SNAT rule to the array
    let nat_config = json!({
        "from": {
            "zone": from_zone
        },
        "to": to_public_ip,
    });

    let mut snat_entries = running_config
        .get_value_from_node(&["nat"], "snat")
        .cloned()
        .unwrap_or_else(|| json!([])); // Get existing SNAT array or create a new one

    if let Some(snat_array) = snat_entries.as_array_mut() {
        snat_array.push(nat_config); // Append the new SNAT entry
    } else {
        return Err("Failed to append to SNAT array".to_string());
    }

    running_config.add_value_to_node(&["nat"], "snat", snat_entries)?;

    // Build the iptables command arguments
    let command_args = vec![
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        "POSTROUTING".to_string(),
        "-o".to_string(),
        from_zone_interface.to_string(),
        "-j".to_string(),
        "SNAT".to_string(),
        "--to-source".to_string(),
        to_public_ip.to_string(),
    ];

    // Optionally set up iptables rules if not in test mode
    if !cfg!(test) {
        let snat_result = Command::new("iptables")
            .args(command_args)
            .output()
            .map_err(|e| format!("Failed to set up NAT SNAT: {}", e))?;

        if !snat_result.status.success() {
            return Err(format!(
                "Failed to set up NAT SNAT: {}",
                String::from_utf8_lossy(&snat_result.stderr)
            ));
        }
    }

    Ok(format!(
        "Enabled NAT SNAT from zone '{}' (interface: '{}') to public IP '{}'",
        from_zone, from_zone_interface, to_public_ip
    ))
}

pub fn set_nat_snat_private_to_public(
    from_zone: String,
    private_ip: String,
    public_ip: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if IP forwarding is enabled in the running configuration
    let ip_forwarding_enabled = running_config
        .get_value_from_node(&["system", "ipforwarding"], "enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !ip_forwarding_enabled {
        return Err("IP forwarding is not enabled. Please enable it with 'set system ipforwarding enabled'.".to_string());
    }

    // Check if the from_zone is defined on any interface
    let interfaces = running_config.config["interface"]
        .as_object()
        .ok_or("No interfaces configured")?;

    let mut from_zone_defined = false;
    let mut from_zone_interface = None;
    let mut interface_cidr: Option<IpNetwork> = None;

    for (interface, config) in interfaces.iter() {
        if let Some(zone) = config["zone"].as_str() {
            if zone == from_zone {
                from_zone_defined = true;
                from_zone_interface = Some(interface.clone());

                // Get the IP and CIDR from the interface config (assuming "ip" field exists)
                if let Some(ip_str) = config["ip"].as_str() {
                    if let Ok(ip_network) = ip_str.parse::<IpNetwork>() {
                        interface_cidr = Some(ip_network);
                    }
                }
            }
        }
    }

    if !from_zone_defined {
        return Err(format!(
            "Zone '{}' is not defined on any interface.",
            from_zone
        ));
    }

    let from_zone_interface = from_zone_interface.ok_or_else(|| {
        format!(
            "No interface found for zone '{}'. Ensure the zone is correctly associated with an interface.",
            from_zone
        )
    })?;
    println!("interfaces config is {:?}", &interfaces);
    let interface_cidr = interface_cidr.ok_or_else(|| {
        format!(
            "No CIDR information found for the interface in zone '{}'.",
            from_zone
        )
    })?;

    // Check if the private_ip is within the interface's CIDR range
    let private_ip_addr: IpAddr = private_ip
        .parse()
        .map_err(|_| "Invalid IP address, The ip address must be from the same class as the interface defined in the zone")?;
    if !interface_cidr.contains(private_ip_addr) {
        return Err(format!(
            "Private IP '{}' is not in the CIDR range '{}' of the interface in zone '{}'.",
            private_ip, interface_cidr, from_zone
        ));
    }

    // Check that the public_ip belongs to an interface in the external zone
    let mut external_zone_interface: Option<String> = None;
    for (interface, config) in interfaces.iter() {
        if let Some(zone) = config["zone"].as_str() {
            if zone == "external" {
                if let Some(ip_str) = config["ip"].as_str() {
                    if ip_str == public_ip {
                        external_zone_interface = Some(interface.clone());
                        break;
                    }
                }
            }
        }
    }

    let external_zone_interface = external_zone_interface.ok_or_else(|| {
        format!(
            "The public IP '{}' does not exist on any interface in the 'external' zone.",
            public_ip
        )
    })?;

    // Update the running configuration by appending the new SNAT rule to the array
    let nat_config = json!({
        "from_zone": from_zone,
        "private_ip": private_ip,
        "public_ip": public_ip,
    });

    let mut snat_entries = running_config
        .get_value_from_node(&["nat"], "snat")
        .cloned()
        .unwrap_or_else(|| json!([])); // Get existing SNAT array or create a new one

    if let Some(snat_array) = snat_entries.as_array_mut() {
        snat_array.push(nat_config); // Append the new SNAT entry
    } else {
        return Err("Failed to append to SNAT array".to_string());
    }

    running_config.add_value_to_node(&["nat"], "snat", snat_entries)?;

    // Set up SNAT using iptables with the identified interface for from_zone
    if !cfg!(test) {
        let snat_result = Command::new("iptables")
            .arg("-t")
            .arg("nat")
            .arg("-A")
            .arg("POSTROUTING")
            .arg("-o")
            .arg(&external_zone_interface) // Use the external interface for SNAT
            .arg("-s")
            .arg(&private_ip)
            .arg("-j")
            .arg("SNAT")
            .arg("--to-source")
            .arg(&public_ip)
            .output()
            .map_err(|e| format!("Failed to set up NAT SNAT: {}", e))?;

        if !snat_result.status.success() {
            return Err(format!(
                "Failed to set up NAT SNAT: {}",
                String::from_utf8_lossy(&snat_result.stderr)
            ));
        }
    }

    Ok(format!(
        "Enabled NAT SNAT from private IP '{}' in zone '{}' (interface: '{}') to public IP '{}' (external interface: '{}')",
        private_ip, from_zone, from_zone_interface, public_ip, external_zone_interface
    ))
}

pub fn set_nat_dnat(
    public_ip: String,
    public_port: u16,
    private_ip: String,
    private_port: u16,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if IP forwarding is enabled
    let ip_forwarding_enabled = running_config
        .get_value_from_node(&["system", "ipforwarding"], "enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !ip_forwarding_enabled {
        return Err("IP forwarding is not enabled. Please enable it with 'set system ipforwarding enabled'.".to_string());
    }

    // Update the running configuration by appending the new DNAT rule to the array
    let nat_config = json!({
        "from": {
            &public_ip: &public_port
        },
        "to": {
            &private_ip: &private_port
        }
    });

    let mut dnat_entries = running_config
        .get_value_from_node(&["nat"], "dnat")
        .cloned()
        .unwrap_or_else(|| json!([])); // Get existing DNAT array or create a new one

    if let Some(dnat_array) = dnat_entries.as_array_mut() {
        dnat_array.push(nat_config); // Append the new DNAT entry
    } else {
        return Err("Failed to append to DNAT array".to_string());
    }

    running_config.add_value_to_node(&["nat"], "dnat", dnat_entries)?;

    // Optionally set up iptables rules if not in test mode
    if !cfg!(test) {
        let dnat_result = Command::new("iptables")
            .arg("-t")
            .arg("nat")
            .arg("-A")
            .arg("PREROUTING")
            .arg("-d")
            .arg(&public_ip)
            .arg("-p")
            .arg("tcp")
            .arg("--dport")
            .arg(public_port.to_string())
            .arg("-j")
            .arg("DNAT")
            .arg("--to-destination")
            .arg(format!("{}:{}", &private_ip, &private_port))
            .output()
            .map_err(|e| format!("Failed to set up NAT DNAT: {}", e))?;

        if !dnat_result.status.success() {
            return Err(format!(
                "Failed to set up NAT DNAT: {}",
                String::from_utf8_lossy(&dnat_result.stderr)
            ));
        }
    }

    Ok(format!(
        "Enabled NAT DNAT from public IP '{}:{}' to private IP '{}:{}'",
        public_ip, public_port, private_ip, private_port
    ))
}

// Help command for NAT masquerade
pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![(
        "set nat masquerade from <zonename> to <zonename>",
        "Enable NAT type MASQUERADE from a zone to another.",
    ),
    (
        "set nat snat from zone <zonename> to <public_ip>",
        "Enable Source NAT (SNAT) from a trusted or untrusted zone to a public IP.",
    ),
    (
        "set nat snat from zone <zonename> <private_ip> to <public_ip>",
        "Enable Source NAT (SNAT) for traffic from a specific private IP in a zone to a public IP.",
    ),
    (
        "set nat dnat from <public_ip> <public_port> to <private_ip> <private_port>",
        "Enable Destination NAT (DNAT) to forward traffic from a public IP and port to a private IP and port.",
    )]
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    fn setup_running_config_with_zones(
        running_config: &mut RunningConfig,
        interface: &str,
        zone: &str,
        zone_ip: &str,
    ) {
        // Add interfaces with zones and assign IPs
        running_config
            .add_value_to_node(&["interface", &interface], "zone", json!(zone))
            .unwrap();
        running_config
            .add_value_to_node(&["interface", &interface], "ip", json!(zone_ip))
            .unwrap();
    }

    #[test]
    fn test_set_nat_masquerade_no_interfaces_configured() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        // Call the function with no interfaces configured
        let from_zone = "internal";
        let to_zone = "external";

        let result = set_nat_masquerade(
            from_zone.to_string(),
            to_zone.to_string(),
            &mut running_config,
        );

        assert!(result.is_err(), "Expected error but got success");
        assert_eq!(
            result.unwrap_err(),
            format!("Zone '{}' is not defined on any interface.", from_zone)
        );
    }

    #[test]
    fn test_set_nat_snat_success() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding in the system configuration
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        let from_zone = "trust";
        let public_ip = "203.0.113.1/24";
        let private_ip = "192.168.1.1/24";

        // Set up from_zone in the running configuration
        setup_running_config_with_zones(&mut running_config, "eth0", "unrelated", public_ip);
        setup_running_config_with_zones(&mut running_config, "eth1", from_zone, private_ip);

        // Call the function to set up SNAT
        let result = set_nat_snat(
            from_zone.to_string(),
            public_ip.to_string(),
            &mut running_config,
        );

        // Assert that the result is OK
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that SNAT configuration was added to running config
        let expected_nat_config = json!({
            "from": {
                "zone": from_zone
            },
            "to": public_ip,
        });

        // Check if the NAT SN
    }

    fn test_set_nat_dnat_success() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding in the system configuration
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        let public_ip = "203.0.113.1";
        let public_port = 8080;
        let private_ip = "192.168.1.10";
        let private_port = 80;

        // Call the function to set up DNAT
        let result = set_nat_dnat(
            public_ip.to_string(),
            public_port,
            private_ip.to_string(),
            private_port,
            &mut running_config,
        );

        // Assert that the result is OK
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that DNAT private-to-public configuration was added to running config
        let expected_nat_config = json!({
            "public_ip": public_ip,
            "public_port": public_port,
            "private_ip": private_ip,
            "private_port": private_port,
        });

        // Check if the NAT DNAT configuration is an array containing the expected object
        let nat_dnat = running_config.get_value_from_node(&["nat"], "dnat");
        assert!(
            nat_dnat.is_some(),
            "NAT DNAT configuration not set in RunningConfig"
        );

        if let Some(Value::Array(arr)) = nat_dnat {
            assert!(
                arr.contains(&expected_nat_config),
                "NAT DNAT configuration not set correctly in RunningConfig"
            );
        } else {
            panic!("NAT DNAT configuration is not an array as expected");
        }
    }

    fn test_add_multiple_snat_rules() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding in the system configuration
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        let interface_1 = "eth0";
        let from_zone_1 = "trust";
        let public_ip_1 = "203.0.112.1/24";
        let private_ip_1 = "192.168.1.1/24";

        let interface_2 = "eth1";
        let from_zone_2 = "untrust";
        let public_ip_2 = "203.0.113.2/24";
        let private_ip_2 = "192.168.2.1/24";

        // Set up zones in the running configuration using the new setup function
        setup_running_config_with_zones(
            &mut running_config,
            interface_1,
            from_zone_1,
            private_ip_1,
        );

        setup_running_config_with_zones(
            &mut running_config,
            interface_2,
            from_zone_2,
            private_ip_2,
        );

        // Add first SNAT rule
        let result1 = set_nat_snat(
            from_zone_1.to_string(),
            public_ip_1.to_string(),
            &mut running_config,
        );
        assert!(
            result1.is_ok(),
            "Test failed with error: {:?}",
            result1.err()
        );

        // Add second SNAT rule
        let result2 = set_nat_snat(
            from_zone_2.to_string(),
            public_ip_2.to_string(),
            &mut running_config,
        );
        assert!(
            result2.is_ok(),
            "Test failed with error: {:?}",
            result2.err()
        );

        // Verify that both SNAT rules are stored in the running configuration
        let expected_snat_config = json!([
            {
                "from": from_zone_1,
                "to_public_ip": public_ip_1,
            },
            {
                "from": from_zone_2,
                "to_public_ip": public_ip_2,
            }
        ]);

        let snat_config = running_config.get_value_from_node(&["nat"], "snat");
        assert!(
            snat_config.is_some(),
            "SNAT configuration not set in RunningConfig"
        );

        if let Some(Value::Array(arr)) = snat_config {
            assert!(
                arr.contains(&expected_snat_config[0]) && arr.contains(&expected_snat_config[1]),
                "Multiple SNAT rules not set correctly in RunningConfig"
            );
        } else {
            panic!("SNAT configuration is not an array as expected");
        }
    }

    #[test]
    fn test_add_multiple_dnat_rules() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding in the system configuration
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        let public_ip_1 = "203.0.113.1";
        let public_port_1 = 8080;
        let private_ip_1 = "192.168.1.10";
        let private_port_1 = 80;

        let public_ip_2 = "203.0.113.2";
        let public_port_2 = 8081;
        let private_ip_2 = "192.168.1.11";
        let private_port_2 = 443;

        // Add first DNAT rule
        let result1 = set_nat_dnat(
            public_ip_1.to_string(),
            public_port_1,
            private_ip_1.to_string(),
            private_port_1,
            &mut running_config,
        );
        assert!(
            result1.is_ok(),
            "Test failed with error: {:?}",
            result1.err()
        );

        // Add second DNAT rule
        let result2 = set_nat_dnat(
            public_ip_2.to_string(),
            public_port_2,
            private_ip_2.to_string(),
            private_port_2,
            &mut running_config,
        );
        assert!(
            result2.is_ok(),
            "Test failed with error: {:?}",
            result2.err()
        );

        // Verify that both DNAT rules are stored in the running configuration
        let expected_dnat_config = json!([
            {
                "from": {
                    public_ip_1: public_port_1
                },
                "to": {
                    private_ip_1: private_port_1
                }
            },
            {
                "from": {
                    public_ip_2: public_port_2
                },
                "to": {
                    private_ip_2: private_port_2
                }
            }
        ]);

        assert_eq!(
            running_config.get_value_from_node(&["nat"], "dnat"),
            Some(&expected_dnat_config),
            "Multiple DNAT rules not set correctly in RunningConfig"
        );
    }

    #[test]
    fn test_set_nat_masquerade_success() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding in the system configuration
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        // Set up from_zone and to_zone
        let from_zone = "internal";
        let to_zone = "external";
        let private_ip = "192.168.1.1/24";
        let public_ip = "203.22.33.2/24";

        let interface_1 = "eth0";
        let interface_2 = "eth1";

        // Configure running config with interfaces and zones
        setup_running_config_with_zones(&mut running_config, interface_1, from_zone, private_ip);

        setup_running_config_with_zones(&mut running_config, interface_2, to_zone, public_ip);

        // Simulate success of iptables command (in test mode)
        let result = set_nat_masquerade(
            from_zone.to_string(),
            to_zone.to_string(),
            &mut running_config,
        );

        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that NAT masquerade configuration was added to running config
        let expected_nat_config = json!({
            "from": from_zone,
            "to": to_zone,
        });

        let nat_masquerade = running_config.get_value_from_node(&["nat"], "masquerade");
        assert!(
            nat_masquerade.is_some(),
            "NAT masquerade configuration not set in RunningConfig"
        );

        if let Some(Value::Object(obj)) = nat_masquerade {
            // Convert expected_nat_config to a map for comparison
            let expected_map = expected_nat_config.as_object().unwrap();

            assert_eq!(
                obj, expected_map,
                "NAT masquerade configuration not set correctly in RunningConfig"
            );
        } else {
            panic!("NAT masquerade configuration is not an object as expected");
        }
    }

    #[test]
    fn test_set_nat_masquerade_ip_forwarding_disabled() {
        let mut running_config = RunningConfig::new();

        // IP forwarding is disabled by default (not enabled in this test)
        let from_zone = "internal";
        let to_zone = "external";
        let private_ip = "192.168.1.1/24";
        let public_ip = "203.23.22.11/24";

        let interface_1 = "eth0";
        let interface_2 = "eth1";

        // Configure running config with interfaces and zones, but don't enable IP forwarding
        setup_running_config_with_zones(&mut running_config, interface_1, from_zone, private_ip);

        setup_running_config_with_zones(&mut running_config, interface_2, to_zone, public_ip);

        // Call the function
        let result = set_nat_masquerade(
            from_zone.to_string(),
            to_zone.to_string(),
            &mut running_config,
        );

        // Ensure that the result is an error due to disabled IP forwarding
        assert!(result.is_err(), "Expected error but got success");
        assert_eq!(
        result.unwrap_err(),
        "IP forwarding is not enabled. Please enable it with 'set system ipforwarding enabled'."
    );
    }

    #[test]
    fn test_set_nat_masquerade_zone_not_defined() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        // Set up only from_zone, but not to_zone
        let from_zone = "internal";
        let to_zone = "non_existent_zone";

        // Configure running config with only the from_zone
        running_config
            .add_value_to_node(&["interface", "eth0"], "zone", json!(from_zone))
            .unwrap();

        // Call the function
        let result = set_nat_masquerade(
            from_zone.to_string(),
            to_zone.to_string(),
            &mut running_config,
        );

        assert!(result.is_err(), "Expected error but got success");
        assert_eq!(
            result.unwrap_err(),
            format!("Zone '{}' is not defined on any interface.", to_zone)
        );
    }

    #[test]
    fn test_set_nat_snat_private_to_public_success() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding in the system configuration
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        let from_zone = "internal";
        let private_ip = "192.168.1.10"; // IP within the 192.168.1.0/24 range
        let public_ip = "203.0.113.2"; // Public IP does not need a /24 for this test

        let interface_1 = "eth0"; // Interface for internal zone
        let interface_ip = "192.168.1.1/24"; // Interface IP with the subnet mask
        let interface_2 = "eth1"; // Interface for external zone

        // Set up from_zone in the running configuration with the respective IP addresses
        setup_running_config_with_zones(
            &mut running_config,
            interface_1,
            from_zone,
            interface_ip, // Internal interface CIDR
        );

        setup_running_config_with_zones(
            &mut running_config,
            interface_2,
            "external",
            public_ip, // External interface IP (no CIDR needed for this example)
        );

        // Call the function to set up SNAT from private to public IP
        let result = set_nat_snat_private_to_public(
            from_zone.to_string(),
            private_ip.to_string(), // Only the IP address, no CIDR
            public_ip.to_string(),  // Only the IP address, no CIDR
            &mut running_config,
        );

        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that SNAT private-to-public configuration was added to running config
        let expected_nat_config = json!({
            "from_zone": from_zone,
            "private_ip": private_ip,
            "public_ip": public_ip,
        });

        let nat_snat = running_config.get_value_from_node(&["nat"], "snat");
        assert!(
            nat_snat.is_some(),
            "SNAT configuration not set in RunningConfig"
        );

        if let Some(Value::Array(arr)) = nat_snat {
            assert!(
                arr.contains(&expected_nat_config),
                "SNAT private-to-public configuration not set correctly in RunningConfig"
            );
        } else {
            panic!("SNAT configuration is not an array as expected");
        }
    }

    #[test]
    fn test_snat_with_multiple_interfaces() {
        let mut running_config = RunningConfig::new();

        // Enable IP forwarding in the system configuration
        running_config
            .add_value_to_node(&["system", "ipforwarding"], "enabled", json!(true))
            .unwrap();

        // Define zones and interfaces
        let external_ip = "203.0.113.1/24";
        let from_zone = "internal";
        let private_ip = "192.168.1.10";

        // Configure running config with multiple interfaces
        running_config
            .add_value_to_node(&["interface", "eth0"], "zone", json!("external"))
            .unwrap();
        running_config
            .add_value_to_node(&["interface", "eth0"], "ip", json!(external_ip))
            .unwrap();

        // Here, we set the internal interface with the correct CIDR range
        running_config
            .add_value_to_node(&["interface", "eth1"], "zone", json!(from_zone))
            .unwrap();
        running_config
            .add_value_to_node(&["interface", "eth1"], "ip", json!("192.168.1.1/24"))
            .unwrap(); // Note: Set as 192.168.1.1/24 to match private IP

        // Set the SNAT rule
        let result = set_nat_snat_private_to_public(
            from_zone.to_string(),
            private_ip.to_string(),
            external_ip.to_string(),
            &mut running_config,
        );
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that the SNAT rule is stored in the running configuration
        let expected_snat_config = json!([
            {
                "from_zone": from_zone,
                "private_ip": private_ip,
                "public_ip": external_ip,
            }
        ]);

        assert_eq!(
            running_config.get_value_from_node(&["nat"], "snat"),
            Some(&expected_snat_config),
            "SNAT rule not set correctly in RunningConfig"
        );
    }
}
