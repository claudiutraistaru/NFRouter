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
use serde_json::json;
use std::process::Command;
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
    if cfg!(test) {
        running_config.add_value_to_node(&["nat"], &format!("masquerade"), nat_config)?;

        return Ok(format!(
            "Enabled NAT masquerade from zone '{}' to zone '{}' (interface: '{}')",
            from_zone, to_zone, to_zone_interface
        ));
    }
    // Set up NAT masquerade using iptables with the identified interface for to_zone
    let nat_result = Command::new("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-A")
        .arg("POSTROUTING")
        .arg("-o")
        .arg(&to_zone_interface)
        .arg("-j")
        .arg("MASQUERADE")
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

    // Update the running configuration
    let nat_config = json!({
        "from": from_zone,
        "to_public_ip": to_public_ip,
    });
    if cfg!(test) {
        running_config.add_value_to_node(&["nat"], &format!("snat"), nat_config)?;

        return Ok(format!(
            "Enabled NAT SNAT from zone '{}' (interface: '{}') to public IP '{}'",
            from_zone, from_zone_interface, to_public_ip
        ));
    }

    // Set up SNAT using iptables with the identified interface for from_zone
    let snat_result = Command::new("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-A")
        .arg("POSTROUTING")
        .arg("-o")
        .arg(&from_zone_interface)
        .arg("-j")
        .arg("SNAT")
        .arg("--to-source")
        .arg(&to_public_ip)
        .output()
        .map_err(|e| format!("Failed to set up NAT SNAT: {}", e))?;

    if !snat_result.status.success() {
        return Err(format!(
            "Failed to set up NAT SNAT: {}",
            String::from_utf8_lossy(&snat_result.stderr)
        ));
    }

    running_config.add_value_to_node(&["nat"], &format!("snat"), nat_config)?;

    Ok(format!(
        "Enabled NAT SNAT from zone '{}' (interface: '{}') to public IP '{}'",
        from_zone, from_zone_interface, to_public_ip
    ))
}

pub fn set_nat_dnat(
    public_ip: String,
    public_port: u16,
    private_ip: String,
    private_port: u16,
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

    // Update the running configuration
    let nat_config = json!({
        "public_ip": public_ip,
        "public_port": public_port,
        "private_ip": private_ip,
        "private_port": private_port,
    });
    if cfg!(test) {
        running_config.add_value_to_node(&["nat"], &format!("dnat"), nat_config)?;

        return Ok(format!(
            "Enabled NAT DNAT from public IP '{}:{}' to private IP '{}:{}'",
            public_ip, public_port, private_ip, private_port
        ));
    }

    // Set up DNAT using iptables
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
        .arg(format!("{}:{}", private_ip, private_port))
        .output()
        .map_err(|e| format!("Failed to set up NAT DNAT: {}", e))?;

    if !dnat_result.status.success() {
        return Err(format!(
            "Failed to set up NAT DNAT: {}",
            String::from_utf8_lossy(&dnat_result.stderr)
        ));
    }

    running_config.add_value_to_node(&["nat"], &format!("dnat"), nat_config)?;

    Ok(format!(
        "Enabled NAT DNAT from public IP '{}:{}' to private IP '{}:{}'",
        public_ip, public_port, private_ip, private_port
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

    // Update the running configuration
    let nat_config = json!({
        "from_zone": from_zone,
        "private_ip": private_ip,
        "public_ip": public_ip,
    });
    if cfg!(test) {
        running_config.add_value_to_node(
            &["nat"],
            &format!("snat_private_to_public"),
            nat_config,
        )?;

        return Ok(format!(
            "Enabled NAT SNAT from private IP '{}' in zone '{}' (interface: '{}') to public IP '{}'",
            private_ip, from_zone, from_zone_interface, public_ip
        ));
    }

    // Set up SNAT using iptables with the identified interface for from_zone
    let snat_result = Command::new("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-A")
        .arg("POSTROUTING")
        .arg("-o")
        .arg(&from_zone_interface)
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

    running_config.add_value_to_node(&["nat"], &format!("snat_private_to_public"), nat_config)?;

    Ok(format!(
        "Enabled NAT SNAT from private IP '{}' in zone '{}' (interface: '{}') to public IP '{}'",
        private_ip, from_zone, from_zone_interface, public_ip
    ))
}
// Help command for NAT masquerade
pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![(
        "set nat masquerade from <zonename> to <zonename>",
        "Enable NAT type MASQUERADE from a zone to another.",
    ),
    (
        "set nat snat from zone <trust|untrust> to <public_ip>",
        "Enable Source NAT (SNAT) from a trusted or untrusted zone to a public IP.",
    ),
    (
        "set nat snat from zone <private_ip> to <public_ip>",
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

    // Helper function to set up running configuration with zones and interfaces
    fn setup_running_config_with_zones(
        running_config: &mut RunningConfig,
        from_zone: &str,
        to_zone: &str,
    ) {
        // Add interfaces with zones
        running_config
            .add_value_to_node(&["interface", "eth0"], "zone", json!(from_zone))
            .unwrap();
        running_config
            .add_value_to_node(&["interface", "eth1"], "zone", json!(to_zone))
            .unwrap();
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

        // Configure running config with interfaces and zones
        setup_running_config_with_zones(&mut running_config, from_zone, to_zone);

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
        assert_eq!(
            running_config.get_value_from_node(&["nat"], "masquerade"),
            Some(&expected_nat_config),
            "NAT masquerade configuration not set correctly in RunningConfig"
        );
    }

    #[test]
    fn test_set_nat_masquerade_ip_forwarding_disabled() {
        let mut running_config = RunningConfig::new();

        // IP forwarding is disabled by default
        let from_zone = "internal";
        let to_zone = "external";

        setup_running_config_with_zones(&mut running_config, from_zone, to_zone);

        // Call the function
        let result = set_nat_masquerade(
            from_zone.to_string(),
            to_zone.to_string(),
            &mut running_config,
        );

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
        let public_ip = "203.0.113.1";

        // Set up from_zone in the running configuration
        setup_running_config_with_zones(&mut running_config, from_zone, "unrelated");

        let result = set_nat_snat(
            from_zone.to_string(),
            public_ip.to_string(),
            &mut running_config,
        );

        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that SNAT configuration was added to running config
        let expected_nat_config = json!({
            "from": from_zone,
            "to_public_ip": public_ip,
        });
        assert_eq!(
            running_config.get_value_from_node(&["nat"], "snat"),
            Some(&expected_nat_config),
            "NAT SNAT configuration not set correctly in RunningConfig"
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
        let private_ip = "192.168.1.10";
        let public_ip = "203.0.113.2";

        // Set up from_zone in the running configuration
        setup_running_config_with_zones(&mut running_config, from_zone, "external");

        let result = set_nat_snat_private_to_public(
            from_zone.to_string(),
            private_ip.to_string(),
            public_ip.to_string(),
            &mut running_config,
        );

        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that SNAT private-to-public configuration was added to running config
        let expected_nat_config = json!({
            "from_zone": from_zone,
            "private_ip": private_ip,
            "public_ip": public_ip,
        });
        assert_eq!(
            running_config.get_value_from_node(&["nat"], "snat_private_to_public"),
            Some(&expected_nat_config),
            "NAT SNAT private-to-public configuration not set correctly in RunningConfig"
        );
    }

    #[test]
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

        let result = set_nat_dnat(
            public_ip.to_string(),
            public_port,
            private_ip.to_string(),
            private_port,
            &mut running_config,
        );

        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        // Verify that DNAT configuration was added to running config
        let expected_nat_config = json!({
            "public_ip": public_ip,
            "public_port": public_port,
            "private_ip": private_ip,
            "private_port": private_port,
        });
        assert_eq!(
            running_config.get_value_from_node(&["nat"], "dnat"),
            Some(&expected_nat_config),
            "NAT DNAT configuration not set correctly in RunningConfig"
        );
    }
}
