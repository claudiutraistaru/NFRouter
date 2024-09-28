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
use std::process::Command;
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

    // Update the running configuration
    let nat_config = json!({
        "from": from_zone,
        "to": to_zone,
    });
    running_config.add_value_to_node(&["nat"], &format!("masquerade"), nat_config)?;

    Ok(format!(
        "Enabled NAT masquerade from zone '{}' to zone '{}' (interface: '{}')",
        from_zone, to_zone, to_zone_interface
    ))
}

// Help command for NAT masquerade
pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![(
        "set nat masquerade from <zonename> to <zonename>",
        "Enable NAT type MASQUERADE from a zone to another.",
    )]
}
