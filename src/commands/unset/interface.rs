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

    // Remove the IP from the running configuration
    running_config.remove_value_from_node(&["interface", &interface], "ip")?;

    Ok(format!("Unset IP address on interface {}", interface))
}

pub fn unset_interface_speed(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if speed exists in the running configuration
    let speed_exists = running_config
        .get_value_from_node(&["interface", &interface, "options"], "speed")
        .is_some();

    if !speed_exists {
        return Err(format!("Speed is not set on interface {}", &interface));
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
    // Check if MTU exists in the running configuration
    let mtu_exists = running_config
        .get_value_from_node(&["interface", &interface, "options"], "mtu")
        .is_some();

    if !mtu_exists {
        return Err(format!("MTU is not set on interface {}", &interface));
    }

    // Reset the MTU to its default value (this command might vary depending on the system)
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
        )
    ]
}
