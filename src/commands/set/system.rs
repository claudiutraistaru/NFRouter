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

pub fn set_ip_forwarding(
    option: &str,
    value: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let enable_forwarding = match value {
        "enabled" => true,
        _ => {
            return Err(
                "Invalid option for IP forwarding. Only 'enabled' is supported.".to_string(),
            )
        }
    };

    let sysctl_value = if enable_forwarding { "1" } else { "0" };

    // Execute the command to set IP forwarding
    let result = Command::new("sysctl")
        .arg("-w")
        .arg(format!("net.ipv4.ip_forward={}", sysctl_value))
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            // Update the running configuration
            running_config.add_value_to_node(
                &["system"],
                "ipforwarding",
                json!({
                    "enabled": enable_forwarding
                }),
            )?;
            Ok(format!(
                "IP forwarding has been {}",
                if enable_forwarding {
                    "enabled"
                } else {
                    "disabled"
                }
            ))
        } else {
            Err(format!(
                "Failed to set IP forwarding: {}",
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute sysctl command: {}",
            result.unwrap_err()
        ))
    }
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![(
        "set system ipforwarding <enabled|disabled>",
        "Enable or disable IP forwarding on the system.",
    )]
}
