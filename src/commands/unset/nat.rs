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

pub fn unset_nat_masquerade(
    from_zone: String,
    to_zone: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if the NAT masquerade exists in the configuration
    let nat_exists = running_config
        .get_value_from_node(&["nat", "masquerade"], "from")
        .and_then(|from| {
            running_config
                .get_value_from_node(&["nat", "masquerade"], "to")
                .filter(|to| *from == json!(from_zone) && **to == json!(to_zone))
            // Dereference 'to' and 'from' for comparison
        })
        .is_some();

    if !nat_exists {
        return Err(format!(
            "NAT masquerade from zone '{}' to zone '{}' is not set.",
            from_zone, to_zone
        ));
    }

    // Remove the NAT masquerade rule using iptables
    let nat_result = Command::new("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-D")
        .arg("POSTROUTING")
        .arg("-o")
        .arg(&to_zone)
        .arg("-j")
        .arg("MASQUERADE")
        .output()
        .map_err(|e| format!("Failed to remove NAT masquerade: {}", e))?;

    if !nat_result.status.success() {
        return Err(format!(
            "Failed to remove NAT masquerade: {}",
            String::from_utf8_lossy(&nat_result.stderr)
        ));
    }

    // Remove the NAT masquerade entry from the configuration
    running_config.remove_value_from_node(&["nat"], "masquerade")?;

    Ok(format!(
        "Removed NAT masquerade from zone '{}' to zone '{}'",
        from_zone, to_zone
    ))
}

pub fn help_command_unset() -> Vec<(&'static str, &'static str)> {
    vec![(
        "unset nat masquerade from <zonename> to <zonename>",
        "Disable NAT type MASQUERADE from a zone to another.",
    )]
}
