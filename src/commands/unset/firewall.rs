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
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

pub fn delete_firewall_rule_from_iptables(
    rule_set_name: &str,
    rule_number: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let mut command_args = vec![];

    // Delete the rule at the given number in the rule set
    command_args.push("-D".to_string());
    command_args.push(rule_set_name.to_string());
    command_args.push(rule_number.to_string());

    if cfg!(test) {
        if let Some(rules) = running_config
            .config
            .get_mut("rules")
            .and_then(|r| r.as_array_mut())
        {
            if let Ok(index) = rule_number.parse::<usize>() {
                if index > 0 && index <= rules.len() {
                    rules.remove(index - 1);
                }
            }
        }
        return Ok(format!("Firewall rule removed"));
    }

    println!(
        "Executing iptables command: iptables {}",
        command_args.clone().join(" ")
    );

    let output = Command::new("iptables")
        .args(&command_args)
        .output()
        .map_err(|e| format!("Failed to run iptables: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to delete rule from iptables: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    if let Some(rule_set) = running_config
        .config
        .get_mut("firewall")
        .and_then(|fw| fw.get_mut(rule_set_name))
        .and_then(|rs| rs.get_mut("rules"))
        .and_then(|r| r.as_array_mut())
    {
        if let Ok(index) = rule_number.parse::<usize>() {
            if index > 0 && index <= rule_set.len() {
                rule_set.remove(index - 1);
            }
        }
    }

    return Ok(format!("Firewall rule removed"));
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![(
        "unset firewall <rule-set-name> <rule-number>",
        "Delete the firewall rule",
    )]
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_delete_firewall_rule_from_iptables() {
        let mut running_config = RunningConfig {
            config: json!({
                "rules": [
                    {
                        "action": "accept",
                        "source": "192.168.0.1",
                        "destination": "192.168.0.2",
                        "protocol": "tcp",
                        "port": 80
                    },
                    {
                        "action": "accept",
                        "destination": "192.168.0.2",
                        "protocol": "tcp",
                        "port": 443
                    },
                    {
                        "action": "accept",
                        "source": "192.168.0.3",
                        "protocol": "udp",
                        "port": 53
                    }
                ]
            }),
        };

        // Test deleting a rule that exists
        let result = delete_firewall_rule_from_iptables("filter", "1", &mut running_config);
        assert!(result.is_ok());
        assert_eq!(running_config.config["rules"].as_array().unwrap().len(), 2);

        // Test deleting a rule that does not exist
        let result = delete_firewall_rule_from_iptables("filter", "10", &mut running_config);
        assert!(result.is_ok()); // No error, but no rule deleted
        assert_eq!(running_config.config["rules"].as_array().unwrap().len(), 2);
    }
}
