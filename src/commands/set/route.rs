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
use serde_json::{json, Value};
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

/// Set a static route using FRR's vtysh.
///
/// This function sets a new static route using FRR's vtysh. The route is
/// defined by its destination IP address, via gateway, and distance.
/// If no distance is provided, it defaults to 1.
/// # Arguments
/// * `destination`: The destination IP address of the route.
/// * `via`: The gateway through which packets will be sent to the destination.
/// * `distance` (optional): The administrative distance for the route.
/// # Returns
/// A JSON string representing the updated routing table, or an error message if the operation fails.
pub fn set_route(
    destination: &str,
    via: &str,
    distance: Option<u32>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Default distance to 1 if not provided
    let distance = distance.unwrap_or(1);

    #[cfg(not(test))]
    {
        // Build the vtysh command to configure the static route
        let mut vtysh_command = Command::new("vtysh");
        vtysh_command.arg("-c").arg(format!("configure terminal"));
        vtysh_command
            .arg("-c")
            .arg(format!("ip route {} {} {}", destination, via, distance));

        // Execute the command and check if it succeeded
        let route_result = vtysh_command.output();
        match route_result {
            Ok(output) => {
                if !output.status.success() {
                    return Err(format!(
                        "Failed to add/update static route to {} via {}: {}",
                        destination,
                        via,
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
            Err(e) => return Err(format!("Failed to execute vtysh command: {}", e)),
        }
    }

    // Update the running configuration

    // Ensure that the "routes" node exists and is an array
    if !running_config.config.get("route").is_some() {
        running_config.config["route"] = json!([]);
    }

    // Get mutable reference to the routes array
    if let Some(routes_array) = running_config
        .config
        .get_mut("route")
        .and_then(|v| v.as_array_mut())
    {
        let route_entry = json!({
            "destination": destination,
            "via": via,
            "distance": distance
        });

        // Check if the route already exists in the running configuration
        if let Some(existing_route) = routes_array
            .iter_mut()
            .find(|r| r["destination"] == destination)
        {
            // Replace the existing route
            *existing_route = route_entry;
        } else {
            // Add the new route
            routes_array.push(route_entry);
        }
    }

    Ok(format!(
        "Added/Updated static route to {} via {} with distance {}",
        destination, via, distance
    ))
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![
        ("set route", "Configure static routes using FRR"),
        ("set route <destination> via <gateway> [distance <value>]", "Add or replace a static route to the specified destination via the given gateway with an optional administrative distance."),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    #[test]
    fn test_set_route_add_new_route() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result = set_route(
            "192.168.1.0/24",
            "192.168.1.1",
            Some(1),
            &mut running_config,
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "Added/Updated static route to 192.168.1.0/24 via 192.168.1.1 with distance 1"
        );

        let routes = running_config
            .config
            .get("route")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0]["destination"], "192.168.1.0/24");
        assert_eq!(routes[0]["via"], "192.168.1.1");
        assert_eq!(routes[0]["distance"], 1);
    }

    #[test]
    fn test_set_route_replace_existing_route() {
        let mut running_config = RunningConfig {
            config: json!({
                "route": [
                    {
                        "destination": "192.168.1.0/24",
                        "via": "192.168.1.1",
                        "distance": 1
                    }
                ]
            }),
        };
        let result = set_route(
            "192.168.1.0/24",
            "192.168.1.254",
            Some(5),
            &mut running_config,
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "Added/Updated static route to 192.168.1.0/24 via 192.168.1.254 with distance 5"
        );

        let routes = running_config
            .config
            .get("route")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0]["destination"], "192.168.1.0/24");
        assert_eq!(routes[0]["via"], "192.168.1.254");
        assert_eq!(routes[0]["distance"], 5);
    }

    #[test]
    fn test_set_route_add_multiple_routes() {
        let mut running_config = RunningConfig { config: json!({}) };
        let result1 = set_route(
            "192.168.1.0/24",
            "192.168.1.1",
            Some(1),
            &mut running_config,
        );
        let result2 = set_route(
            "192.168.2.0/24",
            "192.168.2.1",
            Some(2),
            &mut running_config,
        );
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let routes = running_config
            .config
            .get("route")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0]["destination"], "192.168.1.0/24");
        assert_eq!(routes[0]["via"], "192.168.1.1");
        assert_eq!(routes[0]["distance"], 1);
        assert_eq!(routes[1]["destination"], "192.168.2.0/24");
        assert_eq!(routes[1]["via"], "192.168.2.1");
        assert_eq!(routes[1]["distance"], 2);
    }
}
