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
pub fn unset_route(
    destination: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if the route exists in the running configuration
    let route_exists = running_config
        .config
        .get("routes")
        .and_then(|routes| routes.as_array())
        .map_or(false, |routes_array| {
            routes_array
                .iter()
                .any(|route| route["destination"] == destination)
        });

    if !route_exists {
        return Err(format!(
            "Route to destination '{}' is not set.",
            destination
        ));
    }
    if cfg!(test) {
        if let Some(routes_array) = running_config
            .config
            .get_mut("routes")
            .and_then(|v| v.as_array_mut())
        {
            routes_array.retain(|route| route["destination"] != destination);
        }
        return Ok(format!(
            "Removed route to {} via FRR (test mode)",
            destination
        ));
    }

    // Use VTYSH to remove the route
    let vtysh_result = Command::new("vtysh")
        .arg("-c")
        .arg(format!("configure terminal"))
        .arg("-c")
        .arg(format!("no ip route {}", destination))
        .output()
        .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

    if !vtysh_result.status.success() {
        return Err(format!(
            "Failed to remove route to {} via vtysh: {}",
            destination,
            String::from_utf8_lossy(&vtysh_result.stderr)
        ));
    }

    // Remove the route from the running configuration
    if let Some(routes_array) = running_config
        .config
        .get_mut("routes")
        .and_then(|v| v.as_array_mut())
    {
        routes_array.retain(|route| route["destination"] != destination);
    }

    Ok(format!("Removed route to {} via FRR", destination))
}
pub fn help_command_unset() -> Vec<(&'static str, &'static str)> {
    vec![(
        "unset route <destination>",
        "Remove the route to the specified destination using FRR.",
    )]
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    #[test]
    fn test_unset_route_success() {
        let mut running_config = RunningConfig::new();

        // Add a route to the running configuration to simulate it being set
        running_config.config["routes"] = json!([
            {
                "destination": "192.168.1.0/24",
                "via": "192.168.1.1"
            }
        ]);

        let result = unset_route("192.168.1.0/24", &mut running_config);

        // Ensure the function succeeded
        assert!(result.is_ok(), "Failed with error: {:?}", result.err());

        // Verify the route was removed from the running configuration
        let routes = running_config.config["routes"].as_array().unwrap();
        assert!(!routes.iter().any(|r| r["destination"] == "192.168.1.0/24"));
    }
    #[test]
    fn test_unset_route_not_set() {
        let mut running_config = RunningConfig::new();

        // No routes are set in the configuration
        running_config.config["routes"] = json!([]);

        // Try to unset a route that isn't there
        let result = unset_route("192.168.1.0/24", &mut running_config);

        // Ensure it fails with the correct error message
        assert!(
            result.is_err(),
            "Expected failure when unsetting a route that doesn't exist"
        );
        assert_eq!(
            result.unwrap_err(),
            "Route to destination '192.168.1.0/24' is not set."
        );
    }
}
