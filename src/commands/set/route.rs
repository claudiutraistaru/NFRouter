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

pub fn set_route(
    destination: &str,
    via: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if the route already exists
    let route_exists = Command::new("ip")
        .arg("route")
        .arg("show")
        .arg(destination)
        .output()
        .map_err(|e| format!("Failed to check existing routes: {}", e))?
        .stdout
        .len()
        > 0;

    let mut route_command = Command::new("ip");
    route_command.arg("route");

    // Select the appropriate command based on whether the route exists
    if route_exists {
        route_command.arg("replace");
    } else {
        route_command.arg("add");
    }

    route_command.arg(destination);

    // Detect if `via` is an IP or the name of an interface
    if let Ok(via_ip) = IpAddr::from_str(via) {
        // It's a valid IP, so detect the interface associated with this IP
        let interface = detect_interface_for_ip(&via_ip)?;

        // Set the route via this IP and device
        route_command.arg("via").arg(via).arg("dev").arg(interface);
    } else {
        // If it's not a valid IP, assume it's the name of an interface
        route_command.arg("dev").arg(via);
    }

    // Execute the command and check if it succeeded
    let route_result = route_command.output();
    match route_result {
        Ok(output) => {
            if output.status.success() {
                // Update the running configuration

                // Ensure that the "routes" node exists and is an array
                if !running_config.config.get("routes").is_some() {
                    running_config.config["routes"] = json!([]);
                }

                // Get mutable reference to the routes array
                if let Some(routes_array) = running_config
                    .config
                    .get_mut("routes")
                    .and_then(|v| v.as_array_mut())
                {
                    let route_entry = json!({
                        "destination": destination,
                        "via": via
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
                    "{} route to {} via {}",
                    if route_exists { "Replaced" } else { "Added" },
                    destination,
                    via
                ))
            } else {
                Err(format!(
                    "Failed to {} route to {} via {}: {}",
                    if route_exists { "replace" } else { "add" },
                    destination,
                    via,
                    String::from_utf8_lossy(&output.stderr)
                ))
            }
        }
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

fn detect_interface_for_ip(ip: &IpAddr) -> Result<String, String> {
    let output = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg(ip.to_string())
        .output()
        .map_err(|e| format!("Failed to detect interface for IP {}: {}", ip, e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to detect interface for IP {}: {}",
            ip,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = output_str.lines().next() {
        if let Some(dev_index) = line.find("dev ") {
            let interface = line[dev_index + 4..]
                .split_whitespace()
                .next()
                .ok_or("Failed to parse interface")?;
            return Ok(interface.to_string());
        }
    }

    Err(format!("Could not determine the interface for IP {}", ip))
}
pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![
        ("set routes", "Configure routes"),
        ("set routes <destination> via <gateway|interface>", "Add or replace a route to the specified destination via the given gateway or interface.")
    ]
}
