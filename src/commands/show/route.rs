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
use std::process::Command;

pub fn show_routes(parts: &[&str]) -> Result<String, String> {
    // Execute the vtysh command to show the routing table
    let output = Command::new("vtysh")
        .arg("-c")
        .arg("show ip route")
        .output()
        .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

    // Check if the command was successful and return the output
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!(
            "Error showing routes: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}
pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![("show route", "Show routes")]
}
