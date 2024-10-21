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
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

pub fn parse_show_nat(command: &[&str]) -> Result<String, String> {
    match command {
        ["show", "nat"] => show_nat(),
        ["show", "nat", "conntrack"] => show_nat_conntrack(),
        _ => Err("Invalid protocol command".to_string()),
    }
}
pub fn show_nat() -> Result<String, String> {
    let output = Command::new("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-L")
        .arg("-v")
        .arg("-n")
        .output()
        .map_err(|e| format!("Failed to execute iptables command: {}", e))?;

    if output.status.success() {
        Ok(format!("{}", String::from_utf8_lossy(&output.stdout)))
    } else {
        Err(format!(
            "Error: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Displays the conntrack table.
///
/// This function runs the `conntrack` command with the `-L` flag to display
/// the current conntrack table. The output is returned as a string.
///
/// Returns:
/// * `Ok(String)` on success, containing the output of the `conntrack`
///   command.
/// * `Err(String)` on failure, containing an error message.
pub fn show_nat_conntrack() -> Result<String, String> {
    let output = Command::new("conntrack")
        .arg("-L")
        .output()
        .map_err(|e| format!("Failed to execute conntrack command: {}", e))?;

    if output.status.success() {
        Ok(format!("{}", String::from_utf8_lossy(&output.stdout)))
    } else {
        Err(format!(
            "Error: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![
        ("show nat", "NAT info"),
        ("show nat conntrack", "Show conntrack output"),
    ]
}
