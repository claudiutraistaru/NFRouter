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
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

pub fn show_interface(
    parts: &[&str],
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    match parts {
        ["show", "interface"] => {
            // Handle `show ip interface` - list all interfaces with their IP addresses and statistics
            Ok(show_interfaces(running_config))
        }
        ["show", "interface", interface_name] => {
            // Handle `show ip interface <interfacename>`
            let interface = interface_name.to_string();
            // if running_config.interfaces.contains_key(&interface) {
            Ok(show_interface_details(&interface, running_config))
            // } else {
            //     Err(format!("Interface {} does not exist", interface))
            // }
        }
        _ => Err("Usage: show ip interface or show ip interface <interfacename>".to_string()),
    }
}

pub fn show_interfaces(running_config: &RunningConfig) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{:<10} {:<10} {:<60} {:<10} {:<10} {:<20} {:<20}\n",
        "Interface", "State", "IP Address", "MTU", "RX Bytes", "TX Bytes", "Description"
    ));
    output.push_str(&format!(
        "{:<10} {:<10} {:<60} {:<10} {:<10} {:<20} {:<20}\n",
        "---------",
        "-----",
        "---------------------------------------------------------",
        "-------",
        "--------",
        "--------",
        "-----------"
    ));

    let dev_path = Path::new("/proc/net/dev");
    let dev_file = match File::open(&dev_path) {
        Ok(file) => file,
        Err(e) => return format!("Failed to open /proc/net/dev: {}", e),
    };

    let reader = io::BufReader::new(dev_file);

    for line in reader.lines().skip(2) {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 10 {
                let iface = parts[0].trim_end_matches(':');
                let rx_bytes = parts[1];
                let tx_bytes = parts[9];

                let mtu_path = format!("/sys/class/net/{}/mtu", iface);
                let mtu = fs::read_to_string(mtu_path).unwrap_or_else(|_| "Unknown".to_string());

                let ip_addr_output = Command::new("ip")
                    .arg("addr")
                    .arg("show")
                    .arg(iface)
                    .output()
                    .expect("Failed to execute ip command");

                let ip_addr = String::from_utf8(ip_addr_output.stdout)
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|line| {
                        if line.contains("inet ") || line.contains("inet6 ") {
                            line.split_whitespace().nth(1).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                let state_output = Command::new("ip")
                    .arg("link")
                    .arg("show")
                    .arg(iface)
                    .output()
                    .expect("Failed to execute ip command");

                let state = String::from_utf8(state_output.stdout)
                    .unwrap_or_default()
                    .lines()
                    .find_map(|line| {
                        if line.contains("state UP") {
                            Some("up")
                        } else if line.contains("state DOWN") {
                            Some("down")
                        } else {
                            None
                        }
                    })
                    .unwrap_or("unknown");

                // Retrieve the description from running_config
                let description = running_config
                    .get_value_from_node(&["interface", iface, "options"], "description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("No description");

                output.push_str(&format!(
                    "{:<10} {:<10} {:<60} {:<10} {:<10} {:<20} {:<20}\n",
                    iface,
                    state,
                    ip_addr,
                    mtu.trim(),
                    rx_bytes,
                    tx_bytes,
                    description
                ));
            }
        }
    }

    output
}

pub fn show_interface_details(interface: &str, running_config: &RunningConfig) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "{:<10} {:<20} {:<10} {:<20} {:<10} {:<10} {:<20}\n",
        "Interface", "State", "IP Address", "MTU", "RX Bytes", "TX Bytes", "Description"
    ));
    output.push_str(&format!(
        "{:<10} {:<20} {:<10} {:<20} {:<10} {:<10} {:<20}\n",
        "---------",
        "-----",
        "-------------------",
        "-------",
        "--------",
        "--------",
        "-----------"
    ));

    let dev_path = Path::new("/proc/net/dev");
    let dev_file = match File::open(&dev_path) {
        Ok(file) => file,
        Err(e) => return format!("Failed to open /proc/net/dev: {}", e),
    };

    let reader = io::BufReader::new(dev_file);

    for line in reader.lines().skip(2) {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 10 && parts[0].trim_end_matches(':') == interface {
                let rx_bytes = parts[1];
                let tx_bytes = parts[9];

                let mtu_path = format!("/sys/class/net/{}/mtu", interface);
                let mtu = fs::read_to_string(mtu_path).unwrap_or_else(|_| "Unknown".to_string());

                let ip_addr_output = Command::new("ip")
                    .arg("addr")
                    .arg("show")
                    .arg(interface)
                    .output()
                    .expect("Failed to execute ip command");

                let ip_addr = String::from_utf8(ip_addr_output.stdout)
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|line| {
                        if line.contains("inet ") || line.contains("inet6 ") {
                            line.split_whitespace().nth(1).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                let state_output = Command::new("ip")
                    .arg("link")
                    .arg("show")
                    .arg(interface)
                    .output()
                    .expect("Failed to execute ip command");

                let state = String::from_utf8(state_output.stdout)
                    .unwrap_or_default()
                    .lines()
                    .find_map(|line| {
                        if line.contains("state UP") {
                            Some("up")
                        } else if line.contains("state DOWN") {
                            Some("down")
                        } else {
                            None
                        }
                    })
                    .unwrap_or("unknown");

                // Retrieve the description from running_config
                let description = running_config
                    .get_value_from_node(&["interface", interface, "options"], "description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("No description");

                output.push_str(&format!(
                    "{:<10} {:<20} {:<10} {:<20} {:<10} {:<10} {:<20}\n",
                    interface,
                    state,
                    ip_addr,
                    mtu.trim(),
                    rx_bytes,
                    tx_bytes,
                    description
                ));
            }
        }
    }

    output
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![
        ("show interface", "Show all interfaces."),
        (
            "show interface <interfacename>",
            "Show details for a specific interface.",
        ),
    ]
}
