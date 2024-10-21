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
use std::fs;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

/// Sets the IP address for a given interface. If the provided address is "dhcp",
/// the interface will be set to obtain its IP address via DHCP.
///
/// # Parameters
///
/// * `interface`: The name of the interface to configure.
///
/// * `address`: The IP address to assign, or "dhcp" to enable DHCP.
///
/// * `running_config`: A mutable reference to the running configuration.
///
/// # Returns
///
/// * `Result<String, String>`: A result indicating whether the operation was successful,
///   with a message describing any errors that may have occurred.

pub fn set_interface_ip(
    interface: String,
    address: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if address.to_lowercase() == "dhcp" {
        remove_static_ip(&interface)?;
        set_interface_dhcp(interface, running_config)
    } else {
        stop_dhcp_client(&interface)?;
        set_interface_static_ip(interface, address, running_config)
    }
}

/// Removes any static IP addresses from the given interface.
///
/// # Parameters
///
/// * `interface`: The name of the interface to modify.
///
/// # Returns
///
/// * `Result<(), String>`: A result indicating whether the operation was successful,
///   with a message describing any errors that may have occurred.
fn remove_static_ip(interface: &str) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }

    let down_result = Command::new("ip")
        .arg("link")
        .arg("set")
        .arg(interface)
        .arg("down")
        .output()
        .map_err(|e| format!("Failed to bring interface down: {}", e))?;

    if !down_result.status.success() {
        return Err(format!(
            "Failed to bring interface down: {}",
            String::from_utf8_lossy(&down_result.stderr)
        ));
    }

    // Remove any existing IP addresses from the interface
    let flush_result = Command::new("ip")
        .arg("addr")
        .arg("flush")
        .arg("dev")
        .arg(interface)
        .output()
        .map_err(|e| format!("Failed to flush IP addresses: {}", e))?;

    if !flush_result.status.success() {
        return Err(format!(
            "Failed to flush IP addresses: {}",
            String::from_utf8_lossy(&flush_result.stderr)
        ));
    }

    Ok(())
}

/// Stops the DHCP client for the given interface.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to stop the DHCP client.
/// # Returns
/// * `Result<(), String>`: A result indicating whether the operation was successful,
///   with a message describing any errors that may have occurred.
fn stop_dhcp_client(interface: &str) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }

    let dhclient_stop_result = Command::new("dhclient").arg("-r").arg(interface).output();

    if let Err(e) = dhclient_stop_result {
        println!("Failed to stop DHCP client: {}", e);
    }

    Ok(())
}

/// Starts the DHCP client for the given interface.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to start the DHCP client.
///
/// # Returns
///
/// * `Result<(), String>`: A result indicating whether the operation was successful,
///   with a message describing any errors that may have occurred.
fn start_dhcp_client(interface: &str) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }

    let up_result = Command::new("ip")
        .arg("link")
        .arg("set")
        .arg(interface)
        .arg("up")
        .output()
        .map_err(|e| format!("Failed to bring interface up: {}", e))?;

    if !up_result.status.success() {
        return Err(format!(
            "Failed to bring interface up: {}",
            String::from_utf8_lossy(&up_result.stderr)
        ));
    }

    // Start DHCP client works only on alpine linux, uses openrc
    let dhclient_result = Command::new("udhcpc")
        .arg(interface)
        .output()
        .map_err(|e| format!("Failed to start DHCP client: {}", e))?;

    if !dhclient_result.status.success() {
        return Err(format!(
            "Failed to start DHCP client: {}",
            String::from_utf8_lossy(&dhclient_result.stderr)
        ));
    }

    Ok(())
}

/// Sets the interface's DHCP configuration.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the DHCP configuration.
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
fn set_interface_dhcp(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    start_dhcp_client(&interface)?;
    running_config.add_value_to_node(&["interface", &interface], "address", json!("dhcp"))?;
    Ok(format!(
        "Interface {} is now configured to use DHCP",
        interface
    ))
}

/// Sets the interface's static IP configuration.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the static IP configuration.
/// * `new_ip_with_cidr`: A string containing the new IP address and CIDR (e.g. "192.168.1.100/24").
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
fn set_interface_static_ip(
    interface: String,
    new_ip_with_cidr: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    remove_static_ip(&interface)?;
    if !cfg!(test) {
        let add_result = Command::new("ip")
            .arg("addr")
            .arg("add")
            .arg(&new_ip_with_cidr)
            .arg("dev")
            .arg(&interface)
            .output()
            .map_err(|e| format!("Failed to assign IP address: {}", e))?;

        if !add_result.status.success() {
            return Err(format!(
                "Failed to assign IP address: {}",
                String::from_utf8_lossy(&add_result.stderr)
            ));
        }

        let up_result = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(&interface)
            .arg("up")
            .output()
            .map_err(|e| format!("Failed to bring interface up: {}", e))?;

        if !up_result.status.success() {
            return Err(format!(
                "Failed to bring interface up: {}",
                String::from_utf8_lossy(&up_result.stderr)
            ));
        }
    }
    running_config.add_value_to_node(
        &["interface", &interface],
        "address",
        json!(new_ip_with_cidr),
    )?;
    Ok(format!(
        "Assigned static IP {} to interface {}",
        new_ip_with_cidr, interface
    ))
}

/// Sets the interface's option configuration.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the option configuration.
/// * `options`: A vector of options (e.g. "speed", "mtu", "duplex") to be configured.
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
pub fn set_interface_option(
    interface: String,
    options: Vec<String>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let mut output = String::new();

    let mut i = 0;
    while i < options.len() {
        let option = &options[i];
        i += 1;

        let result =
            if option == "speed" || option == "mtu" || option == "duplex" || option == "hw-id" {
                if i >= options.len() {
                    return Err(format!("Missing value for option '{}'", option));
                }
                let value = &options[i];
                i += 1;
                //Options that need value
                match option.as_str() {
                    "speed" => set_speed(&interface, value, running_config),
                    "mtu" => set_mtu(&interface, value, running_config),
                    "duplex" => set_duplex(&interface, value, running_config),
                    "hw-id" => set_hw_id(&interface, value, running_config),
                    _ => Err(format!("Unknown option: '{}'", option)),
                }
            //Options that do not need value (bool)
            } else if option == "enabled" || option == "disable-flow-control" {
                // Options that do not require a value
                match option.as_str() {
                    "enabled" => set_interface_enabled(&interface, running_config),
                    "disable-flow-control" => disable_flow_control(&interface, running_config),
                    _ => Err(format!("Unknown option: '{}'", option)),
                }
            } else {
                Err(format!("Unknown option: '{}'", option))
            };

        match result {
            Ok(message) => output.push_str(&message),
            Err(e) => return Err(e),
        }
    }

    Ok(output)
}

/// Sets the speed of an interface.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the speed.
/// * `speed_str`: A string representing the desired speed (e.g. "1000", "10000").
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
fn set_speed(
    interface: &str,
    speed_str: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let speed: u32 = speed_str.parse().map_err(|_| "Invalid speed".to_string())?;
    if cfg!(test) {
        // When in test mode , we only update the configuration without executing the command
        running_config.add_value_to_node(
            &["interface", interface, "options"],
            "speed",
            json!(speed),
        )?;
        return Ok(format!(
            "Set speed {} on interface {} (test mode)\n",
            speed, interface
        ));
    }

    let result = Command::new("ethtool")
        .arg("-s")
        .arg(interface)
        .arg("speed")
        .arg(&speed.to_string())
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            running_config.add_value_to_node(
                &["interface", interface, "options"],
                "speed",
                json!(speed),
            )?;
            Ok(format!("Set speed {} on interface {}\n", speed, interface))
        } else {
            Err(format!(
                "Failed to set speed {} on interface {}: {}",
                speed,
                interface,
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute speed command: {}",
            result.unwrap_err()
        ))
    }
}

/// Sets the MTU of an interface.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the MTU.
/// * `mtu_str`: A string representing the desired MTU (e.g. "1500", "9000").
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
fn set_mtu(
    interface: &str,
    mtu_str: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let mtu: u32 = mtu_str.parse().map_err(|_| "Invalid MTU".to_string())?;
    if cfg!(test) {
        running_config.add_value_to_node(
            &["interface", interface, "options"],
            "mtu",
            json!(mtu),
        )?;
        Ok(format!("Set MTU {} on interface {}\n", mtu, interface))
    } else {
        let result = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(interface)
            .arg("mtu")
            .arg(&mtu.to_string())
            .output();

        if let Ok(res) = result {
            if res.status.success() {
                running_config.add_value_to_node(
                    &["interface", interface, "options"],
                    "mtu",
                    json!(mtu),
                )?;
                Ok(format!("Set MTU {} on interface {}\n", mtu, interface))
            } else {
                Err(format!(
                    "Failed to set MTU {} on interface {}: {}",
                    mtu,
                    interface,
                    String::from_utf8_lossy(&res.stderr)
                ))
            }
        } else {
            Err(format!(
                "Failed to execute MTU command: {}",
                result.unwrap_err()
            ))
        }
    }
}

///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the duplex.
/// * `duplex`: A string representing the desired duplex (e.g. "full", "half").
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
fn set_duplex(
    interface: &str,
    duplex: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if !cfg!(test) {
        let result = Command::new("ethtool")
            .arg("-s")
            .arg(interface)
            .arg("duplex")
            .arg(duplex)
            .output();

        if let Ok(res) = result {
            if res.status.success() {
                running_config.add_value_to_node(
                    &["interface", interface, "options"],
                    "duplex",
                    json!(duplex),
                )?;
                Ok(format!(
                    "Set duplex {} on interface {}\n",
                    duplex, interface
                ))
            } else {
                Err(format!(
                    "Failed to set duplex {} on interface {}: {}",
                    duplex,
                    interface,
                    String::from_utf8_lossy(&res.stderr)
                ))
            }
        } else {
            Err(format!(
                "Failed to execute duplex command: {}",
                result.unwrap_err()
            ))
        }
    } else {
        running_config.add_value_to_node(
            &["interface", interface, "options"],
            "duplex",
            json!(duplex),
        )?;
        Ok(format!(
            "Set duplex {} on interface {}\n",
            duplex, interface
        ))
    }
}
/// Sets the hardware ID of an interface.
/// # Parameters
/// * `interface`: The name of the interface for which to set the hardware ID.
/// * `hw_id`: A string representing the desired hardware ID.
/// * `running_config`: A reference to the running configuration in which to add the value.
/// # Returns
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
fn set_hw_id(
    interface: &str,
    hw_id: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if cfg!(test) {
        running_config.add_value_to_node(
            &["interface", interface, "options"],
            "hw-id",
            json!(hw_id),
        )?;
        Ok(format!("Set hw-id {} on interface {}\n", hw_id, interface))
    } else {
        let result = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(interface)
            .arg("address")
            .arg(hw_id)
            .output();

        if let Ok(res) = result {
            if res.status.success() {
                running_config.add_value_to_node(
                    &["interface", interface, "options"],
                    "hw-id",
                    json!(hw_id),
                )?;
                Ok(format!("Set hw-id {} on interface {}\n", hw_id, interface))
            } else {
                Err(format!(
                    "Failed to set hw-id {} on interface {}: {}",
                    hw_id,
                    interface,
                    String::from_utf8_lossy(&res.stderr)
                ))
            }
        } else {
            Err(format!(
                "Failed to execute hw-id command: {}",
                result.unwrap_err()
            ))
        }
    }
}

/// Sets the enabled state of an interface.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the enabled state.
///
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
fn set_interface_enabled(
    interface: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let enabled = true;

    let action = if enabled { "up" } else { "down" };
    if cfg!(test) {
        running_config.add_value_to_node(
            &["interface", interface, "options"],
            "enabled",
            json!(enabled),
        )?;
        Ok(format!(
            "Interface {} is now {}",
            interface,
            if enabled { "enabled" } else { "disabled" }
        ))
    } else {
        // Execute the command to bring the interface up or down
        let result = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(interface)
            .arg(action)
            .output();

        if let Ok(res) = result {
            if res.status.success() {
                // Update the running configuration
                running_config.add_value_to_node(
                    &["interface", interface, "options"],
                    "enabled",
                    json!(enabled),
                )?;
                Ok(format!(
                    "Interface {} is now {}",
                    interface,
                    if enabled { "enabled" } else { "disabled" }
                ))
            } else {
                Err(format!(
                    "Failed to set interface {} to {}: {}",
                    interface,
                    action,
                    String::from_utf8_lossy(&res.stderr)
                ))
            }
        } else {
            Err(format!(
                "Failed to execute the command: {}",
                result.unwrap_err()
            ))
        }
    }
}

/// Sets the description of an interface.
///
/// # Parameters
///
/// * `interface`: The name of the interface for which to set the description.
///
/// * `description`: A string representing the desired description.
///
/// * `running_config`: A reference to the running configuration in which to add the value.
///
/// # Returns
///
/// * `Result<String, String>`: A result containing a message indicating whether the operation was successful,
///   with an error message if not.
pub fn set_interface_description(
    interface: &str,
    description: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    running_config.add_value_to_node(
        &["interface", interface],
        "description",
        json!(description),
    )?;
    Ok(format!(
        "Set description '{}' on interface {}\n",
        description, interface
    ))
}

pub fn set_interface_vlan(
    interface: &str,
    vlan_id: u16,
    ip_address: Option<String>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let vlan_interface = format!("{}.{}", interface, vlan_id);
    if cfg!(test) {
        running_config.add_value_to_node(
            &["interface", &vlan_interface, "vlan"],
            "id",
            json!(vlan_id),
        )?;
        if let Some(ip) = ip_address.clone() {
            running_config.add_value_to_node(&["interface", &vlan_interface], "ip", json!(ip))?;
        }
        return Ok(format!(
            "Test mode: Created VLAN interface {} with VLAN ID {}{}",
            vlan_interface,
            vlan_id,
            if ip_address.is_some() {
                " and IP address"
            } else {
                ""
            }
        ));
    }
    // Execute the command to create a VLAN interface
    let create_vlan_result = Command::new("ip")
        .arg("link")
        .arg("add")
        .arg(&vlan_interface)
        .arg("link")
        .arg(interface)
        .arg("type")
        .arg("vlan")
        .arg("id")
        .arg(vlan_id.to_string())
        .output();

    if let Ok(res) = create_vlan_result {
        if !res.status.success() {
            return Err(format!(
                "Failed to create VLAN interface {}: {}",
                vlan_interface,
                String::from_utf8_lossy(&res.stderr)
            ));
        }
    } else {
        return Err(format!(
            "Failed to execute VLAN creation command: {}",
            create_vlan_result.unwrap_err()
        ));
    }

    // If an IP address is provided, assign it to the VLAN interface
    if let Some(ip) = ip_address.clone() {
        let set_ip_result = Command::new("ip")
            .arg("addr")
            .arg("add")
            .arg(&ip)
            .arg("dev")
            .arg(&vlan_interface)
            .output();

        if let Ok(res) = set_ip_result {
            if res.status.success() {
                running_config.add_value_to_node(
                    &["interface", &vlan_interface, "vlan"],
                    "id",
                    json!(vlan_id),
                )?;
                running_config.add_value_to_node(
                    &["interface", &vlan_interface],
                    "ip",
                    json!(ip),
                )?;
            } else {
                return Err(format!(
                    "Failed to assign IP address {} to VLAN interface {}: {}",
                    ip,
                    vlan_interface,
                    String::from_utf8_lossy(&res.stderr)
                ));
            }
        } else {
            return Err(format!(
                "Failed to execute IP assignment command: {}",
                set_ip_result.unwrap_err()
            ));
        }
    } else {
        // If no IP is provided, just add the VLAN ID to the configuration
        running_config.add_value_to_node(
            &["interface", &vlan_interface, "vlan"],
            "id",
            json!(vlan_id),
        )?;
    }

    Ok(format!(
        "Created VLAN interface {} with VLAN ID {}{}",
        vlan_interface,
        vlan_id,
        if ip_address.is_some() {
            " and IP address"
        } else {
            ""
        }
    ))
}

pub fn set_interface_zone(
    interface: String,
    zone_name: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Validate zone name: must not contain spaces and must not be empty
    if zone_name.trim().is_empty() || zone_name.contains(' ') {
        return Err(format!(
            "Invalid zone name: '{}'. Zone name must not contain spaces and must not be empty.",
            zone_name
        ));
    }

    // Check if the interface exists on the system
    let interface_path = format!("/sys/class/net/{}", interface);
    if !fs::metadata(interface_path).is_ok() {
        return Err(format!(
            "Interface '{}' does not exist on the system.",
            interface
        ));
    }

    // Update the running configuration with the interface-zone mapping
    running_config.add_value_to_node(&["interface", &interface], "zone", json!(zone_name))?;

    Ok(format!(
        "Assigned interface {} to zone '{}'",
        interface, zone_name
    ))
}

fn disable_flow_control(
    interface: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if cfg!(test) {
        running_config.add_value_to_node(
            &["interface", interface, "options"],
            "disable-flow-control",
            json!(true),
        )?;
        return Ok(format!(
            "Disabled flow control on interface {}\n",
            interface
        ));
    }

    let result = Command::new("ethtool")
        .arg("-A")
        .arg(interface)
        .arg("rx")
        .arg("off")
        .arg("tx")
        .arg("off")
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            running_config.add_value_to_node(
                &["interface", interface, "options"],
                "disable-flow-control",
                json!(true),
            )?;
            Ok(format!(
                "Disabled flow control on interface {}\n",
                interface
            ))
        } else {
            Err(format!(
                "Failed to disable flow control on interface {}: {}",
                interface,
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute disable flow control command: {}",
            result.unwrap_err()
        ))
    }
}

pub fn set_interface_ip_adjust_mss(
    interface: String,
    value: Option<String>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let mss_value = match value {
        Some(val) => val,
        None => return Err("No MSS value provided".to_string()),
    };

    // Validate the value
    if mss_value != "clamp-mss-to-pmtu" {
        let mss_num: u16 = mss_value
            .parse()
            .map_err(|_| "Invalid MSS value".to_string())?;
        if mss_num < 500 || mss_num > 1460 {
            return Err("MSS value out of valid range (500-1460)".to_string());
        }
    }
    if cfg!(test) {
        // În modul de test, actualizăm doar configurația fără a executa comanda
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "adjust-mss",
            json!(mss_value),
        )?;
        return Ok(format!(
            "Set TCP MSS adjustment on interface {} to {}\n",
            interface, mss_value
        ));
    }
    // Use iptables to adjust the MSS
    let result = Command::new("iptables")
        .arg("-A")
        .arg("FORWARD")
        .arg("-o")
        .arg(&interface)
        .arg("-p")
        .arg("tcp")
        .arg("--tcp-flags")
        .arg("SYN,RST")
        .arg("SYN")
        .arg("-j")
        .arg("TCPMSS")
        .arg("--set-mss")
        .arg(&mss_value)
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            // Update the running configuration
            running_config.add_value_to_node(
                &["interface", &interface, "ip"],
                "adjust-mss",
                json!(mss_value),
            )?;
            Ok(format!(
                "Set TCP MSS adjustment on interface {} to {}\n",
                interface, mss_value
            ))
        } else {
            Err(format!(
                "Failed to set TCP MSS adjustment on interface {}: {}",
                interface,
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute iptables command: {}",
            result.unwrap_err()
        ))
    }
}
pub fn set_interface_ip_arp_cache_timeout(
    interface: String,
    seconds: u32,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if cfg!(test) {
        // În modul de test, actualizăm doar configurația fără a executa comanda
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "arp-cache-timeout",
            json!(seconds),
        )?;
        return Ok(format!(
            "Set ARP cache timeout on interface {} to {} seconds\n",
            interface, seconds
        ));
    }
    let arp_timeout_path = format!("/proc/sys/net/ipv4/neigh/{}/gc_stale_time", interface);
    let result = std::fs::write(&arp_timeout_path, seconds.to_string());

    if let Ok(_) = result {
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "arp-cache-timeout",
            json!(seconds),
        )?;
        Ok(format!(
            "Set ARP cache timeout on interface {} to {} seconds\n",
            interface, seconds
        ))
    } else {
        Err(format!(
            "Failed to set ARP cache timeout: {}",
            result.unwrap_err()
        ))
    }
}
pub fn set_interface_ip_disable_arp_filter(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let arp_filter_path = format!("/proc/sys/net/ipv4/conf/{}/arp_filter", interface);
    let result = std::fs::write(&arp_filter_path, "0");

    if cfg!(test) {
        // În modul de test, actualizăm doar configurația fără a executa comanda
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "disable-arp-filter",
            json!(true),
        )?;
        return Ok(format!(
            "Disabled ARP filtering on interface {}\n",
            interface
        ));
    }

    if let Ok(_) = result {
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "disable-arp-filter",
            json!(true),
        )?;
        Ok(format!(
            "Disabled ARP filtering on interface {}\n",
            interface
        ))
    } else {
        Err(format!(
            "Failed to disable ARP filter: {}",
            result.unwrap_err()
        ))
    }
}
pub fn set_interface_ip_disable_forwarding(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let forwarding_path = format!("/proc/sys/net/ipv4/conf/{}/forwarding", interface);
    let result = std::fs::write(&forwarding_path, "0");
    if cfg!(test) {
        // În modul de test, actualizăm doar configurația fără a executa comanda
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "disable-forwarding",
            json!(true),
        )?;
        return Ok(format!(
            "Disabled IP forwarding on interface {}\n",
            interface
        ));
    }
    if let Ok(_) = result {
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "disable-forwarding",
            json!(true),
        )?;
        Ok(format!(
            "Disabled IP forwarding on interface {}\n",
            interface
        ))
    } else {
        Err(format!(
            "Failed to disable IP forwarding: {}",
            result.unwrap_err()
        ))
    }
}

pub fn set_enable_proxy_arp(
    interface: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Update the running config first
    if cfg!(test) {
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "enable-proxy-arp",
            json!(true),
        )?;
        Ok(format!("Proxy ARP enabled for interface {}\n", interface))
    } else {
        running_config.add_value_to_node(
            &["interface", &interface, "ip"],
            "enable-proxy-arp",
            json!(true),
        )?;
        // Now perform the system command action to enable or disable proxy ARP

        let proxy_arp_path = format!("/proc/sys/net/ipv4/conf/{}/proxy_arp", interface);

        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("echo {} > {}", 1, proxy_arp_path))
            .output();

        match output {
            Ok(output) if output.status.success() => {
                Ok(format!("Proxy ARP enabled for interface {}\n", interface))
            }
            Ok(output) => Err(format!(
                "Failed to set proxy ARP for interface {}: {}",
                interface,
                String::from_utf8_lossy(&output.stderr)
            )),
            Err(e) => Err(format!("Failed to execute command: {}", e)),
        }
    }
}
pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("set interface", "Configure interfaces."),
        (
            "set interface <interface>",
            "Configure a specific interface.",
        ),
        (
            "set interface <interface> address",
            "Set the IP address for the interface.",
        ),
        (
            "set interface <interface> address <ip_address>",
            "Specify the IP address.",
        ),
        (
            "set interface <interface> address dhcp",
            "Configure the interface to use DHCP.",
        ),
        (
            "set interface <interface> options",
            "Configure options for the interface.",
        ),
        (
            "set interface <interface> options speed",
            "Set the speed of the interface.",
        ),
        (
            "set interface <interface> options speed <speed>",
            "Specify the speed in Mbps.",
        ),
        (
            "set interface <interface> options mtu",
            "Set the MTU of the interface.",
        ),
        (
            "set interface <interface> options mtu <mtu>",
            "Specify the MTU size.",
        ),
        (
            "set interface <interface> options duplex",
            "Set the duplex mode of the interface.",
        ),
        (
            "set interface <interface> options duplex <full|half|auto>",
            "Specify the duplex mode.",
        ),
        (
            "set interface <interface> options hw-id",
            "Set the hardware ID of the interface.",
        ),
        (
            "set interface <interface> options hw-id <MAC address>",
            "Specify the MAC address.",
        ),
        (
            "set interface <interface> options enabled",
            "Enable or disable the interface.",
        ),
        (
            "set interface <interface> options disable-flow-control",
            "Disable flow control on the interface.",
        ),
        (
            "set interface <interface> options disable-flow-control <true|false>",
            "Disable flow control on the interface.",
        ),
        ("set interface <interface> vlan", "Create a VLAN interface."),
        (
            "set interface <interface> vlan <vlan_id> ip <ip_address>",
            "Create a VLAN with a specified IP address.",
        ),
        (
            "set interface <interface> zone",
            "Assign the interface to a zone.",
        ),
        (
            "set interface <interface> zone <zonename>",
            "Specify the zone name.",
        ),
        (
            "set interface <interface> description",
            "Set the description for the interface.",
        ),
        (
            "set interface <interface> description <text>",
            "Specify the description text.",
        ),
        (
            "set interface <interface> ip adjust-mss",
            "Adjust the TCP MSS value.",
        ),
        (
            "set interface <interface> ip adjust-mss <value>",
            "Specify the MSS value or 'clamp-mss-to-pmtu'.",
        ),
        (
            "set interface <interface> ip arp-cache-timeout <seconds>",
            "Set ARP cache timeout.",
        ),
        (
            "set interface <interface> ip disable-arp-filter",
            "Disable ARP filtering.",
        ),
        (
            "set interface <interface> ip disable-forwarding",
            "Disable IP forwarding on the interface.",
        ),
        (
            "set interface <interface> ip enable-proxy-arp",
            "Enable proxy ARP.",
        ),
        (
            "set interface <interface> firewall <in|out|local> <rule-set-name>",
            "Apply a firewall rule set to an interface in a specified direction (in or out).",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_interface_ip_static() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let ip_address = "192.168.1.10/24".to_string();

        let result = set_interface_ip(interface.clone(), ip_address.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface], "address"),
            Some(&serde_json::Value::String(ip_address))
        );
    }
    #[test]
    fn test_set_interface_ip_dhcp() {
        let mut running_config = RunningConfig::new();
        let interface = "eth1".to_string();

        let result = set_interface_ip(interface.clone(), "dhcp".to_string(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface], "address"),
            Some(&serde_json::Value::String("dhcp".to_string()))
        );
    }
    #[test]
    fn test_set_interface_option_speed() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let options = vec!["speed".to_string(), "1000".to_string()];

        let result = set_interface_option(interface.clone(), options, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface, "options"], "speed"),
            Some(&serde_json::Value::Number(1000.into()))
        );
    }
    #[test]
    fn test_set_speed_invalid_speed() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0";
        let speed = "invalid";

        let result = set_speed(interface, speed, &mut running_config);
        assert!(result.is_err(), "Test should fail with invalid speed");
        assert_eq!(result.unwrap_err(), "Invalid speed".to_string());
    }
    #[test]
    fn test_set_interface_option_mtu() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let options = vec!["mtu".to_string(), "1500".to_string()];

        let result = set_interface_option(interface.clone(), options, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface, "options"], "mtu"),
            Some(&serde_json::Value::Number(1500.into()))
        );
    }

    #[test]
    fn test_set_interface_option_duplex() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let options = vec!["duplex".to_string(), "full".to_string()];

        let result = set_interface_option(interface.clone(), options, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface, "options"], "duplex"),
            Some(&serde_json::Value::String("full".to_string()))
        );
    }

    #[test]
    fn test_set_interface_option_hw_id() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let hw_id = "00:1A:2B:3C:4D:5E".to_string();
        let options = vec!["hw-id".to_string(), hw_id.clone()];

        let result = set_interface_option(interface.clone(), options, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface, "options"], "hw-id"),
            Some(&serde_json::Value::String(hw_id))
        );
    }

    #[test]
    fn test_set_interface_option_enabled() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let options = vec!["enabled".to_string()];

        let result = set_interface_option(interface.clone(), options, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface, "options"], "enabled"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_set_interface_option_disable_flow_control() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let options = vec!["disable-flow-control".to_string()];

        let result = set_interface_option(interface.clone(), options, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(
                &["interface", &interface, "options"],
                "disable-flow-control"
            ),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_set_interface_description() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0";
        let description = "Main uplink interface";

        let result = set_interface_description(interface, description, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", "eth0"], "description"),
            Some(&serde_json::Value::String(description.to_string()))
        );
    }

    #[test]
    fn test_set_interface_vlan() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let vlan_id = 100;
        let ip_address = Some("192.168.100.1/24".to_string());

        let result =
            set_interface_vlan(&interface, vlan_id, ip_address.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());

        let vlan_interface = format!("{}.{}", interface, vlan_id);
        assert_eq!(
            running_config.get_value_from_node(&["interface", &vlan_interface, "vlan"], "id"),
            Some(&serde_json::Value::Number(vlan_id.into()))
        );
        assert_eq!(
            running_config.get_value_from_node(&["interface", &vlan_interface], "ip"),
            Some(&serde_json::Value::String(ip_address.unwrap()))
        );
    }

    #[test]
    fn test_set_interface_zone_valid() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let zone_name = "trusted".to_string();

        let result = set_interface_zone(interface.clone(), zone_name.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface], "zone"),
            Some(&serde_json::Value::String(zone_name))
        );
    }

    #[test]
    fn test_set_interface_zone_invalid() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let zone_name = "invalid zone".to_string(); // Contains space

        let result = set_interface_zone(interface, zone_name, &mut running_config);
        assert!(
            result.is_err(),
            "Test should have failed due to invalid zone name"
        );
    }

    #[test]
    fn test_set_interface_ip_adjust_mss_valid() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let mss_value = Some("1400".to_string());

        let result =
            set_interface_ip_adjust_mss(interface.clone(), mss_value.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config.get_value_from_node(&["interface", &interface, "ip"], "adjust-mss"),
            Some(&serde_json::Value::String("1400".to_string()))
        );
    }

    #[test]
    fn test_set_interface_ip_adjust_mss_invalid() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let mss_value = Some("2000".to_string()); // Out of valid range

        let result =
            set_interface_ip_adjust_mss(interface.clone(), mss_value.clone(), &mut running_config);
        assert!(
            result.is_err(),
            "Test should have failed due to invalid MSS value"
        );
        // Verificăm actualizarea RunningConfig
    }

    #[test]
    fn test_set_interface_ip_arp_cache_timeout() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();
        let timeout = 300;

        let result =
            set_interface_ip_arp_cache_timeout(interface.clone(), timeout, &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config
                .get_value_from_node(&["interface", &interface, "ip"], "arp-cache-timeout"),
            Some(&serde_json::Value::Number(timeout.into()))
        );
    }

    #[test]
    fn test_set_interface_ip_disable_arp_filter() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();

        let result = set_interface_ip_disable_arp_filter(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config
                .get_value_from_node(&["interface", &interface, "ip"], "disable-arp-filter"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_set_interface_ip_disable_forwarding() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();

        let result = set_interface_ip_disable_forwarding(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config
                .get_value_from_node(&["interface", &interface, "ip"], "disable-forwarding"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_set_enable_proxy_arp() {
        let mut running_config = RunningConfig::new();
        let interface = "eth0".to_string();

        let result = set_enable_proxy_arp(interface.clone(), &mut running_config);
        assert!(result.is_ok(), "Test failed with error: {:?}", result.err());
        assert_eq!(
            running_config
                .get_value_from_node(&["interface", &interface, "ip"], "enable-proxy-arp"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_help_commands() {
        let commands = help_commands();
        assert!(!commands.is_empty(), "Help commands should not be empty");

        // Example: Check if a specific command is present
        assert!(
            commands.iter().any(|(cmd, _)| *cmd == "set interface"),
            "Help should include 'set interface'"
        );
    }
}
