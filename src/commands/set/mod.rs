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
pub mod firewall;
pub mod hostname;
pub mod interface;
pub mod nat;
pub mod route;
pub mod service;
pub mod system;

use crate::config::RunningConfig;
use firewall::*;
use hostname::set_hostname;
use interface::{
    set_enable_proxy_arp, set_interface_description, set_interface_ip, set_interface_ip_adjust_mss,
    set_interface_ip_arp_cache_timeout, set_interface_ip_disable_arp_filter,
    set_interface_ip_disable_forwarding, set_interface_option, set_interface_vlan,
    set_interface_zone,
};
use nat::set_nat_masquerade;
use route::set_route;
use service::parse_dhcp_server_command;
use std::net::IpAddr;
use system::set_ip_forwarding;
pub fn parse_set_command(
    parts: &[&str],
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if parts.len() > 2 {
        match parts[1] {
            "interface" => {
                let interface = parts[2];
                if parts.len() >= 4 {
                    match parts[3] {
                        "firewall" => {
                            if parts.len() == 6
                                && (parts[4] == "in" || parts[4] == "out" || parts[4] == "local")
                            {
                                let direction = parts[4]; // "in" or "out"
                                let rule_set_name = parts[5]; // Rule set name
                                apply_firewall_to_interface(
                                    interface,
                                    direction,
                                    rule_set_name,
                                    running_config,
                                )
                            } else {
                                Err("Invalid set interface firewall command".to_string())
                            }
                        }
                        "options" => {
                            let options = parts[4..].iter().map(|s| s.to_string()).collect();
                            set_interface_option(interface.to_string(), options, running_config)
                        }
                        "zone" => {
                            if parts.len() == 5 {
                                let zone_name = parts[4].to_string();
                                set_interface_zone(interface.to_string(), zone_name, running_config)
                            } else {
                                Err("Invalid set interface zone command".to_string())
                            }
                        }
                        "address" => {
                            if parts.len() == 5 {
                                let ip = parts[4].to_string();
                                set_interface_ip(interface.to_string(), ip, running_config)
                            } else {
                                Err("Invalid set interface address command".to_string())
                            }
                        }
                        "vlan" => {
                            if parts.len() > 4 {
                                let vlan_id: u16 = parts[4]
                                    .parse()
                                    .map_err(|_| "Cannot parse VLAN ID".to_string())?;
                                // Check if an IP address is provided
                                let ip: Option<String> = if parts.len() > 6 && parts[5] == "address"
                                {
                                    Some(parts[6].to_string())
                                } else {
                                    None
                                };
                                set_interface_vlan(interface, vlan_id, ip, running_config)
                            } else {
                                Err("Invalid set interface vlan command".to_string())
                            }
                        }
                        "description" => {
                            if parts.len() > 4 {
                                let description = parts[4..].join(" ");
                                set_interface_description(interface, &description, running_config)
                            } else {
                                Err("Invalid set interface description command".to_string())
                            }
                        }
                        "ip" => {
                            if parts.len() >= 5 {
                                match parts[4] {
                                    "adjust-mss" => {
                                        if parts.len() == 6 {
                                            let value = parts[5].to_string();
                                            set_interface_ip_adjust_mss(
                                                interface.to_string(),
                                                Some(value),
                                                running_config,
                                            )
                                        } else if parts.len() == 5 {
                                            set_interface_ip_adjust_mss(
                                                interface.to_string(),
                                                None,
                                                running_config,
                                            )
                                        } else {
                                            Err("Invalid set interface ip adjust-mss command"
                                                .to_string())
                                        }
                                    }
                                    "arp-cache-timeout" => {
                                        if parts.len() == 6 {
                                            let seconds: u32 = parts[5]
                                                .parse()
                                                .map_err(|_| "Invalid seconds value".to_string())?;
                                            set_interface_ip_arp_cache_timeout(
                                                interface.to_string(),
                                                seconds,
                                                running_config,
                                            )
                                        } else {
                                            Err("Invalid set interface ip arp-cache-timeout command"
                                                .to_string())
                                        }
                                    }
                                    "disable-arp-filter" => {
                                        if parts.len() == 5 {
                                            set_interface_ip_disable_arp_filter(
                                                interface.to_string(),
                                                running_config,
                                            )
                                        } else {
                                            Err("Invalid set interface ip disable-arp-filter command".to_string())
                                        }
                                    }
                                    "disable-forwarding" => {
                                        if parts.len() == 5 {
                                            set_interface_ip_disable_forwarding(
                                                interface.to_string(),
                                                running_config,
                                            )
                                        } else {
                                            Err("Invalid set interface ip disable-forwarding command".to_string())
                                        }
                                    }
                                    "enable-proxy-arp" => {
                                        if parts.len() == 5 {
                                            set_enable_proxy_arp(
                                                interface.to_string(),
                                                running_config,
                                            )
                                        } else {
                                            Err("Invalid set interface ip enable_proxy_arp command"
                                                .to_string())
                                        }
                                    }
                                    _ => Err("Invalid set interface ip command".to_string()),
                                }
                            } else {
                                Err("Incomplete set interface options command".to_string())
                            }
                        }
                        _ => Err("Incomplete or unknown set interface command".to_string()),
                    }
                } else {
                    Err("Incomplete set interface command".to_string())
                }
            }

            "hostname" if parts.len() == 3 => {
                let hostname = parts[2].to_string();
                set_hostname(hostname, running_config)
            }
            "routes" if parts.len() == 5 => {
                let destination = parts[2];
                let via = parts[4];
                set_route(destination, via, running_config)
            }
            "system" if parts.len() == 4 && parts[2] == "ipforwarding" => {
                set_ip_forwarding(parts[2], parts[3], running_config)
            }
            "nat"
                if parts[0] == "set"
                    && parts[1] == "nat"
                    && parts[2] == "masquerade"
                    && parts[3] == "from"
                    && parts[5] == "to" =>
            {
                // Handle the command to set NAT masquerade between zones
                let from_zone = parts[4].to_string();
                let to_zone = parts[6].to_string();
                set_nat_masquerade(from_zone, to_zone, running_config)
            }

            "firewall" => {
                let rule_set_name = parts[2];

                // Verificăm dacă trebuie creat setul de reguli
                if running_config.config["firewall"]
                    .get(rule_set_name)
                    .is_none()
                {
                    create_firewall_rule_set(rule_set_name, running_config)?;
                }

                // Cazul pentru setarea politicii implicite
                if parts.len() == 5 && parts[3] == "default-policy" {
                    let policy = parts[4];
                    return set_default_policy(rule_set_name, policy, running_config);
                }

                // Verificăm dacă este un caz de "insert-before" sau "insert-after"
                if parts.len() > 4 && (parts[3] == "insert-before" || parts[3] == "insert-after") {
                    let position = parts[3]; // either "insert-before" or "insert-after"
                    let rule_number = parts[4]
                        .parse::<u32>()
                        .map_err(|_| "Invalid rule number".to_string())?;

                    let mut action: Option<&str> = None;
                    let mut source: Option<&str> = None;
                    let mut destination: Option<&str> = None;
                    let mut protocol: Option<&str> = None;
                    let mut port: Option<u32> = None;
                    let mut interface: Option<&str> = None;

                    let mut i = 5;
                    while i < parts.len() {
                        match parts[i] {
                            "action" => {
                                action = Some(parts[i + 1]);
                                i += 2;
                            }
                            "source" => {
                                source = Some(parts[i + 1]);
                                i += 2;
                            }
                            "destination" => {
                                destination = Some(parts[i + 1]);
                                i += 2;
                            }
                            "protocol" => {
                                protocol = Some(parts[i + 1]);
                                i += 2;
                            }
                            "port" => {
                                port = Some(
                                    parts[i + 1]
                                        .parse()
                                        .map_err(|_| "Invalid port number".to_string())?,
                                );
                                i += 2;
                            }
                            "interface" => {
                                interface = Some(parts[i + 1]);
                                i += 2;
                            }
                            _ => {
                                return Err("Invalid firewall command syntax.".to_string());
                            }
                        }
                    }

                    // Verificăm dacă acțiunea este specificată
                    if action.is_none() {
                        return Err("Action (accept, drop, reject) must be specified.".to_string());
                    }

                    // Apelăm funcția corespunzătoare pentru a insera regula înainte sau după
                    add_firewall_rule_position(
                        rule_set_name,
                        rule_number,
                        position, // "before" or "after"
                        action.unwrap(),
                        source,
                        destination,
                        protocol,
                        port,
                        running_config,
                    )
                } else {
                    // Cazul pentru adăugarea unei reguli în setul de firewall (comandă clasică)
                    let mut rule_number: Option<u32> = None;
                    let mut action: Option<&str> = None;
                    let mut source: Option<&str> = None;
                    let mut destination: Option<&str> = None;
                    let mut protocol: Option<&str> = None;
                    let mut port: Option<u32> = None;

                    let mut i = 3;
                    while i < parts.len() {
                        match parts[i] {
                            "rule" => {
                                rule_number = Some(
                                    parts[i + 1]
                                        .parse()
                                        .map_err(|_| "Invalid rule number".to_string())?,
                                );
                                i += 2;
                            }
                            "action" => {
                                action = Some(parts[i + 1]);
                                i += 2;
                            }
                            "source" => {
                                source = Some(parts[i + 1]);
                                i += 2;
                            }
                            "destination" => {
                                destination = Some(parts[i + 1]);
                                i += 2;
                            }
                            "protocol" => {
                                protocol = Some(parts[i + 1]);
                                i += 2;
                            }
                            "port" => {
                                port = Some(
                                    parts[i + 1]
                                        .parse()
                                        .map_err(|_| "Invalid port number".to_string())?,
                                );
                                i += 2;
                            }

                            _ => {
                                return Err("Invalid firewall command syntax.".to_string());
                            }
                        }
                    }

                    // Verificăm dacă acțiunea este specificată
                    if action.is_none() {
                        return Err("Action (accept, drop, reject) must be specified.".to_string());
                    }

                    // Apelăm funcția care adaugă regula în configurația firewall-ului
                    add_firewall_rule(
                        rule_set_name,
                        rule_number,
                        action.unwrap(),
                        source,
                        destination,
                        protocol,
                        port,
                        running_config,
                    )
                }
            }
            "service" if parts[2] == "dhcp-server" => {
                parse_dhcp_server_command(parts, running_config)
            }

            _ => Err("Invalid set command".to_string()),
        }
    } else {
        Err("Incomplete set command".to_string())
    }
}
