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
pub mod firewall;
pub mod interface;
pub mod nat;
pub mod route;
pub mod system;

use crate::config::RunningConfig;
use firewall::delete_firewall_rule_from_iptables;
use interface::{unset_interface_ip, unset_interface_speed};
use route::unset_route;
use std::net::IpAddr;
use system::unset_ip_forwarding;
pub fn parse_unset_command(
    parts: &[&str],
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    match parts {
        ["unset", "interface", interface, "ip"] => {
            unset_interface_ip(interface.to_string(), running_config)
        }
        ["unset", "system", "ipforwarding", "enabled"] => unset_ip_forwarding(running_config),
        ["unset", "route", destination] => unset_route(destination, running_config),
        ["unset", "firewall", rule_set_name, rule_number] => {
            delete_firewall_rule_from_iptables(rule_set_name, rule_number, running_config)
        }
        // Uncomment and adjust the following match arms as needed:
        // ["unset", "hostname", hostname] => {
        //     unset_hostname(hostname.to_string(), running_config)
        // }
        // ["unset", "route", destination, "via", via] => {
        //     unset_route(destination, via, running_config)
        // }
        _ => Err("Invalid or incomplete unset command".to_string()),
    }
}
