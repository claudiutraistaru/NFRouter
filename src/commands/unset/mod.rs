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
pub mod interface;
pub mod nat;
pub mod route;

use crate::config::RunningConfig;
use interface::{unset_interface_ip, unset_interface_speed};
use std::net::IpAddr;
pub fn parse_unset_command(
    parts: &[&str],
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if parts.len() > 2 {
        match parts[1] {
            "interface" => {
                let interface = parts[2];
                if parts.len() == 4 && parts[3] == "ip" {
                    unset_interface_ip(interface.to_string(), running_config)
                } else {
                    Err("Invalid or incomplete unset command".to_string())
                }
            }
            // "hostname" if parts.len() == 3 => {
            //     let hostname = parts[2].to_string();
            //     unet_hostname(hostname, running_config)
            // }
            // "route" if parts.len() == 5 => {
            //     let destination = parts[2];
            //     let via = parts[4];
            //     set_route(destination, via, running_config)
            // }
            _ => Err("Invalid set command".to_string()),
        }
    } else {
        Err("Incomplete set command".to_string())
    }
}
