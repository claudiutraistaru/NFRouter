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
use libc;
use serde_json::json;

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("set protocols rip", "Enable the RIP routing protocol."),
        (
            "set protocols rip network <network-ip/prefix>",
            "Add a network to the RIP routing protocol.",
        ),
        (
            "set protocols rip version <1|2>",
            "Set the RIP version (1 or 2).",
        ),
        (
            "set protocols rip passive-interface <interface-name>",
            "Set an interface to be passive in RIP, meaning it will not send RIP updates.",
        ),
        (
            "set protocols rip redistribute static",
            "Redistribute static routes into RIP.",
        ),
        (
            "set protocols rip redistribute connected",
            "Redistribute connected routes into RIP.",
        ),
        // (
        //     "set protocols rip redistribute ospf",
        //     "Redistribute OSPF routes into RIP.",
        // ),
        // (
        //     "set protocols rip redistribute bgp",
        //     "Redistribute BGP routes into RIP.",
        // ),
        (
            "set protocols rip distance <distance>",
            "Set the administrative distance for RIP routes.",
        ),
        (
            "set protocols rip default-information originate",
            "Advertise a default route in RIP.",
        ),
    ]
}
