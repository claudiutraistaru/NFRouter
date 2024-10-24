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
use std::process::Command;

pub fn parse_show_current_config(running_config: &RunningConfig) -> Result<String, String> {
    running_config.show_current_config()
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "show current-config",
            "Show the current running configuration.",
        ),
        (
            "show setcommands",
            "Show configuration in a command line ready format",
        ),
    ]
}
