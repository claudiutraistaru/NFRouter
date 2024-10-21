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
use libc;
use std::ffi::CStr;
use std::mem;

pub fn parse_show_hostname(parts: &[&str]) -> Result<String, String> {
    // Create a buffer to hold the hostname
    let mut buffer: [libc::c_char; 256] = unsafe { mem::zeroed() };

    // Use the libc `gethostname` function to get the system hostname
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr(), buffer.len()) };

    if result == 0 {
        // Convert the C string to a Rust string
        let c_str_hostname = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        let hostname = c_str_hostname
            .to_str()
            .map_err(|e| format!("Failed to convert hostname: {}", e))?;

        Ok(format!("Current hostname: {}", hostname))
    } else {
        Err(format!("Failed to retrieve hostname"))
    }
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![("show hostname", "Show the system hostname.")]
}
