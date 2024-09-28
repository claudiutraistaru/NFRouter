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
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::net::IpAddr;

/// Sets the hostname for the current session and makes the change permanent by updating `/etc/hostname` and optionally `/etc/hosts`.
///
/// # Parameters
///
/// * `hostname`: The new hostname to be set.
///
/// # Returns
///
/// A `Result` containing a success message if the operation is successful, or an error message with a description of what went wrong if it fails.
pub fn set_hostname(
    hostname: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    //running_config.hostname = Some(hostname.clone());

    // Step 1: Set the hostname for the current session
    let c_hostname =
        CString::new(hostname.clone()).map_err(|e| format!("Failed to convert hostname: {}", e))?;
    let result = unsafe { libc::sethostname(c_hostname.as_ptr(), c_hostname.to_bytes().len()) };

    if result != 0 {
        return Err(format!("Failed to set hostname for the current session"));
    }

    // Step 2: Update the /etc/hostname file to make the change permanent
    let result = update_hostname_file(&hostname);
    if let Err(e) = result {
        return Err(format!("Failed to update /etc/hostname: {}", e));
    }

    // Optionally, update the /etc/hosts file to reflect the new hostname
    let result = update_hosts_file(&hostname);
    if let Err(e) = result {
        return Err(format!("Failed to update /etc/hosts: {}", e));
    }
    running_config.config["hostname"] = json!(hostname);
    Ok(format!(
        "Hostname set successfully and change made permanent"
    ))
}

/// Updates the contents of the `/etc/hostname` file with the provided `hostname`.
///
/// This function creates a new file at the specified path, writes the hostname to it,
/// and then closes the file. If any error occurs during this process, an `io::Error`
/// is returned.
///
/// # Arguments
///
/// * `hostname`: The hostname to be written to the `/etc/hostname` file.
///
/// # Returns
///
/// A `Result` containing `()` if the operation was successful, or an `io::Error` if it failed.
fn update_hostname_file(hostname: &str) -> io::Result<()> {
    let mut file = File::create("/etc/hostname")?;
    writeln!(file, "{}", hostname)?;
    Ok(())
}

/// Updates the contents of the `/etc/hosts` file with a new entry for the provided `hostname`.
///
/// This function reads the current content of /etc/hosts, updates the loopback address
/// entry for the hostname (either replacing an existing one or appending a new one),
/// and then writes the updated content back to the file. If any error occurs during this process,
/// an `io::Error` is returned.
///
/// # Arguments
///
/// * `hostname`: The hostname to be written to /etc/hosts.
///
/// # Returns
///
/// A `Result` containing `()` if the operation was successful, or an `io::Error` if it failed.
fn update_hosts_file(hostname: &str) -> io::Result<()> {
    // Read the current content of /etc/hosts
    let mut content = std::fs::read_to_string("/etc/hosts")?;

    // Update the loopback address entry for the hostname
    let new_entry = format!("127.0.0.1\t{}", hostname);
    let loopback_prefix = "127.0.0.1";

    // Replace any existing 127.0.0.1 entry or append a new one
    if content.contains(loopback_prefix) {
        content = content
            .lines()
            .map(|line| {
                if line.starts_with(loopback_prefix) {
                    new_entry.clone()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
    } else {
        content.push_str(&format!("\n{}", new_entry));
    }

    // Write the updated content back to /etc/hosts
    let mut file = File::create("/etc/hosts")?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("set hostname", "Set the system hostname."),
        (
            "set hostname <hostname>",
            "Set the system hostname to the specified name.",
        ),
    ]
}
