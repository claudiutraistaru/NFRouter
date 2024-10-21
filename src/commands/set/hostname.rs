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
    if hostname.is_empty() {
        return Err("Hostname cannot be an empty string".to_string());
    }
    if !is_valid_hostname(&hostname) {
        return Err("Hostname contains invalid characters or format".to_string());
    }

    if cfg!(test) {
        running_config.config["hostname"] = json!(hostname.to_string());
        return Ok("Hostname set successfully".to_string());
    }
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

    running_config.config["hostname"] = json!(hostname.to_string());

    Ok(format!(
        "Hostname set successfully and change made permanent"
    ))
}
/// Checks if a hostname is valid according to the rules of the Domain Name System (DNS).
///
/// A hostname must consist of letters, digits, hyphens, and periods. Each label in the hostname must be at most 63 characters long, and there must not be more than 253 total characters.
///
/// Additionally, each label must start and end with a letter or digit, and may contain any number of hyphens. The hostname itself may have no leading hyphen.
///
/// # Parameters
///
/// * `hostname`: The hostname to check.
///
/// # Returns
///
/// A boolean indicating whether the hostname is valid.
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    let labels = hostname.split('.');

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        let bytes = label.as_bytes();

        // Labels must start and end with a letter or digit
        if !is_letter_or_digit(bytes[0]) || !is_letter_or_digit(bytes[bytes.len() - 1]) {
            return false;
        }

        // Check each character in the label
        for &b in bytes {
            if !(is_letter_or_digit(b) || b == b'-') {
                return false;
            }
        }
    }

    true
}
/// Checks whether a byte represents a letter or digit.
///
/// # Parameters
///
/// * `b`: The byte to check.
///
/// # Returns
///
/// A boolean indicating whether the byte represents a letter or digit.
fn is_letter_or_digit(b: u8) -> bool {
    (b'A'..=b'Z').contains(&b) || (b'a'..=b'z').contains(&b) || (b'0'..=b'9').contains(&b)
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_hostname_updates_running_config() {
        let mut running_config = RunningConfig::new();
        let hostname = "test1234".to_string();

        // Call the function to set the hostname
        let result = set_hostname(hostname.clone(), &mut running_config);
        // Verify that the function succeeded
        assert!(
            result.is_ok(),
            "Function failed with error: {:?}",
            result.err()
        );

        // Verify that the running_config was updated correctly
        let expected_config = json!(hostname);
        assert_eq!(
            running_config.config["hostname"], expected_config,
            "RunningConfig did not contain the expected hostname"
        );
    }

    #[test]
    fn test_set_hostname_with_special_characters() {
        let mut running_config = RunningConfig::new();
        let hostname = "test-host-123_ABC".to_string();

        // Call the function to set the hostname
        let result = set_hostname(hostname.clone(), &mut running_config);

        // Verify that the set did not succed
        assert!(
            result.is_err(),
            "Failed to set hostname for the current session"
        );
    }

    #[test]
    fn test_set_hostname_empty_string() {
        let mut running_config = RunningConfig::new();
        let hostname = "".to_string();

        // Call the function to set the hostname
        let result = set_hostname(hostname.clone(), &mut running_config);

        // Verify that the set did not succed
        assert!(
            result.is_err(),
            "Failed to set hostname for the current session"
        );
    }

    #[test]
    fn test_help_commands_contains_set_hostname() {
        let commands = help_commands();
        let set_hostname_cmd = commands
            .iter()
            .find(|&&(cmd, _)| cmd == "set hostname")
            .expect("Help commands should contain 'set hostname'");

        assert_eq!(
            set_hostname_cmd.1, "Set the system hostname.",
            "Help command description mismatch"
        );
    }

    #[test]
    fn test_help_commands_contains_set_hostname_with_arg() {
        let commands = help_commands();
        let set_hostname_with_arg_cmd = commands
            .iter()
            .find(|&&(cmd, _)| cmd == "set hostname <hostname>")
            .expect("Help commands should contain 'set hostname <hostname>'");

        assert_eq!(
            set_hostname_with_arg_cmd.1, "Set the system hostname to the specified name.",
            "Help command description mismatch"
        );
    }
}
