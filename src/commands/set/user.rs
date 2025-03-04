use crate::config::RunningConfig;
use serde_json::json;
use std::fs::{read_to_string, write, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::process::Command;

/// Sets the user password for the specified username. If the user does not exist, it creates the user with a home directory.
///
/// # Parameters
///
/// * `username`: The username for which the password is to be set.
/// * `password`: The password to be set for the user.
///
/// # Returns
///
/// A `Result` containing a success message if the operation is successful, or an error message with a description of what went wrong if it fails.
pub fn set_user_password(
    username: String,
    password: String,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if username.is_empty() || password.is_empty() {
        return Err("Username and password cannot be empty".to_string());
    }

    // Check if the user exists
    let user_exists = Command::new("id")
        .arg(&username)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if !user_exists {
        // Create the user with a home directory
        let create_user = Command::new("useradd")
            .arg("-m")
            .arg(&username)
            .output()
            .map_err(|e| format!("Failed to create user: {}", e))?;

        if !create_user.status.success() {
            return Err(format!(
                "Failed to create user: {}",
                String::from_utf8_lossy(&create_user.stderr)
            ));
        }
    }

    // Determine if the password is a hash
    let is_hash = password.len() == 106 && password.starts_with('$');

    // Set the user password
    if is_hash {
        // Directly write the hash to the shadow file
        let shadow_content = read_to_string("/etc/shadow")
            .map_err(|e| format!("Failed to read /etc/shadow: {}", e))?;

        let new_shadow_content: String = shadow_content
            .lines()
            .map(|line| {
                if line.starts_with(&username) {
                    let mut parts: Vec<&str> = line.split(':').collect();
                    parts[1] = &password;
                    parts.join(":")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join("\n");

        write("/etc/shadow", new_shadow_content)
            .map_err(|e| format!("Failed to write to /etc/shadow: {}", e))?;
    } else {
        // Encode the password and apply it using usermod
        let hashed_password = Command::new("openssl")
            .arg("passwd")
            .arg("-1")
            .arg(&password)
            .output()
            .map_err(|e| format!("Failed to hash password: {}", e))?;

        let hashed_password = String::from_utf8(hashed_password.stdout)
            .map_err(|e| format!("Failed to convert hashed password to string: {}", e))?;

        let set_password = Command::new("usermod")
            .arg("--password")
            .arg(hashed_password.trim())
            .arg(&username)
            .output()
            .map_err(|e| format!("Failed to set password: {}", e))?;

        if !set_password.status.success() {
            return Err(format!(
                "Failed to set password: {}",
                String::from_utf8_lossy(&set_password.stderr)
            ));
        }
    }

    // Get the password hash from /etc/shadow
    let shadow_file =
        File::open("/etc/shadow").map_err(|e| format!("Failed to open /etc/shadow: {}", e))?;
    let reader = BufReader::new(shadow_file);
    let hash_line = reader
        .lines()
        .find(|line| {
            line.as_ref()
                .map(|l| l.starts_with(&username))
                .unwrap_or(false)
        })
        .ok_or_else(|| "Failed to find user in /etc/shadow".to_string())?
        .map_err(|e| format!("Failed to read line from /etc/shadow: {}", e))?;

    let hash = hash_line
        .split(':')
        .nth(1)
        .ok_or_else(|| "Failed to extract hash from /etc/shadow".to_string())?;

    // Update the running configuration
    running_config.config["user"][&username] = json!({
        "password": hash
    });

    Ok(format!("User {} created/updated successfully", username))
}
pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![(
        "set user <username> password <password>",
        "Create or update a user with the specified password.",
    )]
}
