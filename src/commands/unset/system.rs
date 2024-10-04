use crate::config::RunningConfig;
use serde_json::json;
use std::process::Command;

pub fn unset_ip_forwarding(running_config: &mut RunningConfig) -> Result<String, String> {
    // Check if IP forwarding is enabled in the running configuration
    let ip_forwarding_exists = running_config
        .get_value_from_node(&["system"], "ipforwarding")
        .is_some();

    if !ip_forwarding_exists {
        return Err("IP forwarding is not set.".to_string());
    }

    if cfg!(test) {
        // Remove the value from the configuration in test mode without running commands
        running_config.remove_value_from_node(&["system"], "ipforwarding")?;
        return Ok("IP forwarding has been removed (test mode)".to_string());
    }

    // Execute the command to disable IP forwarding
    let result = Command::new("sysctl")
        .arg("-w")
        .arg("net.ipv4.ip_forward=0")
        .output();

    if let Ok(res) = result {
        if res.status.success() {
            // Remove the IP forwarding entry from the running configuration
            running_config.remove_value_from_node(&["system"], "ipforwarding")?;
            Ok("IP forwarding has been disabled".to_string())
        } else {
            Err(format!(
                "Failed to disable IP forwarding: {}",
                String::from_utf8_lossy(&res.stderr)
            ))
        }
    } else {
        Err(format!(
            "Failed to execute sysctl command: {}",
            result.unwrap_err()
        ))
    }
}

pub fn help_unset_command() -> Vec<(&'static str, &'static str)> {
    vec![(
        "unset system ipforwarding",
        "Disable and remove IP forwarding configuration.",
    )]
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    #[test]
    fn test_unset_ip_forwarding_success() {
        let mut running_config = RunningConfig::new();

        // Simulate IP forwarding being enabled
        running_config
            .add_value_to_node(&["system"], "ipforwarding", json!({"enabled": true}))
            .unwrap();

        // Call the unset function
        let result = unset_ip_forwarding(&mut running_config);
        assert!(result.is_ok(), "Failed with error: {:?}", result.err());

        // Check if the configuration was removed correctly
        assert!(
            running_config
                .get_value_from_node(&["system"], "ipforwarding")
                .is_none(),
            "IP forwarding entry was not removed from the configuration"
        );
    }

    #[test]
    fn test_unset_ip_forwarding_not_set() {
        let mut running_config = RunningConfig::new();

        // IP forwarding is not set in the configuration
        let result = unset_ip_forwarding(&mut running_config);

        // Ensure the correct error is returned
        assert!(
            result.is_err(),
            "Expected failure when IP forwarding is not set"
        );
        assert_eq!(result.unwrap_err(), "IP forwarding is not set.");
    }
}
