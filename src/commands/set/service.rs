use crate::config::RunningConfig;
use serde_json::{json, Value};
use std::process::Command;

/// Parses a DHCP server command and updates the running configuration accordingly.
///
/// This function takes a list of strings representing the command parts (e.g. "dhcp-server", "--address", "10.0.0.1") and
/// an instance of `RunningConfig` to be updated in place.
///
/// It returns a string representation of the DHCP server configuration, or an error message if parsing fails.
///
pub fn parse_service_dhcp_server_command(
    parts: &[&str],
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    match parts {
        ["set", "service", "dhcp-server", "enabled"] => {
            // Ensure all configurations are set before enabling
            if check_dhcp_config(running_config)? {
                running_config.config["service"]["dhcp-server"]["enabled"] = json!(true);

                // Apply the configuration when DHCP is enabled
                apply_dhcp_config(running_config)?;

                if !cfg!(test) {
                    // Start or restart the DNSMASQ service for DHCP
                    run_command("rc-service", &["dnsmasq", "restart"])?;
                }
                Ok("DHCP server (dnsmasq) enabled and configuration applied".to_string())
            } else {
                Err(
                    "Incomplete DHCP configuration. Set all necessary options before enabling."
                        .to_string(),
                )
            }
        }
        ["set", "service", "dhcp-server", "shared-network-name", network, "subnet", subnet, options @ ..] =>
        {
            let mut idx = 0;
            while idx < options.len() {
                match options[idx] {
                    "default-router" if idx + 1 < options.len() => {
                        let router = options[idx + 1];
                        running_config.config["service"]["dhcp-server"]["shared-network-name"]
                            [network]["subnet"][subnet]["default-router"] = json!(router);
                        idx += 2;
                    }
                    "dns-server" if idx + 1 < options.len() => {
                        let dns = options[idx + 1];
                        running_config.config["service"]["dhcp-server"]["shared-network-name"]
                            [network]["subnet"][subnet]["dns-server"] = json!(dns);
                        idx += 2;
                    }
                    "domain-name" if idx + 1 < options.len() => {
                        let domain = options[idx + 1];
                        running_config.config["service"]["dhcp-server"]["shared-network-name"]
                            [network]["subnet"][subnet]["domain-name"] = json!(domain);
                        idx += 2;
                    }
                    "lease" if idx + 1 < options.len() => {
                        let lease = options[idx + 1];
                        running_config.config["service"]["dhcp-server"]["shared-network-name"]
                            [network]["subnet"][subnet]["lease"] = json!(lease);
                        idx += 2;
                    }
                    "start"
                        if idx + 1 < options.len()
                            && idx + 2 < options.len()
                            && options[idx + 2] == "stop"
                            && idx + 3 < options.len() =>
                    {
                        let start = options[idx + 1];
                        let stop = options[idx + 3];
                        running_config.config["service"]["dhcp-server"]["shared-network-name"]
                            [network]["subnet"][subnet]["start"] = json!(start);
                        running_config.config["service"]["dhcp-server"]["shared-network-name"]
                            [network]["subnet"][subnet]["stop"] = json!(stop);
                        idx += 4;
                    }
                    _ => {
                        return Err(format!(
                            "Invalid or incomplete DHCP server option: {}",
                            options[idx]
                        ));
                    }
                }
            }

            Ok(format!(
                "DHCP server configuration updated for network '{}' subnet '{}'",
                network, subnet
            ))
        }
        _ => Err("Invalid DHCP server command".to_string()),
    }
}

/// Checks if all necessary configurations are set before enabling the DHCP server.
/// Returns an error or bool
fn check_dhcp_config(running_config: &RunningConfig) -> Result<bool, String> {
    // Check if shared-network-name and related settings exist
    if let Some(shared_networks) = running_config
        .config
        .get("service")
        .and_then(|s| s.get("dhcp-server"))
        .and_then(|d| d.get("shared-network-name"))
        .and_then(|sn| sn.as_object())
    {
        // Iterate over each network to verify if required fields are present
        for (_, network_config) in shared_networks {
            if let Some(subnets) = network_config.get("subnet").and_then(|s| s.as_object()) {
                for (_, config) in subnets {
                    // Check required fields: start, stop, default-router, dns-server, and lease
                    if config.get("start").is_none()
                        || config.get("stop").is_none()
                        || config.get("default-router").is_none()
                        || config.get("dns-server").is_none()
                        || config.get("lease").is_none()
                    {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    } else {
        // No shared-network-name found, config is incomplete
        Ok(false)
    }
}

/// Apply the DHCP configuration from `RunningConfig` to the system only when the DHCP server is enabled
fn apply_dhcp_config(running_config: &RunningConfig) -> Result<(), String> {
    // Ensure DHCP server is enabled before applying configurations
    if running_config.config["service"]["dhcp-server"]["enabled"] == json!(true) {
        if let Some(shared_networks) =
            running_config.config["service"]["dhcp-server"]["shared-network-name"].as_object()
        {
            for (_network_name, network_config) in shared_networks {
                if let Some(subnets) = network_config["subnet"].as_object() {
                    for (_subnet, config) in subnets {
                        let mut dnsmasq_config = String::new();

                        if let Some(start_ip) = config.get("start").and_then(|v| v.as_str()) {
                            if let Some(stop_ip) = config.get("stop").and_then(|v| v.as_str()) {
                                if let Some(lease_time) =
                                    config.get("lease").and_then(|v| v.as_str())
                                {
                                    dnsmasq_config.push_str(&format!(
                                        "dhcp-range={},{},{}\n",
                                        start_ip, stop_ip, lease_time
                                    ));
                                }
                            }
                        }
                        if let Some(default_router) =
                            config.get("default-router").and_then(|v| v.as_str())
                        {
                            dnsmasq_config.push_str(&format!(
                                "dhcp-option=option:router,{}\n",
                                default_router
                            ));
                        }
                        if let Some(dns_server) = config.get("dns-server").and_then(|v| v.as_str())
                        {
                            dnsmasq_config.push_str(&format!(
                                "dhcp-option=option:dns-server,{}\n",
                                dns_server
                            ));
                        }
                        if let Some(domain_name) =
                            config.get("domain-name").and_then(|v| v.as_str())
                        {
                            dnsmasq_config.push_str(&format!(
                                "dhcp-option=option:domain-name,{}\n",
                                domain_name
                            ));
                        }

                        if cfg!(test) {
                            continue; // Skip saving the configuration to file
                        }
                        // Save the configuration to the `/etc/dnsmasq.d/dhcp.conf` file
                        run_command(
                            "sh",
                            &[
                                "-c",
                                &format!("echo '{}' > /etc/dnsmasq.d/dhcp.conf", dnsmasq_config),
                            ],
                        )?;
                    }
                }
            }
        }
    } else {
        return Err("DHCP server is not enabled. Run 'set service dhcp-server enabled' to apply the configuration.".to_string());
    }

    Ok(())
}

/// Utility function to run commands on the Linux system
fn run_command(command: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "set service dhcp-server enabled",
            "Enable the DHCP server."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip>/<prefix-length> start <start-ip> stop <end-ip> default-router <gateway-ip> dns-server <dns-server-ip> domain-name <domain-name> lease <lease-time>",
            "Configure the DHCP server with all options for the specified shared network and subnet."
        ),
        (
            "set service dhcp-server shared-network-name <network-name>",
            "Specify the name of the shared network for the DHCP server."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip>/<prefix-length>",
            "Configure a subnet within the specified shared network."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip/prefix-length> start <start-ip> stop <end-ip>",
            "Define the IP address range for the DHCP server to assign to clients within the specified subnet."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip/prefix-length> start <start-ip>",
            "Define the IP address start range for the DHCP server to assign to clients within the specified subnet."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip/prefix-length> stop <start-ip> stop <end-ip>",
            "Define the IP address stop range for the DHCP server to assign to clients within the specified subnet."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip/prefix-length> default-router <gateway-ip>",
            "Set the default gateway for the specified subnet."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip/prefix-length> dns-server <dns-server-ip>",
            "Set the DNS server for the specified subnet."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip/prefix-length> domain-name <domain-name>",
            "Set the domain name for the specified subnet."
        ),
        (
            "set service dhcp-server shared-network-name <network-name> subnet <subnet-ip/prefix-length> lease <lease-time>",
            "Set the lease time in seconds for the specified subnet."
        )
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    #[test]
    fn test_set_dhcp_server_enabled_success() {
        let mut running_config = RunningConfig::new();

        // Simulate valid DHCP configuration
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "start",
                json!("192.168.1.10"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "stop",
                json!("192.168.1.100"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "default-router",
                json!("192.168.1.1"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "dns-server",
                json!("8.8.8.8"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "lease",
                json!("86400"),
            )
            .unwrap();

        let parts = vec!["set", "service", "dhcp-server", "enabled"];
        let result = parse_service_dhcp_server_command(&parts, &mut running_config);

        assert!(
            result.is_ok(),
            "Failed to enable DHCP server: {:?}",
            result.err()
        );
        assert_eq!(
            running_config.config["service"]["dhcp-server"]["enabled"],
            json!(true),
            "DHCP server was not enabled in the running configuration"
        );
    }

    #[test]
    fn test_set_dhcp_server_enabled_incomplete_config() {
        let mut running_config = RunningConfig::new();

        // Simulate incomplete DHCP configuration
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "start",
                json!("192.168.1.10"),
            )
            .unwrap();
        // Missing other necessary configurations like stop, default-router, etc.

        let parts = vec!["set", "service", "dhcp-server", "enabled"];
        let result = parse_service_dhcp_server_command(&parts, &mut running_config);

        assert!(
            result.is_err(),
            "Expected error for incomplete DHCP configuration"
        );
        assert_eq!(
            result.err().unwrap(),
            "Incomplete DHCP configuration. Set all necessary options before enabling."
        );
    }

    #[test]
    fn test_set_dhcp_server_shared_network_success() {
        let mut running_config = RunningConfig::new();

        let parts = vec![
            "set",
            "service",
            "dhcp-server",
            "shared-network-name",
            "net1",
            "subnet",
            "192.168.1.0/24",
            "start",
            "192.168.1.10",
            "stop",
            "192.168.1.100",
            "default-router",
            "192.168.1.1",
            "dns-server",
            "8.8.8.8",
            "lease",
            "86400",
        ];
        let result = parse_service_dhcp_server_command(&parts, &mut running_config);

        assert!(
            result.is_ok(),
            "Failed to configure DHCP server: {:?}",
            result.err()
        );
        let subnet_config = &running_config.config["service"]["dhcp-server"]["shared-network-name"]
            ["net1"]["subnet"]["192.168.1.0/24"];

        assert_eq!(subnet_config["start"], json!("192.168.1.10"));
        assert_eq!(subnet_config["stop"], json!("192.168.1.100"));
        assert_eq!(subnet_config["default-router"], json!("192.168.1.1"));
        assert_eq!(subnet_config["dns-server"], json!("8.8.8.8"));
        assert_eq!(subnet_config["lease"], json!("86400"));
    }

    #[test]
    fn test_set_dhcp_server_shared_network_invalid_option() {
        let mut running_config = RunningConfig::new();

        let parts = vec![
            "set",
            "service",
            "dhcp-server",
            "shared-network-name",
            "net1",
            "subnet",
            "192.168.1.0/24",
            "invalid-option",
        ];
        let result = parse_service_dhcp_server_command(&parts, &mut running_config);

        assert!(result.is_err(), "Expected error for invalid option");
        assert_eq!(
            result.err().unwrap(),
            "Invalid or incomplete DHCP server option: invalid-option"
        );
    }

    #[test]
    fn test_apply_dhcp_config_success() {
        let mut running_config = RunningConfig::new();

        // Enable DHCP server and set valid configuration
        running_config
            .add_value_to_node(&["service", "dhcp-server"], "enabled", json!(true))
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "start",
                json!("192.168.1.10"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "stop",
                json!("192.168.1.100"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "default-router",
                json!("192.168.1.1"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "dns-server",
                json!("8.8.8.8"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "lease",
                json!("86400"),
            )
            .unwrap();

        let result = apply_dhcp_config(&running_config);
        assert!(
            result.is_ok(),
            "Failed to apply DHCP config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_apply_dhcp_config_dhcp_disabled() {
        let mut running_config = RunningConfig::new();

        // Set valid configuration but don't enable DHCP server
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "start",
                json!("192.168.1.10"),
            )
            .unwrap();
        running_config
            .add_value_to_node(
                &[
                    "service",
                    "dhcp-server",
                    "shared-network-name",
                    "net1",
                    "subnet",
                    "192.168.1.0/24",
                ],
                "stop",
                json!("192.168.1.100"),
            )
            .unwrap();

        let result = apply_dhcp_config(&running_config);
        assert!(result.is_err(), "Expected error for DHCP server disabled");
        assert_eq!(
            result.err().unwrap(),
            "DHCP server is not enabled. Run 'set service dhcp-server enabled' to apply the configuration."
        );
    }
}
