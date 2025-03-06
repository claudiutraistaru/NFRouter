use crate::config::RunningConfig;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;
use tempfile::NamedTempFile;

pub fn set_vpn_wireguard(
    interface: String,
    address: Option<String>,
    private_key: Option<String>,
    peer_public_key: Option<String>,
    allowed_ips: Option<String>,
    endpoint: Option<String>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Check if the WireGuard interface exists
    let check_interface = Command::new("ip")
        .arg("link")
        .arg("show")
        .arg(&interface)
        .output();

    if let Err(e) = check_interface {
        return Err(format!("Failed to check WireGuard interface: {}", e));
    }

    let interface_exists = check_interface.unwrap().status.success();

    if !interface_exists {
        // Create the WireGuard interface if it does not exist
        let create_interface = Command::new("ip")
            .arg("link")
            .arg("add")
            .arg("dev")
            .arg(&interface)
            .arg("type")
            .arg("wireguard")
            .output();

        if let Err(e) = &create_interface {
            return Err(format!("Failed to create WireGuard interface: {}", e));
        }

        // if !create_interface.unwrap().status.success() {
        //     return Err(format!(
        //         "Failed to create WireGuard interface: {}",
        //         String::from_utf8_lossy(&create_interface.unwrap().stderr)
        //     ));
        // }
    }

    // Generate the private key if not provided
    let private_key = match private_key {
        Some(key) => key,
        None => {
            let private_key_output = Command::new("wg")
                .arg("genkey")
                .output()
                .map_err(|e| format!("Failed to generate private key: {}", e))?;

            if !private_key_output.status.success() {
                return Err(format!(
                    "Failed to generate private key: {}",
                    String::from_utf8_lossy(&private_key_output.stderr)
                ));
            }

            let private_key = String::from_utf8(private_key_output.stdout)
                .map_err(|e| format!("Failed to parse private key: {}", e))?
                .trim()
                .to_string();

            // Write the private key to a temporary file
            let mut temp_file =
                NamedTempFile::new().map_err(|e| format!("Failed to create temp file: {}", e))?;
            println!("{:?}", &temp_file);
            write!(temp_file.as_file_mut(), "{}", private_key)
                .map_err(|e| format!("Failed to write to temp file: {}", e))?;

            let set_private_key = Command::new("wg")
                .arg("set")
                .arg(&interface)
                .arg("private-key")
                .arg(temp_file.path())
                .output()
                .map_err(|e| format!("Failed to set private key: {}", e))?;

            if !set_private_key.status.success() {
                return Err(format!(
                    "Failed to set private key: {}",
                    String::from_utf8_lossy(&set_private_key.stderr)
                ));
            }

            // Read the private key from the temporary file
            let mut file = File::open(temp_file.path())
                .map_err(|e| format!("Failed to open temp file: {}", e))?;
            let mut private_key_from_file = String::new();
            file.read_to_string(&mut private_key_from_file)
                .map_err(|e| format!("Failed to read private key from temp file: {}", e))?;

            private_key_from_file.trim().to_string()
        }
    };

    if !cfg!(test) {
        // Assign the IP address to the interface if provided (server configuration)
        if let Some(address) = &address {
            let check_interface_again = Command::new("ip")
                .arg("link")
                .arg("show")
                .arg(&interface)
                .output();

            if let Err(e) = check_interface_again {
                return Err(format!("Failed to check WireGuard interface: {}", e));
            }
            let interface_exists = check_interface_again.unwrap().status.success();
            if !interface_exists {
                // Assign the IP address to the interface
                let assign_address = Command::new("ip")
                    .arg("address")
                    .arg("add")
                    .arg(&address)
                    .arg("dev")
                    .arg(&interface)
                    .output()
                    .map_err(|e| format!("Failed to assign IP address: {}", e))?;

                if !assign_address.status.success() {
                    return Err(format!(
                        "Failed to assign IP address: {}",
                        String::from_utf8_lossy(&assign_address.stderr)
                    ));
                }

                // Set the private key for the interface
                let set_private_key = Command::new("wg")
                    .arg("set")
                    .arg(&interface)
                    .arg("private-key")
                    .arg(&private_key)
                    .output()
                    .map_err(|e| format!("Failed to set private key: {}", e))?;

                if !set_private_key.status.success() {
                    return Err(format!(
                        "Failed to set private key: {}",
                        String::from_utf8_lossy(&set_private_key.stderr)
                    ));
                }

                // Enable the interface
                let enable_interface = Command::new("ip")
                    .arg("link")
                    .arg("set")
                    .arg("up")
                    .arg(&interface)
                    .output()
                    .map_err(|e| format!("Failed to enable interface: {}", e))?;

                if !enable_interface.status.success() {
                    return Err(format!(
                        "Failed to enable interface: {}",
                        String::from_utf8_lossy(&enable_interface.stderr)
                    ));
                }
            }
        }

        // Configure the peer if provided
        if let (Some(peer_public_key), Some(allowed_ips)) =
            (peer_public_key.clone(), allowed_ips.clone())
        {
            let mut configure_peer = {
                let mut cmd = Command::new("wg");
                cmd.arg("set")
                    .arg(&interface)
                    .arg("peer")
                    .arg(&peer_public_key)
                    .arg("allowed-ips")
                    .arg(&allowed_ips);

                if let Some(endpoint) = endpoint.clone() {
                    cmd.arg("endpoint").arg(&endpoint);
                }

                cmd
            };

            let configure_peer_output = configure_peer
                .output()
                .map_err(|e| format!("Failed to configure peer: {}", e))?;

            if !configure_peer_output.status.success() {
                return Err(format!(
                    "Failed to configure peer: {}",
                    String::from_utf8_lossy(&configure_peer_output.stderr)
                ));
            }
        }
    }

    // Update the running configuration
    if let Some(address) = address {
        running_config.add_value_to_node(
            &["vpn", "wireguard", &interface],
            "address",
            json! {address},
        )?;
        running_config.add_value_to_node(
            &["vpn", "wireguard", &interface],
            "private-key",
            json! {private_key},
        )?;
    }

    if let Some(peer_public_key) = peer_public_key {
        let peer_config = json!({
            "public-key": peer_public_key,
            "allowed-ips": allowed_ips,
            "endpoint": endpoint,
        });

        running_config.add_value_to_node(
            &["vpn", "wireguard", &interface, "peers"],
            &peer_public_key,
            peer_config,
        )?;
    }

    Ok(format!(
        "WireGuard interface {} configured successfully",
        interface
    ))
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
            (
                "set vpn wireguard <interface> address <address> private-key <private_key>",
                "Configure a WireGuard interface with the specified parameters.",
            ),
            (
                "set vpn wireguard <interface> peer <peer_public_key> allowed-ips <allowed_ips> endpoint <endpoint>",
                "Configure a WireGuard peer with the specified parameters.",
            ),
            (
                "set vpn wireguard <interface> peer <peer_public_key> allowed-ips <allowed_ips>",
                "Configure a WireGuard peer with the specified parameters.",
            ),
            (
                "set interface wireguard <interface> address <address> private-key <private_key>",
                "Configure a WireGuard interface for road-warrior clients with the specified parameters.",
            ),
            (
                "set interface wireguard <interface> peer <peer_public_key> allowed-ips <allowed_ips>",
                "Configure a WireGuard peer for road-warrior clients with the specified parameters.",
            ),
        ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;

    #[test]
    fn test_set_vpn_wireguard() {
        let mut running_config = RunningConfig {
            config: json!({
                "vpn": {}
            }),
        };

        let result = set_vpn_wireguard(
            "wg0".to_string(),
            Some("10.10.10.1/24".to_string()),
            Some("SERVER_PRIVATE_KEY".to_string()),
            None,
            None,
            None,
            &mut running_config,
        );

        assert!(result.is_ok());
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["address"],
            "10.10.10.1/24"
        );
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["private-key"],
            "SERVER_PRIVATE_KEY"
        );
    }

    #[test]
    fn test_set_vpn_wireguard_peer() {
        let mut running_config = RunningConfig {
            config: json!({
                "vpn": {}
            }),
        };

        let result = set_vpn_wireguard(
            "wg0".to_string(),
            None,
            None,
            Some("CLIENT1_PUBLIC_KEY".to_string()),
            Some("10.10.10.2/32".to_string()),
            None,
            &mut running_config,
        );

        assert!(result.is_ok());
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peers"]["CLIENT1_PUBLIC_KEY"]
                ["public-key"],
            "CLIENT1_PUBLIC_KEY"
        );
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peers"]["CLIENT1_PUBLIC_KEY"]
                ["allowed-ips"],
            "10.10.10.2/32"
        );
    }
}
