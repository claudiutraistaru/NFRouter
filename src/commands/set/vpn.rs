use crate::config::RunningConfig;
use base64;
use serde_json::json;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn set_vpn_wireguard(
    interface: String,
    address: Option<String>,
    private_key: Option<String>,
    public_key: Option<String>,
    allowed_ips: Option<String>,
    endpoint: Option<String>,
    enable: bool,
    port: Option<u16>,
    peer_port: Option<u16>,
    peer_public_key: Option<String>,
    peername: Option<String>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    // Ensure /etc/wireguard directory exists
    fs::create_dir_all("/etc/wireguard")
        .map_err(|e| format!("Failed to create /etc/wireguard directory: {}", e))?;

    // Check if the WireGuard interface exists
    let check_interface = Command::new("ip")
        .arg("link")
        .arg("show")
        .arg(&interface)
        .output();

    if let Err(e) = check_interface {
        return Err(format!("Failed to check WireGuard interface: {}", e));
    }

    // Use the provided private key or the one from the config, or generate a new one if not provided
    let private_key = match private_key {
        Some(key) => {
            // Validate the provided private key
            if key.len() != 44 || base64::decode(&key).is_err() {
                return Err(
                    "Invalid private key format. It must be 32 bytes long and base64 encoded."
                        .to_string(),
                );
            }
            key
        }
        None => {
            if let Some(config_key) =
                running_config.config["vpn"]["wireguard"][&interface]["private-key"].as_str()
            {
                config_key.to_string()
            } else {
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

                private_key.to_string()
            }
        }
    };

    // Use the provided public key or generate a new one if not provided
    let public_key = match public_key {
        Some(key) => key,
        None => {
            let mut child = Command::new("wg")
                .arg("pubkey")
                .stdin(Stdio::piped()) // Allow writing to stdin
                .stdout(Stdio::piped()) // Capture stdout
                .spawn()
                .map_err(|e| format!("Failed to start command: {}", e))?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin
                    .write_all(private_key.as_bytes())
                    .map_err(|e| format!("Failed to write to stdin: {}", e))?;
            }

            let output = child
                .wait_with_output()
                .map_err(|e| format!("Failed to read output: {}", e))?;

            String::from_utf8(output.stdout)
                .map_err(|e| format!("Failed to parse public key: {}", e))?
                .trim()
                .to_string()
        }
    };

    // Bring up the interface using wg-quick only if enable is true
    if enable {
        // Fetch parameters from current_config if enable is true
        let address = running_config.config["vpn"]["wireguard"][&interface]["address"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Address not found in current config".to_string())?;
        let private_key = running_config.config["vpn"]["wireguard"][&interface]["private-key"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or(private_key.clone());
        let port = running_config.config["vpn"]["wireguard"][&interface]["port"]
            .as_u64()
            .map(|p| p as u16)
            .unwrap_or(51820); // Default WireGuard port

        // Create the WireGuard configuration file
        let conf_path = format!("/etc/wireguard/{}.conf", interface);
        let mut conf_file =
            File::create(&conf_path).map_err(|e| format!("Failed to create config file: {}", e))?;
        let mut conf_content = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\nListenPort = {}\n",
            private_key,
            address.clone(),
            port // Default WireGuard port
        );

        // Add peers to the configuration
        if let Some(peers) =
            running_config.config["vpn"]["wireguard"][&interface]["peer"].as_object()
        {
            for (peer_name, peer) in peers.iter() {
                let peer_public_key = peer["public-key"].as_str().unwrap_or_default();
                let allowed_ips = peer["allowed-ips"].as_str().unwrap_or_default();
                let endpoint = peer
                    .get("endpoint")
                    .and_then(|e| e.as_str())
                    .unwrap_or_default();
                let peer_port = peer["port"].as_u64().unwrap_or(51820);

                let peer_conf = if !endpoint.is_empty() {
                    format!(
                        "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {}:{}",
                        peer_public_key, allowed_ips, endpoint, peer_port
                    )
                } else {
                    format!(
                        "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}",
                        peer_public_key, allowed_ips
                    )
                };

                conf_content.push_str(&peer_conf);
            }
        }

        conf_file
            .write_all(conf_content.as_bytes())
            .map_err(|e| format!("Failed to write to config file: {}", e))?;
        let up_interface = Command::new("wg-quick")
            .arg("up")
            .arg(&interface)
            .output()
            .map_err(|e| format!("Failed to bring up interface: {}", e))?;

        if !up_interface.status.success() {
            return Err(format!(
                "Failed to bring up interface: {}",
                String::from_utf8_lossy(&up_interface.stderr)
            ));
        }

        // let assign_address = Command::new("ip")
        //     .arg("address")
        //     .arg("add")
        //     .arg(&address)
        //     .arg("dev")
        //     .arg(&interface)
        //     .output()
        //     .map_err(|e| format!("Failed to assign IP address: {}", e))?;

        // if !assign_address.status.success() {
        //     return Err(format!(
        //         "Failed to assign IP address: {}",
        //         String::from_utf8_lossy(&assign_address.stderr)
        //     ));
        // }
    }

    // Update the running configuration
    if let Some(address) = address {
        running_config.add_value_to_node(
            &["vpn", "wireguard", &interface],
            "address",
            json! {address},
        )?;
    }

    running_config.add_value_to_node(
        &["vpn", "wireguard", &interface],
        "private-key",
        json! {private_key},
    )?;

    running_config.add_value_to_node(
        &["vpn", "wireguard", &interface],
        "public-key",
        json! {public_key},
    )?;

    if let Some(port) = port {
        running_config.add_value_to_node(
            &["vpn", "wireguard", &interface],
            "port",
            json! {port},
        )?;
    }

    if enable {
        running_config.add_value_to_node(
            &["vpn", "wireguard", &interface],
            "enabled",
            json!(true),
        )?;
    }

    if let Some(peername) = peername {
        let peer_path = &["vpn", "wireguard", &interface, "peer", &peername];
        if let Some(peer_public_key) = peer_public_key {
            running_config.add_value_to_node(peer_path, "public-key", json! {peer_public_key})?;
        }

        if let Some(allowed_ips) = allowed_ips {
            running_config.add_value_to_node(peer_path, "allowed-ips", json! {allowed_ips})?;
        }

        if let Some(endpoint) = endpoint {
            running_config.add_value_to_node(peer_path, "endpoint", json! {endpoint})?;
        }

        if let Some(peer_port) = peer_port {
            running_config.add_value_to_node(peer_path, "port", json! {peer_port})?;
        }
    }

    Ok(format!(
        "WireGuard interface {} configured successfully",
        interface
    ))
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "set vpn wireguard <interface> address <address> private-key <private_key> public-key <public-key> [port <port>]",
            "Configure a WireGuard interface with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> public-key <peer_public_key> allowed-ips <allowed_ips> endpoint <endpoint> port <port>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> public-key <peer_public_key> allowed-ips <allowed_ips>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> public-key <peer_public_key> endpoint <endpoint> port <port>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> public-key <peer_public_key> port <port>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> allowed-ips <allowed_ips> endpoint <endpoint> port <port>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> allowed-ips <allowed_ips> endpoint <endpoint>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> allowed-ips <allowed_ips> port <port>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> peer <peername> endpoint <endpoint> port <port>",
            "Configure a WireGuard peer with the specified parameters.",
        ),
        (
            "set vpn wireguard <interface> enable",
            "Enable the interface",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunningConfig;
    use serde_json::json;
    use std::fs;

    #[test]
    fn test_set_vpn_wireguard() {
        // Tests: set vpn wireguard <interface> address <address> private-key <private_key> [port <port>]
        let mut running_config = RunningConfig {
            config: json!({
                "vpn": {}
            }),
        };

        let result = set_vpn_wireguard(
            "wg0".to_string(),
            Some("10.10.10.1/24".to_string()),
            Some("8Di7Ea7GZm8REvFF2Nt020gXWPDDyZiHg38eqzaiUUU=".to_string()), // Valid private key
            None,
            None,
            None,
            false,
            None,
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
            "8Di7Ea7GZm8REvFF2Nt020gXWPDDyZiHg38eqzaiUUU="
        );
    }

    #[test]
    fn test_set_vpn_wireguard_peer() {
        // Tests: set vpn wireguard <interface> peers <peername> public-key <peer_public_key> allowed-ips <allowed_ips> endpoint <endpoint> port <port>
        let mut running_config = RunningConfig {
            config: json!({
                "vpn": {
                    "wireguard": {
                        "wg0": {
                            "peer": {}
                        }
                    }
                }
            }),
        };

        let result = set_vpn_wireguard(
            "wg0".to_string(),
            None,
            None,
            None,
            Some("10.10.10.2/32".to_string()),
            Some("endpoint".to_string()),
            false,
            None,
            Some(51820),
            Some("CLIENT1_PUBLIC_KEY".to_string()),
            Some("peer1".to_string()),
            &mut running_config,
        );

        assert!(result.is_ok());
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peer"]["peer1"]["public-key"],
            "CLIENT1_PUBLIC_KEY"
        );
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peer"]["peer1"]["allowed-ips"],
            "10.10.10.2/32"
        );
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peer"]["peer1"]["endpoint"],
            "endpoint"
        );
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peer"]["peer1"]["port"],
            51820
        );
    }

    #[test]
    fn test_set_vpn_wireguard_peer_no_public_key() {
        // Tests: set vpn wireguard <interface> peers <peername> allowed-ips <allowed_ips> port <port>
        let mut running_config = RunningConfig {
            config: json!({
                "vpn": {
                    "wireguard": {
                        "wg0": {
                            "peer": {}
                        }
                    }
                }
            }),
        };

        let result = set_vpn_wireguard(
            "wg0".to_string(),
            None,
            None,
            None,
            Some("10.10.10.2/32".to_string()),
            None,
            false,
            None,
            Some(51820),
            None,
            Some("peer1".to_string()),
            &mut running_config,
        );

        assert!(result.is_ok());
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peer"]["peer1"]["allowed-ips"],
            "10.10.10.2/32"
        );
        assert_eq!(
            running_config.config["vpn"]["wireguard"]["wg0"]["peer"]["peer1"]["port"],
            51820
        );
    }
    #[test]
    fn test_set_vpn_wireguard_peer_no_endpoint_no_port() {
        // Tests: set vpn wireguard <interface> peers <peername> public-key <peer_public_key> allowed-ips <allowed_ips>
        let expected_config = json!({
            "vpn": {
                "wireguard": {
                    "wg0": {
                        "address": "10.10.10.1/24",
                        "port": 51820,
                        "private-key": "8Di7Ea7GZm8REvFF2Nt020gXWPDDyZiHg38eqzaiUUU=", // Valid private key
                        "public-key": "QC9VMng5r5xc9xx4wBNY2PRqcEMzY1XQMhql5XvkcxA=",
                        "peer": {
                            "client1": {
                                "public-key": "CLIENT1_PUBLIC_KEY",
                                "allowed-ips": "0.0.0.0/0"
                            },
                            "client2": {
                                "public-key": "CLIENT2_PUBLIC_KEY",
                                "allowed-ips": "0.0.0.0/0"
                            }
                        }
                    }
                }
            }
        });

        // Load the configuration from the file and apply it
        let mut running_config = RunningConfig::new();
        running_config.apply_settings(Some(&expected_config));

        // Verify that the applied configuration matches the expected configuration
        assert_eq!(running_config.config["vpn"], expected_config["vpn"]);
    }
    #[test]
    fn test_conf_file_generation() {
        // Tests: set vpn wireguard <interface> enable
        let mut running_config = RunningConfig {
            config: json!({
                "vpn": {
                    "wireguard": {
                        "wg0": {
                            "address": "10.10.10.1/24",
                            "port": 51820,
                            "private-key": "8Di7Ea7GZm8REvFF2Nt020gXWPDDyZiHg38eqzaiUUU=", // Valid private key
                            "public-key": "QC9VMng5r5xc9xx4wBNY2PRqcEMzY1XQMhql5XvkcxA=",
                            "enabled": true,
                            "peer": {
                                "client1": {
                                    "public-key": "CLIENT1_PUBLIC_KEY",
                                    "allowed-ips": "0.0.0.0/0",
                                    "endpoint": "endpoint",
                                    "port": 51820
                                },
                                "client2": {
                                    "public-key": "CLIENT2_PUBLIC_KEY",
                                    "allowed-ips": "0.0.0.0/0",
                                    "endpoint": "endpoint2",
                                    "port": 51821
                                }
                            }
                        }
                    }
                }
            }),
        };

        let result = set_vpn_wireguard(
            "wg0".to_string(),
            None,
            None,
            None,
            None,
            None,
            true,
            None,
            None,
            None,
            None,
            &mut running_config,
        );

        let conf_path = "/etc/wireguard/wg0.conf";
        let conf_content = fs::read_to_string(conf_path).expect("Failed to read conf file");

        let expected_content = "[Interface]\nPrivateKey = 8Di7Ea7GZm8REvFF2Nt020gXWPDDyZiHg38eqzaiUUU=\nAddress = 10.10.10.1/24\nListenPort = 51820\n\n[Peer]\nPublicKey = CLIENT1_PUBLIC_KEY\nAllowedIPs = 0.0.0.0/0\nEndpoint = endpoint:51820\n[Peer]\nPublicKey = CLIENT2_PUBLIC_KEY\nAllowedIPs = 0.0.0.0/0\nEndpoint = endpoint2:51821";
        assert_eq!(conf_content, expected_content);
    }

    #[test]
    fn test_apply_config() {
        // Tests: apply_config with an example VPN current configuration
        let expected_config = json!({
            "vpn": {
                "wireguard": {
                    "wg0": {
                        "address": "10.10.10.1/24",
                        "port": 51820,
                        "private-key": "8Di7Ea7GZm8REvFF2Nt020gXWPDDyZiHg38eqzaiUUU=", // Valid private key
                        "public-key": "QC9VMng5r5xc9xx4wBNY2PRqcEMzY1XQMhql5XvkcxA=",
                        "peer": {
                            "client1": {
                                "public-key": "CLIENT1_PUBLIC_KEY",
                                "allowed-ips": "0.0.0.0/0",
                                "endpoint": "endpoint",
                                "port": 51820
                            },
                            "client2": {
                                "public-key": "CLIENT2_PUBLIC_KEY",
                                "allowed-ips": "0.0.0.0/0",
                                "endpoint": "endpoint2",
                                "port": 51821
                            }
                        }
                    }
                }
            }
        });

        // Load the configuration from the file and apply it
        let mut running_config = RunningConfig::new();
        running_config.apply_settings(Some(&expected_config));

        // Verify that the applied configuration matches the expected configuration
        assert_eq!(running_config.config["vpn"], expected_config["vpn"]);
    }
}
