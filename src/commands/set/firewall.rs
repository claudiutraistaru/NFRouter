use crate::config::RunningConfig;
use crate::DETACHED_FLAG;
use serde_json::json;
use std::collections::HashSet;
use std::process::{Command, Output};
use std::str;
/// Create a firewall rule set with the given name and update the running configuration.
///
/// If the rule set does not exist in the configuration, it will be created with an empty array of rules.
/// Otherwise, an error is returned indicating that the rule set already exists.
///
/// # Parameters
///
/// * rule_set_name: The name of the firewall rule set to create or check for existence.
/// * running_config: A mutable reference to the running configuration.
///
/// # Returns
///
/// A result containing a success message if the rule set was created, or an error message if it already exists.
pub fn create_firewall_rule_set(
    rule_set_name: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if running_config.config["firewall"]
        .get(rule_set_name)
        .is_none()
    {
        running_config.config["firewall"][rule_set_name] = json!({
            "rules": []            // Array gol pentru reguli
        });
        Ok(format!("Rule set {} created successfully.", rule_set_name))
    } else {
        Err(format!("Rule set {} already exists.", rule_set_name))
    }
}

/// Adds a new firewall rule to the specified rule set in the running configuration.
///
/// The rule will be added at the specified position, or before the default policy if no position is provided.
///
/// If the rule set does not exist in the configuration, it will be created with an empty array of rules.
///
/// # Parameters
///
/// * rule_set_name: The name of the firewall rule set to add a rule to.
/// * rule_number: The position where the new rule should be inserted (optional).
/// * action: The action that this rule will take when matched.
/// * source: The source IP address or network (optional).
/// * destination: The destination IP address or network (optional).
/// * protocol: The protocol to apply this rule for (optional).
/// * port: The port number to apply this rule for (optional).
///
/// # Returns
///
/// A result containing a success message if the rule was added, or an error message if any of the parameters are invalid.
pub fn add_firewall_rule(
    rule_set_name: &str,
    rule_number: Option<u32>,
    action: &str,
    source: Option<&str>,
    destination: Option<&str>,
    protocol: Option<&str>,
    port: Option<u32>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    create_chain(&rule_set_name)?;

    let firewall_config = running_config.config["firewall"]
        .as_object_mut()
        .ok_or_else(|| "Firewall configuration is not a valid object".to_string())?;

    let rule_set = firewall_config
        .get_mut(rule_set_name)
        .and_then(|set| set.as_object_mut())
        .ok_or_else(|| format!("Rule set {} does not exist", rule_set_name))?;

    let rules = rule_set
        .entry("rules")
        .or_insert_with(|| json!([])) // Creează un array gol dacă nu există
        .as_array_mut()
        .ok_or_else(|| format!("Invalid rules structure for rule set {}", rule_set_name))?;

    let mut new_rule = json!({
        "action": action
    });

    if let Some(src) = source {
        new_rule["source"] = json!(src);
    }
    if let Some(dst) = destination {
        new_rule["destination"] = json!(dst);
    }
    if let Some(proto) = protocol {
        new_rule["protocol"] = json!(proto);
    }
    if let Some(p) = port {
        new_rule["port"] = json!(p);
    }

    let mut insert_position = rules.len(); // Implicit, se inserează la final
    for (index, rule) in rules.iter().enumerate() {
        if rule.get("action") == Some(&json!("default-policy")) {
            insert_position = index; // Inserează înainte de "default-policy"
            break;
        }
    }

    if let Some(num) = rule_number {
        if (num as usize) - 1 <= rules.len() {
            rules.insert(num as usize, new_rule);
        } else {
            return Err(format!("Rule number {} is out of bounds", num));
        }
    } else {
        rules.insert(insert_position, new_rule); // Inserează înainte de default-policy sau la final
    }

    let rules_len = rules.len();

    let mut applied_interfaces: HashSet<(String, String)> = HashSet::new();

    let interfaces = running_config.config["interface"]
        .as_object()
        .ok_or_else(|| {
            "add_firewall_rule: Interface configuration is not a valid object".to_string()
        })?;

    if cfg!(test) {
        return Ok(format!(
            "Firewall rule added successfully to {}",
            rule_set_name
        ));
    }
    for (iface_name, iface_config) in interfaces {
        if let Some(firewall_config) = iface_config.get("firewall") {
            for (direction, assigned_rule_set) in firewall_config
                .as_object()
                .unwrap_or(&serde_json::Map::new())
            {
                let iface_direction = (iface_name.to_string(), direction.to_string());

                if assigned_rule_set == rule_set_name
                    && !applied_interfaces.contains(&iface_direction)
                {
                    applied_interfaces.insert(iface_direction.clone());

                    let mut command_args = vec![];
                    if rules_len > 0 {
                        command_args.push("-I".to_string());
                        command_args.push(rule_set_name.to_string());
                        command_args.push((rules_len).to_string()); // Add before the last rule, before default-policy
                    } else {
                        command_args.push("-A".to_string());
                        command_args.push(rule_set_name.to_string());
                    }

                    if let Some(src) = source {
                        command_args.push("-s".to_string());
                        command_args.push(src.to_string());
                    }
                    if let Some(dst) = destination {
                        command_args.push("-d".to_string());
                        command_args.push(dst.to_string());
                    }
                    if let Some(proto) = protocol {
                        command_args.push("-p".to_string());
                        command_args.push(proto.to_string());
                    }
                    if let Some(p) = port {
                        command_args.push("--dport".to_string());
                        command_args.push(p.to_string());
                    }
                    command_args.push("-j".to_string());
                    command_args.push(action.to_string().to_ascii_uppercase());

                    println!(
                        "Executing iptables command: iptables {}",
                        command_args.join(" ")
                    );

                    let output = Command::new("iptables")
                        .args(&command_args)
                        .output()
                        .map_err(|e| format!("Failed to add rule to iptables: {}", e))?;

                    if !output.status.success() {
                        return Err(format!(
                            "Failed to add rule to iptables: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ));

                        println!(
                            "Rule applied successfully to iptables for interface: {} ({})",
                            iface_name, direction
                        );
                    }
                }
            }
        }
    }

    Ok(format!(
        "Firewall rule added successfully to {}",
        rule_set_name
    ))
}

pub fn apply_firewall_to_interface(
    interface: &str,
    direction: &str,
    rule_set_name: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    if direction != "in" && direction != "out" && direction != "local" {
        return Err(format!(
            "Invalid direction: {}. Use 'in' or 'out'",
            direction
        ));
    }

    let firewall_rules = running_config.config["firewall"]
        .get(rule_set_name)
        .ok_or_else(|| format!("Rule set {} does not exist", rule_set_name))?
        .clone();

    if firewall_rules.get("default-policy").is_none() {
        return Err(format!(
            "Rule set {} does not have a default policy in the root firewall object. Please set it before applying to an interface.",
            rule_set_name
        ));
    }

    let interface_config = running_config.config["interface"]
        .get_mut(interface)
        .and_then(|config| config.as_object_mut())
        .ok_or_else(|| {
            format!(
                "Interface {} does not exist or is not a valid object",
                interface
            )
        })?;

    let default_policy = firewall_rules.get("default-policy").and_then(|v| v.as_str())
    .ok_or_else(|| format!("Rule set {} does not have a default policy in the root firewall object. Please set it before applying to an interface.", rule_set_name))?;

    // Dacă există deja secțiunea "firewall" pentru interfață, o actualizăm, altfel o creăm
    let firewall_config = interface_config
        .entry("firewall")
        .or_insert_with(|| json!({}));

    firewall_config[direction] = json!(rule_set_name);
    if cfg!(test) {
        return Ok(format!(
            "Applied firewall {} to interface {} for {} traffic",
            rule_set_name, interface, direction
        ));
    }

    create_chain(&rule_set_name)?;

    let chain_interface_command = if direction == "in" {
        vec!["-A", "FORWARD", "-i", interface, "-j", &rule_set_name]
    } else if direction == "local" {
        vec!["-A", "INPUT", "-i", interface, "-j", &rule_set_name]
    } else {
        vec!["-A", "OUTPUT", "-o", interface, "-j", &rule_set_name]
    };

    println!(
        "Executing command: iptables {}",
        chain_interface_command.join(" ")
    );

    let output = Command::new("iptables")
        .args(&chain_interface_command)
        .output()
        .map_err(|e| format!("Failed to apply chain to interface: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to apply chain to interface: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let rules = firewall_rules
        .get("rules")
        .ok_or_else(|| format!("No rules found in rule set {}", rule_set_name))?;

    if let Some(rules_array) = rules.as_array() {
        for rule in rules_array {
            // Construim comanda iptables în funcție de reguli
            let action = rule
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("ACCEPT");
            let protocol = rule
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp");

            let source = rule.get("source").and_then(|v| v.as_str());
            let destination = rule.get("destination").and_then(|v| v.as_str());

            let port = rule.get("port").and_then(|v| v.as_u64());

            let mut command_args = vec![
                "-A".to_string(),
                rule_set_name.to_string(),
                "-p".to_string(),
                protocol.to_string(),
            ];

            if let Some(src) = source {
                command_args.push("-s".to_string());
                command_args.push(src.to_string()); // Adresa sursă
            } else if let Some(dst) = destination {
                command_args.push("-d".to_string());
                command_args.push(dst.to_string()); // Adresa destinație (fallback dacă nu există source)
            }

            if let Some(p) = port {
                command_args.push("-m".to_string());
                command_args.push(protocol.to_string()); // Se utilizează modul de protocol (necesar pentru port)
                command_args.push("--dport".to_string());
                command_args.push(p.to_string()); // Portul destinație
            }

            command_args.push("-j".to_string());
            command_args.push(action.to_string().to_uppercase());

            println!("Executing command: iptables {}", command_args.join(" "));

            let output = Command::new("iptables")
                .args(&command_args)
                .output()
                .map_err(|e| format!("Failed to add rule to chain: {}", e))?;

            if !output.status.success() {
                return Err(format!(
                    "Failed to add rule to chain: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
    }
    let default_policy = firewall_rules.get("default-policy").and_then(|v| v.as_str())
    .ok_or_else(|| format!("Rule set {} does not have a default policy in the root firewall object. Please set it before applying to an interface.", rule_set_name))?;
    let default_policy_uppercase = default_policy.to_uppercase();

    let default_policy_command = vec!["-A", &rule_set_name, "-j", &default_policy_uppercase];

    println!(
        "Executing command: iptables {}",
        default_policy_command.join(" ")
    );

    let output_policy = Command::new("iptables")
        .args(&default_policy_command)
        .output()
        .map_err(|e| format!("Failed to set default policy for chain: {}", e))?;

    if !output_policy.status.success() {
        return Err(format!(
            "Failed to set default policy for chain: {}",
            String::from_utf8_lossy(&output_policy.stderr)
        ));
    }

    Ok(format!(
        "Applied firewall {} to interface {} for {} traffic",
        rule_set_name, interface, direction
    ))
}

/// Creates a new iptables chain if it does not already exist.
///
/// Args:
///     chain_name: The name of the iptables chain to create.
///
/// Returns:
///     A Result containing an empty string on success or an error message on failure.

fn create_chain(chain_name: &str) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }
    let output_check = Command::new("iptables")
        .args(&["-L", chain_name])
        .output()
        .map_err(|e| format!("Failed to check chain existence: {}", e))?;

    if output_check.status.success() {
        println!("Chain {} already exists, skipping creation.", chain_name);
        return Ok(()); // Chain-ul există, nu trebuie să-l creăm din nou
    }

    let output_create = Command::new("iptables")
        .args(&["-N", chain_name])
        .output()
        .map_err(|e| format!("Failed to create chain: {}", e))?;

    if !output_create.status.success() {
        return Err(format!(
            "Failed to create chain: {}",
            String::from_utf8_lossy(&output_create.stderr)
        ));
    }

    println!("Chain {} created successfully.", chain_name);
    Ok(())
}

/// Checks if the specified ruleset is assigned to the interface.
///
/// Args:
///     chain_name: The name of the ruleset to check for assignment.
///     interface: The name of the interface to check on.
///     direction: The direction (in/out) to check in.
///     running_config: The running configuration object containing the interfaces and their firewall configurations.
///
/// Returns:
///     A Result containing a boolean indicating whether the ruleset is assigned to the interface or not. If an error occurs, returns an error message.

fn is_ruleset_assigned_to_interface(
    chain_name: &str,
    interface: &str,
    direction: &str,
    running_config: &RunningConfig,
) -> Result<bool, String> {
    // Get the interface configuration from the running config
    let interfaces = running_config
        .config
        .get("interface")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            "is_ruleset_assigned_to_interface: Interface configuration is not a valid object"
                .to_string()
        })?;
    // Check if the specified interface exists in the configuration
    if let Some(interface_config) = interfaces.get(interface) {
        // Check if the interface has a firewall assigned in the specified direction (in/out)
        if let Some(firewall_config) = interface_config.get("firewall") {
            if let Some(assigned_ruleset) = firewall_config.get(direction) {
                // Return true if the ruleset matches the chain_name
                return Ok(assigned_ruleset == chain_name);
            }
        }
    }

    // If the ruleset is not assigned, return false
    Ok(false)
}

/// Checks if a specified iptables chain exists.
///
/// Args:
///     chain: The name of the iptables chain to check for existence.
///
/// Returns:
///     A Result containing a boolean indicating whether the chain exists or not. If an error occurs, returns an error message.

fn does_chain_exist(chain: &str) -> Result<bool, String> {
    let output = Command::new("iptables")
        .arg("-S")
        .output()
        .map_err(|e| format!("Failed to check chains: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to list chains: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .any(|line| line.contains(&format!("-N {}", chain))))
}

///
/// Retrieves the existing rules for a specified iptables chain.
///
/// Args:
///     chain: The name of the iptables chain to retrieve rules from.
///
/// Returns:
///     A Result containing a vector of strings representing the existing rules for the chain, or an error message on failure.

fn get_existing_rules(chain: &str) -> Result<Vec<String>, String> {
    let output = Command::new("iptables")
        .arg("-S")
        .arg(chain)
        .output()
        .map_err(|e| format!("Failed to get rules for chain {}: {}", chain, e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to get rules for chain {}: {}",
            chain,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let rules: Vec<String> = stdout.lines().map(|line| line.to_string()).collect();
    Ok(rules)
}

/**
 * Sets the default policy for a specified rule set.
 *
 * Args:
 *     rule_set_name (str): The name of the rule set to set the default policy for.
 *     policy (str): The new default policy to set. Can be 'accept', 'drop', or 'reject'.
 *     running_config (RunningConfig): The running configuration object containing the interfaces and their firewall configurations.
 *
 * Returns:
 *     A Result containing a string indicating whether the default policy was set successfully, or an error message on failure.
 */
pub fn set_default_policy(
    rule_set_name: &str,
    policy: &str,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    match policy {
        "accept" | "drop" | "reject" => {
            let root_config = running_config
                .config
                .as_object_mut()
                .ok_or_else(|| "Root configuration is not a valid object".to_string())?;

            let firewall_config = root_config
                .get_mut("firewall")
                .and_then(|fw| fw.as_object_mut())
                .ok_or_else(|| {
                    "'firewall' configuration is missing or not at root level".to_string()
                })?;

            if firewall_config.get(rule_set_name).is_none() {
                firewall_config.insert(
                    rule_set_name.to_string(),
                    json!({
                        "rules": [],
                        "default-policy": policy,
                    }),
                );
            } else {
                if let Some(rule_set) = firewall_config.get_mut(rule_set_name) {
                    rule_set
                        .as_object_mut()
                        .ok_or_else(|| format!("Rule set {} is not a valid object", rule_set_name))?
                        .insert("default-policy".to_string(), json!(policy));
                }
            }
            if !cfg!(test) {
                let output = Command::new("iptables")
                    .arg("-A")
                    .arg(rule_set_name)
                    .arg("-j")
                    .arg(policy)
                    .output()
                    .map_err(|e| format!("Failed to execute iptables command: {}", e))?;
            }

            Ok(format!(
                "Default policy for rule set {} has been set to {}",
                rule_set_name, policy
            ))
        }
        _ => Err(format!(
            "Invalid policy: {}. Use 'accept', 'drop', or 'reject'.",
            policy
        )),
    }
}

/**
 * Adds a new firewall rule to the specified rule set.
 *
 * Args:
 *     rule_set_name (str): The name of the rule set to add the rule to.
 *     action (str): The action to take when this rule is matched. Can be 'accept', 'drop', or 'reject'.
 *     source (Optional[str]): The IP address or network address to match against for the source of traffic.
 *     destination (Optional[str]): The IP address or network address to match against for the destination of traffic.
 *     protocol (Optional[str]): The protocol to match against. Can be 'tcp', 'udp', or 'icmp'.
 *     port (Optional[int]): The port number to match against. Required if `protocol` is specified.
 *     position (str): The position in which to add the rule relative to an existing rule. Can be 'before' or 'after'. If not specified, the rule will be added at the end of the list.
 *     reference_rule_number (Optional[int]): The number of the rule relative to which the new rule should be positioned. Required if `position` is specified.
 *
 * Returns:
 *     A Result containing a string indicating whether the rule was successfully added, or an error message on failure.
 */
pub fn add_firewall_rule_position(
    rule_set_name: &str,
    reference_rule_number: u32,
    position: &str, // "before" or "after"
    action: &str,
    source: Option<&str>,
    destination: Option<&str>,
    protocol: Option<&str>,
    port: Option<u32>,
    running_config: &mut RunningConfig,
) -> Result<String, String> {
    let firewall_config = running_config.config["firewall"]
        .as_object_mut()
        .ok_or_else(|| "Firewall configuration is not a valid object".to_string())?;

    let rule_set = firewall_config
        .get_mut(rule_set_name)
        .and_then(|set| set.as_object_mut())
        .ok_or_else(|| format!("Rule set {} does not exist", rule_set_name))?;

    let rules = rule_set
        .entry("rules")
        .or_insert_with(|| json!([])) // Create empty array if it doesn't exist
        .as_array_mut()
        .ok_or_else(|| format!("Invalid rules structure for rule set {}", rule_set_name))?;

    if (reference_rule_number as usize) > rules.len() {
        return Err(format!(
            "Reference rule number {} is out of bounds",
            reference_rule_number
        ));
    }

    let mut new_rule = json!({
        "action": action
    });

    if let Some(src) = source {
        new_rule["source"] = json!(src);
    }
    if let Some(dst) = destination {
        new_rule["destination"] = json!(dst);
    }
    if let Some(proto) = protocol {
        new_rule["protocol"] = json!(proto);
    }
    if let Some(p) = port {
        new_rule["port"] = json!(p);
    }

    if position == "insert-before" {
        rules.insert((reference_rule_number) as usize, new_rule);
    } else if position == "insert-after" {
        rules.insert((reference_rule_number) as usize, new_rule);
    } else {
        return Err(format!(
            "Invalid position add_firewall: {}. Use 'before' or 'after'",
            position
        ));
    }

    apply_firewall_rule_to_iptables(
        rule_set_name,
        action,
        source,
        destination,
        protocol,
        port,
        position,
        Some(reference_rule_number), // pass the rule number for positioning
    )?;
    Ok(format!(
        "Firewall rule added {} rule number {} in rule set {}",
        position, reference_rule_number, rule_set_name
    ))
}

/// Applies a firewall rule to iptables based on the specified parameters.
///
/// This function takes various parameters such as action, source and destination IP addresses or network addresses,
/// protocol (tcp/udp/icmp), port number, position ('before' or 'after'), and reference rule number.
///
/// It constructs an iptables command with the provided parameters and executes it. If the execution fails, it returns an error message.
fn apply_firewall_rule_to_iptables(
    rule_set_name: &str,
    action: &str,
    source: Option<&str>,
    destination: Option<&str>,
    protocol: Option<&str>,
    port: Option<u32>,
    position: &str,                     // "before" or "after"
    reference_rule_number: Option<u32>, // Optional, in case we need to insert before/after
) -> Result<(), String> {
    let mut command_args = vec![];

    if let Some(ref_rule) = reference_rule_number {
        let pos = match position {
            "insert-before" => {
                command_args.push("-I".to_string());
                command_args.push(rule_set_name.to_string());
                command_args.push((ref_rule).to_string());
            }
            "insert-after" => {
                command_args.push("-I".to_string());
                command_args.push(rule_set_name.to_string());
                command_args.push((ref_rule + 1).to_string());
            }
            _ => {
                command_args.push("-A".to_string());
                command_args.push(rule_set_name.to_string());
            }
        };
    }

    if let Some(src) = source {
        command_args.push("-s".to_string());
        command_args.push(src.to_string());
    }
    if let Some(dst) = destination {
        command_args.push("-d".to_string());
        command_args.push(dst.to_string());
    }
    if let Some(proto) = protocol {
        command_args.push("-p".to_string());
        command_args.push(proto.to_string());
    }
    if let Some(p) = port {
        command_args.push("--dport".to_string());
        command_args.push(p.to_string());
    }

    command_args.push("-j".to_string());
    command_args.push(action.to_uppercase());
    if cfg!(test) {
        return Ok(());
    }
    println!(
        "Executing iptables command: iptables {}",
        command_args.clone().join(" ")
    );

    let output = Command::new("iptables")
        .args(&command_args)
        .output()
        .map_err(|e| format!("Failed to run iptables: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to add rule to iptables: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "set firewall <rule-set-name> default-policy <accept|drop|reject>",
            "Set the default policy for the specified rule set."
    ),
        (
            "set firewall  <rule-set-name> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp> port <port-number>",
            "Add a firewall rule with the specified action and optional parameters (source, destination, protocol, port, interface)."
        ),
        (
            "set firewall <rule-set-name> insert-before <rule-number> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp> port <port-number> ",
            "Insert a firewall rule before the specified rule number."
        ),
        (
            "set firewall <rule-set-name> insert-after <rule-number> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp> port <port-number>",
            "Insert a firewall rule after the specified rule number."
        ),
        (   "set firewall <rule-set-name>",
            "The name of the firewall rule set you are configuring."
        ),
        (
            "set firewall <rule-set-name> default-policy",
            "Set the default policy for the specified rule set."
        ),
        (
            "set firewall <rule-set-name> action <accept|drop|reject>",
            "The action to take for traffic matching this rule: 'accept', 'drop', or 'reject'"
        ),
        (
            "set firewall <rule-set-name> action <accept|drop|reject> source <ip-address>",
            "Optional; define the source IP address to match for this rule."
        ),
        (
            "set firewall <rule-set-name> action <accept|drop|reject> source <ip-address> destination <ip-address>",
            " Optional; define the destination IP address to match for this rule."
        ),
        (
            "set firewall <rule-set-name> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp>",
            "Optional; specify the protocol to match for this rule (e.g., TCP, UDP, ICMP)."
        ),
        (
            "set firewall <rule-set-name> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp> port <port-number>",
            "Optional; specify the port number for the traffic, if applicable."   
        ),
        (
            "set firewall <rule-set-name> action <accept|drop|reject> destination <ip-address>",
            "Optional; define the destination IP address to match for this rule."
        ),
    ]
}
mod tests {
    use super::*;
    #[test]
    fn test_create_firewall_rule_set() {
        let mut running_config = RunningConfig::new();

        // Test creating a new rule set
        let result = create_firewall_rule_set("test-rule-set", &mut running_config);
        assert!(result.is_ok());
        assert_eq!(
            running_config.config["firewall"]["test-rule-set"]["rules"],
            json!([])
        );

        // Test trying to create the same rule set again
        let result = create_firewall_rule_set("test-rule-set", &mut running_config);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Rule set test-rule-set already exists."
        );
    }

    #[test]
    fn test_add_firewall_rule() {
        let mut running_config = RunningConfig::new();

        // Create a rule set to which the rule will be added
        create_firewall_rule_set("test-rule-set", &mut running_config).unwrap();
        println!(
            "Running config after rule set creation: {:?}",
            running_config.config
        );
        // Add a rule to the rule set
        let result = add_firewall_rule(
            "test-rule-set",
            None,
            "accept",
            Some("192.168.0.1"),
            Some("192.168.0.2"),
            Some("tcp"),
            Some(80),
            &mut running_config,
        );
        //println!("result {:?}", result.clone());
        // assert!(result.is_ok());

        // Check if the rule has been added
        let rules = &running_config.config["firewall"]["test-rule-set"]["rules"];
        assert_eq!(rules.as_array().unwrap().len(), 1);
        assert_eq!(
            rules[0],
            json!({
                "action": "accept",
                "source": "192.168.0.1",
                "destination": "192.168.0.2",
                "protocol": "tcp",
                "port": 80
            })
        );
    }
    #[test]
    fn test_set_default_policy() {
        let mut running_config = RunningConfig::new();

        // Create a rule set
        create_firewall_rule_set("test-rule-set", &mut running_config).unwrap();

        // Set a default policy
        let result = set_default_policy("test-rule-set", "drop", &mut running_config);
        assert!(result.is_ok());
        assert_eq!(
            running_config.config["firewall"]["test-rule-set"]["default-policy"],
            json!("drop")
        );

        // Test invalid policy
        let result = set_default_policy("test-rule-set", "invalid-policy", &mut running_config);
        assert!(result.is_err());
    }
    #[test]
    fn test_add_firewall_rule_position() {
        let mut running_config = RunningConfig::new();

        // Create a rule set
        create_firewall_rule_set("test-rule-set", &mut running_config).unwrap();

        // Add a rule at a specific position
        let result = add_firewall_rule_position(
            "test-rule-set",
            0,
            "insert-before",
            "accept",
            Some("192.168.0.1"),
            Some("192.168.0.2"),
            Some("tcp"),
            Some(80),
            &mut running_config,
        );
        assert!(result.is_ok());

        // Verify the rule is inserted at the correct position
        let rules = &running_config.config["firewall"]["test-rule-set"]["rules"];
        assert_eq!(rules.as_array().unwrap().len(), 1);
        assert_eq!(
            rules[0],
            json!({
                "action": "accept",
                "source": "192.168.0.1",
                "destination": "192.168.0.2",
                "protocol": "tcp",
                "port": 80
            })
        );
    }

    #[test]
    fn test_is_ruleset_assigned_to_interface() {
        let mut running_config = RunningConfig::new();

        // Create a rule set and assign it to an interface
        create_firewall_rule_set("test-rule-set", &mut running_config).unwrap();
        running_config.config["interface"]["eth0"] = json!({
            "firewall": {
                "in": "test-rule-set"
            }
        });

        // Check if the rule set is assigned to the interface
        let result =
            is_ruleset_assigned_to_interface("test-rule-set", "eth0", "in", &running_config);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Check if a non-existent rule set is assigned
        let result =
            is_ruleset_assigned_to_interface("non-existent", "eth0", "in", &running_config);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
