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
use crate::handle_set_command;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::process::Command;
pub struct RunningConfig {
    pub config: Value,
}

impl RunningConfig {
    pub fn new() -> Self {
        let config_path = "/config/currentconfig";
        let mut running_config = if let Ok(config) = RunningConfig::load_from_file(config_path) {
            config
        } else {
            let mut new_config = RunningConfig {
                config: json!({
                   "config-version": "0.1alfa",
                   "interface": {}
                }),
            };

            // Automatically detect Ethernet interfaces and set enabled=true
            new_config.detect_and_initialize_interfaces();

            new_config
        };

        //running_config.apply_settings(None);

        running_config
    }

    //Applies the settings from the configuration to the system.
    //
    //This method collects all commands from the configuration, sorts them based on priority,
    //and applies them in order. Enabled commands are applied last.

    pub fn apply_settings(&mut self, config: Option<&serde_json::Value>) {
        // Clone the config to avoid borrowing self.config while mutably borrowing self
        let config_to_apply = if let Some(config) = config {
            config
        } else {
            &self.config.clone()
        };

        //let config_clone = self.config.clone();
        let mut path = vec![];
        let mut commands: Vec<(i32, String)> = vec![]; // Collect non-enabled commands with priorities
        let mut enabled_commands: Vec<String> = vec![]; // Collect enabled commands separately
        let mut beginning_commands = None; //Collect commands that need to be applied first

        // Collect all commands, separating enabled commands
        self.collect_commands(
            config_to_apply,
            &mut path,
            &mut commands,
            &mut enabled_commands,
            &mut beginning_commands,
        );

        // Sort the commands based on priority
        commands.sort_by(|a, b| a.0.cmp(&b.0));
        // Apply the 'set system ipforwarding enabled' command first if found
        if let Some(beginning_command) = beginning_commands {
            let parts: Vec<&str> = beginning_command.split_whitespace().collect();
            handle_set_command(&parts, self);
        }
        // Apply non-enabled commands first
        for (_, cmd) in commands {
            println!("Applying command: {}", cmd);
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            handle_set_command(&parts, self);
        }

        // Apply the 'enabled' commands last
        for enabled_cmd in enabled_commands {
            println!("Applying 'enabled' command: {}", enabled_cmd);
            let parts: Vec<&str> = enabled_cmd.split_whitespace().collect();
            handle_set_command(&parts, self);
        }
    }

    // Show the commands by collecting and outputting them
    pub fn show_set_commands(&self) -> Result<String, String> {
        let mut path = vec![];
        let mut commands: Vec<(i32, String)> = vec![]; // Collect non-enabled commands with priorities
        let mut enabled_commands: Vec<String> = vec![]; // Collect enabled commands separately
        let mut beginning_commands = None; // Collect commands that need to be applied first

        // Collect all commands from the configuration (non-mutable `self`)
        self.collect_commands(
            &self.config,
            &mut path,
            &mut commands,
            &mut enabled_commands,
            &mut beginning_commands,
        );

        // Sort the commands based on priority
        commands.sort_by(|a, b| a.0.cmp(&b.0));

        let mut output: Vec<String> = Vec::new();

        // Output the 'set system ipforwarding enabled' command first if found
        if let Some(beginning_command) = beginning_commands {
            output.push(beginning_command);
        }

        // Output non-enabled commands
        for (_, cmd) in commands {
            output.push(cmd);
        }

        // Output the 'enabled' commands last
        for enabled_cmd in enabled_commands {
            output.push(enabled_cmd);
        }

        Ok(output.join("\n"))
    }
    // Funcție care colectează comenzile și le asociază cu o prioritate
    fn collect_commands(
        &self,
        node: &Value,
        path: &mut Vec<String>,
        commands: &mut Vec<(i32, String)>,
        enabled_commands: &mut Vec<String>,
        beggining_commands: &mut Option<String>, // Collect enabled commands separately
    ) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    if key == "config-version" {
                        continue;
                    }

                    // Handle 'enabled' commands separately
                    if key == "enabled" {
                        if let Value::Bool(enabled) = value {
                            if *enabled {
                                let command = format!("set {} enabled", path.join(" "));
                                // Special case for system ipforwarding enabled
                                if path.len() == 2
                                    && path[0] == "system"
                                    && path[1] == "ipforwarding"
                                {
                                    *beggining_commands = Some(command);
                                } else {
                                    enabled_commands.push(command);
                                }
                            }
                        }
                        continue; // Skip adding to normal commands
                    }
                    if key == "firewall" && path.is_empty() {
                        if let Value::Object(firewall_map) = value {
                            for (rule_set_name, rule_set_value) in firewall_map {
                                if let Value::Object(rule_set_obj) = rule_set_value {
                                    // Collect commands for firewall rules
                                    if let Some(rules) =
                                        rule_set_obj.get("rules").and_then(|r| r.as_array())
                                    {
                                        // Call collect_firewall_rules here
                                        self.collect_firewall_rules(
                                            rule_set_name,
                                            rules,
                                            path,
                                            commands,
                                        );
                                    }

                                    // Collect other firewall settings (e.g., default-policy)
                                    for (inner_key, inner_value) in rule_set_obj {
                                        if inner_key != "rules" {
                                            path.push(format!("firewall {}", rule_set_name));
                                            path.push(inner_key.clone());
                                            self.collect_commands(
                                                inner_value,
                                                path,
                                                commands,
                                                enabled_commands,
                                                beggining_commands,
                                            );
                                            path.pop();
                                            path.pop();
                                        }
                                    }
                                }
                            }
                        }
                        continue; // Skip the rest of the firewall processing as it's handled above
                    }
                    if key == "nat" && path.is_empty() {
                        if let Value::Object(nat_map) = value {
                            for (nat_type, nat_value) in nat_map {
                                if let Value::Array(nat_array) = nat_value {
                                    for nat_rule in nat_array {
                                        if let Value::Object(rule_map) = nat_rule {
                                            let mut cmd = format!("set nat {}", nat_type);

                                            // Flatten nested objects and treat all fields generically
                                            for (rule_field, rule_val) in rule_map {
                                                // Handle nested objects
                                                if let Value::Object(nested_obj) = rule_val {
                                                    for (nested_key, nested_val) in nested_obj {
                                                        cmd.push_str(&format!(
                                                            " {} {}",
                                                            format!(
                                                                "{} {}",
                                                                rule_field, nested_key
                                                            ),
                                                            nested_val
                                                                .as_str()
                                                                .unwrap_or(&nested_val.to_string())
                                                        ));
                                                    }
                                                } else {
                                                    // Handle non-object fields
                                                    cmd.push_str(&format!(
                                                        " {} {}",
                                                        rule_field,
                                                        rule_val
                                                            .as_str()
                                                            .unwrap_or(&rule_val.to_string())
                                                    ));
                                                }
                                            }

                                            let priority = self.get_command_priority(&path);
                                            println!("Applying nat command: {}", cmd);
                                            commands.push((priority, cmd));
                                        }
                                    }
                                }
                            }
                        }
                        continue; // Skip the rest of the NAT processing as it's handled above
                    }
                    // Recursively handle other keys
                    path.push(key.clone());
                    self.collect_commands(
                        value,
                        path,
                        commands,
                        enabled_commands,
                        beggining_commands,
                    );
                    path.pop();
                }
            }
            Value::Array(array) => {
                for item in array {
                    self.collect_commands(
                        item,
                        path,
                        commands,
                        enabled_commands,
                        beggining_commands,
                    );
                }
            }
            Value::String(s) => {
                let cmd = format!("set {} {}", path.join(" "), s);
                let priority = self.get_command_priority(&path); // Get priority for the command
                commands.push((priority, cmd));
            }
            Value::Number(n) => {
                let cmd = format!("set {} {}", path.join(" "), n.to_string());
                let priority = self.get_command_priority(&path); // Get priority for the command
                commands.push((priority, cmd));
            }
            Value::Bool(_) => {
                let cmd = format!("set {}", path.join(" "));
                let priority = self.get_command_priority(&path); // Get priority for the command
                commands.push((priority, cmd));
            }
            _ => {}
        }
    }
    // Function to handle the firewall rules specifically
    /// Collects a list of firewall rules from the configuration object.
    ///
    /// This function iterates over each rule in the `rules` array and constructs a command string
    /// for it. The constructed commands are then added to the `commands` vector with their respective priorities.
    ///
    fn collect_firewall_rules(
        &self,
        rule_set_name: &str,
        rules: &Vec<Value>,
        path: &mut Vec<String>,
        commands: &mut Vec<(i32, String)>,
    ) {
        for rule in rules {
            if let Value::Object(rule_obj) = rule {
                // Start building the firewall command
                let mut cmd = format!("set firewall {}", rule_set_name);
                let mut is_valid_rule = true;

                // Add each field from the rule to the command
                if let Some(Value::String(action)) = rule_obj.get("action") {
                    cmd.push_str(&format!(" action {}", action));
                } else {
                    is_valid_rule = false;
                }
                if let Some(Value::String(source)) = rule_obj.get("source") {
                    cmd.push_str(&format!(" source {}", source));
                }

                if let Some(Value::String(destination)) = rule_obj.get("destination") {
                    cmd.push_str(&format!(" destination {}", destination));
                }

                if let Some(Value::String(protocol)) = rule_obj.get("protocol") {
                    cmd.push_str(&format!(" protocol {}", protocol));
                }

                if let Some(Value::Number(port)) = rule_obj.get("port") {
                    cmd.push_str(&format!(" port {}", port));
                }

                if is_valid_rule {
                    // Add to the command list with appropriate priority
                    let priority = self.get_command_priority(&path); // Firewall rule priority
                    commands.push((priority, cmd));
                }
            }
        }
    }

    // Funcție care determină prioritatea în funcție de tipul comenzii
    fn get_command_priority(&self, path: &[String]) -> i32 {
        if path.contains(&"system".to_string()) {
            return 2; // Prioritate înaltă pentru setarea politicii implicite
        }
        if path.contains(&"default-policy".to_string()) {
            return 3; // Prioritate înaltă pentru setarea politicii implicite
        }
        if path.contains(&"interface".to_string()) {
            return 5;
        }
        if path.contains(&"nat".to_string()) {
            return 6; // Prioritate medie pentru regulile firewall
        }
        if path.contains(&"interface".to_string()) && path.contains(&"firewall".to_string()) {
            return 7; // Prioritate joasă pentru aplicarea firewall-ului la interfață
        }
        if path.contains(&"rules".to_string()) {
            return 9; // Prioritate medie pentru regulile firewall
        }
        99 // Prioritate generală pentru alte comenzi
    }

    fn handle_multi_key_command(
        &mut self,
        map: &serde_json::Map<String, serde_json::Value>,
        path: &mut Vec<String>,
    ) {
        // Start building the base command
        let cmd_base = format!("set {}", path.join(" "));
        let mut cmd_parts = vec![cmd_base];
        let mut is_complete_command = true;

        // Process each key-value pair in the map
        for (key, value) in map.iter() {
            match value {
                serde_json::Value::String(s) => {
                    cmd_parts.push(format!("{} {}", key, s));
                }
                serde_json::Value::Bool(b) => {
                    cmd_parts.push(format!("{} {}", key, if *b { "true" } else { "false" }));
                }
                serde_json::Value::Object(nested_map) => {
                    // Handle nested objects recursively
                    let mut nested_path = path.clone();
                    nested_path.push(key.clone());
                    self.handle_multi_key_command(nested_map, &mut nested_path);
                    return; // Return after processing the nested object to avoid executing partial commands
                }
                _ => {
                    is_complete_command = false;
                }
            }
        }

        // Only execute the command if it's complete
        if is_complete_command && cmd_parts.len() > 1 {
            let cmd = cmd_parts.join(" ");
            println!("Executing complete command: {:?}", cmd);
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            handle_set_command(&parts, self);
        } else {
            println!("Skipping incomplete command: {:?}", cmd_parts.join(" "));
        }
    }

    /// Detect and initialize interfaces.
    ///
    /// This function reads the `/sys/class/net` directory to find physical Ethernet
    /// interfaces. It then checks if each interface has a type of 1, indicating it's a
    /// physical Ethernet interface. If so, it initializes the interface with `enabled=true`
    /// under "options" and includes its hardware ID.
    fn detect_and_initialize_interfaces(&mut self) {
        let interfaces_dir = "/sys/class/net";
        let entries = fs::read_dir(interfaces_dir).unwrap();

        for entry in entries {
            if let Ok(entry) = entry {
                let interface_name = entry.file_name().into_string().unwrap();

                // Skip VLANs (interfaces with a dot in their name)
                if interface_name.contains('.') {
                    continue;
                }

                // Check if the interface is a physical Ethernet interface
                let interface_type_path = format!("{}/type", entry.path().display());
                if let Ok(interface_type) = fs::read_to_string(&interface_type_path) {
                    if interface_type.trim() == "1" {
                        // Read the hardware address (hw-id)
                        let hwid_path = format!("{}/address", entry.path().display());
                        let hwid = fs::read_to_string(&hwid_path)
                            .unwrap_or_else(|_| "Unknown".to_string())
                            .trim()
                            .to_string();

                        // Initialize the interface with enabled=true under "options", and include hw-id
                        self.config["interface"][&interface_name] = json!({
                            "options": {
                                "enabled": true,
                                "hw-id": hwid
                            }
                        });
                    }
                }
            }
        }
    }

    pub fn save_running_config(&self) -> Result<(), String> {
        self.save_to_file("/config/currentconfig")
    }

    pub fn save_to_file(&self, filename: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.config).map_err(|e| e.to_string())?;
        fs::write(filename, json).map_err(|e| e.to_string())
    }

    pub fn load_from_file_in_daemon(filename: &str) -> Result<Value, String> {
        let content = fs::read_to_string(filename).map_err(|e| e.to_string())?;
        let config: Value = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        Ok(config)
    }
    pub fn load_from_file(filename: &str) -> Result<Self, String> {
        let content = fs::read_to_string(filename).map_err(|e| e.to_string())?;
        let config: Value = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        Ok(RunningConfig { config })
    }
    pub fn show_current_config(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.config).map_err(|e| e.to_string())
    }
    pub fn set_value_at_node(&mut self, node_path: &[&str], value: Value) -> Result<(), String> {
        let mut current_node = &mut self.config;

        for node in node_path.iter() {
            // Ensure current_node is an object and get the next node in the path
            if !current_node.is_object() {
                return Err(format!("Node {} is not an object", node));
            }

            current_node = current_node
                .as_object_mut()
                .unwrap()
                .entry(node.to_string())
                .or_insert_with(|| json!({}));
        }

        // Set the value at the current node
        *current_node = value;
        Ok(())
    }

    /// Add a value to a node in the configuration.
    ///
    /// This function allows adding values to existing nodes. It traverses through the configuration
    /// tree following the provided path and adds the specified key-value pair to the final node.
    /// If any part of the path does not exist, an error is returned.
    pub fn add_value_to_node(
        &mut self,
        node_path: &[&str],
        key: &str,
        value: Value,
    ) -> Result<(), String> {
        let mut current_node = &mut self.config;

        for node in node_path {
            if !current_node.is_object() {
                return Err(format!("Node {} is not an object", node));
            }

            current_node = current_node
                .as_object_mut()
                .unwrap()
                .entry(node.to_string())
                .or_insert_with(|| json!({}));
        }

        // If key is empty, set the value directly at the current node
        if key.is_empty() {
            *current_node = value;
            Ok(())
        } else {
            // Ensure the final node is an object before inserting the key-value pair
            if let Some(obj) = current_node.as_object_mut() {
                obj.insert(key.to_string(), value);
                Ok(())
            } else {
                Err(format!("Final node {} is not an object", key))
            }
        }
    }

    /// Get a value from a node in the configuration.
    ///
    /// This function traverses through the configuration tree following the provided path and returns the value
    /// associated with the final node if it exists. If any part of the path does not exist, None is returned.
    pub fn get_value_from_node(&self, node_path: &[&str], key: &str) -> Option<&Value> {
        let mut current_node = &self.config;

        for node in node_path {
            // Traverse the JSON structure to the desired node
            if let Some(next_node) = current_node.get(node) {
                current_node = next_node;
            } else {
                return None; // Node path does not exist
            }
        }

        // Return the value if the final node is an object and contains the key
        current_node.get(key)
    }
    /// Get a mutable reference to a value from a node in the configuration.
    ///
    /// This function traverses through the configuration tree following the provided path and returns a mutable reference
    /// to the value associated with the final node if it exists. If any part of the path does not exist, None is returned.
    pub fn get_value_from_node_mut(&mut self, node_path: &[&str], key: &str) -> Option<&mut Value> {
        let mut current_node = &mut self.config;

        for node in node_path {
            current_node = current_node.get_mut(node)?;
        }

        current_node.get_mut(key)
    }
    pub fn get_or_create_array_node(&mut self, path: &[&str]) -> &mut Value {
        let mut current_node = &mut self.config;

        for key in path {
            current_node = current_node
                .as_object_mut()
                .unwrap()
                .entry(key.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
        }

        // Ensure the final node is an array
        if !current_node.is_array() {
            *current_node = Value::Array(Vec::new());
        }

        current_node
    }

    /// Remove a value from a node in the configuration.
    ///
    /// This function allows removing values from existing nodes. It traverses through the configuration
    /// tree following the provided path and removes the specified key-value pair from the final node.
    /// If any part of the path does not exist, an error is returned.
    ///
    /// # Arguments
    /// * `node_path`: The path to the node where the value will be removed. This must be a list of string keys
    /// * `key`: The key of the value that will be removed from the final node
    pub fn remove_value_from_node(&mut self, node_path: &[&str], key: &str) -> Result<(), String> {
        let mut current_node = &mut self.config;

        for node in node_path {
            // Ensure current_node is an object and get the next node in the path
            if !current_node.is_object() {
                return Err(format!("Node {} is not an object", node));
            }

            current_node = current_node
                .as_object_mut()
                .unwrap()
                .get_mut(*node) // Use *node to get a &str from node, which is a &str
                .ok_or_else(|| format!("Node {} does not exist", node))?;
        }

        // Ensure the final node is an object before removing the key-value pair
        if let Some(obj) = current_node.as_object_mut() {
            obj.remove(key);
            Ok(())
        } else {
            Err(format!("Final node {} is not an object", key))
        }
    }
}
