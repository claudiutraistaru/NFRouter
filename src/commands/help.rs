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
use std::collections::HashMap;
use std::collections::HashSet;

//use crate::commands::show::ip::command::help_ip_command;

pub fn build_help_message() -> String {
    let mut help_lines = vec!["Available commands:".to_string()];

    // Adăugăm comenzile din modulul `hostname`
    for (cmd, desc) in help_command() {
        help_lines.push(format!("  {:<40} - {}", cmd, desc));
    }

    // Adăugăm comenzile din modulul `ip`
    // for (cmd, desc) in help_ip_command() {
    //     help_lines.push(format!("  {:<40} - {}", cmd, desc));
    // }

    // Adăugăm comenzile generale
    help_lines.push(format!(
        "  {:<40} - {}",
        "save running-config", "Save the current configuration to a file."
    ));
    help_lines.push(format!("  {:<40} - {}", "help", "Show this help message."));
    help_lines.push(format!("  {:<40} - {}", "exit", "Exit the CLI."));

    help_lines.join("\n")
}
pub fn build_help_message_vec() -> Vec<(&'static str, &'static str)> {
    let mut help_items = Vec::new();

    // // Add commands from the hostname module
    // help_items.extend(hostname::help_command());

    // // Add commands from other modules (e.g., ip)
    // help_items.extend(interface::help_command());

    // Add general commands
    // let general_commands = vec![
    //     ("save current-config", "Save the current configuration to a file."),
    //     ("help", "Show this help message."),
    //     ("exit", "Exit the CLI."),
    // ];

    // help_items.extend(general_commands);

    help_items
}

pub fn help_for_context(
    help_lines: Vec<(&'static str, &'static str)>,
    context: Option<String>,
) -> Vec<(String, String)> {
    let mut next_words: HashMap<String, (&str, usize)> = HashMap::new();
    let context_parts: Vec<&str> = context
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .collect();

    for (cmd, desc) in help_lines {
        let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
        if cmd_parts.len() > context_parts.len() && match_command(&cmd_parts, &context_parts) {
            let next_word = cmd_parts[context_parts.len()];
            let key = next_word.to_string();

            // Keep the description of the command with the shortest length (most general)
            let current_length = cmd_parts.len();
            if let Some((_, existing_length)) = next_words.get(&key) {
                if current_length < *existing_length {
                    next_words.insert(key, (desc, current_length));
                }
            } else {
                next_words.insert(key, (desc, current_length));
            }
        }
    }

    let mut results = Vec::new();
    for (word, (desc, _)) in next_words {
        results.push((word, desc.to_string()));
    }

    // Sort results for consistent ordering (optional)
    results.sort_by(|a, b| a.0.cmp(&b.0));

    results
}

fn match_command(cmd_parts: &[&str], context_parts: &[&str]) -> bool {
    if context_parts.len() > cmd_parts.len() {
        return false;
    }
    for (cmd_part, context_part) in cmd_parts.iter().zip(context_parts.iter()) {
        if cmd_part.starts_with('<') && cmd_part.ends_with('>') {
            // Variable part, matches any context_part
            continue;
        } else if cmd_part != context_part {
            return false;
        }
    }
    true
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "save current-config",
            "Save the current configuration to a file.",
        ),
        ("help", "Show this help message."),
        ("exit", "Exit the CLI."),
    ]
}
