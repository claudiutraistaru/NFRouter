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
#[macro_use]
extern crate lazy_static;

// Definim o variabilă globală de tip bool, inițializată cu true

use commands::set::interface::set_interface_ip;
use commands::show::currentconfig::show_current_config_command;
use commands::show::firewall::show_firewall;
use commands::show::interface::show_interface;
use commands::unset::interface::{unset_interface_ip, unset_interface_mtu, unset_interface_speed};
use rustyline::error::ReadlineError;
use rustyline::{Config, DefaultEditor, Editor};

mod commands;
mod completer;
mod config;

use crate::completer::{CommandCompleter, MyHelper};
use commands::help::{build_help_message, build_help_message_vec, help_for_context};
use commands::show::hostname::show_hostname_command;
use commands::show::routes::show_routes;
use config::RunningConfig;
use std::env;

//This variable is needed to avoid duplicate running of firewall apply when running with -d (apply whole config)
//This is not the optimal solution but I do not have another for now
lazy_static! {
   pub static ref DETACHED_FLAG: bool = {
        let args: Vec<String> = env::args().collect();
        // Verificăm dacă a fost specificat un argument "set-flag" în linia de comandă
        args.contains(&"-d".to_string())
    };
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let help_lines = collect_help_lines();

    let completer = CommandCompleter::new(help_lines.clone());
    let config = Config::builder().auto_add_history(true).build();
    let helper = MyHelper::new(help_lines.clone());
    let mut rl = Editor::with_config(config).unwrap();
    //let mut running_config: RunningConfig = load_running_config();

    let completer = CommandCompleter::new(help_lines.clone());

    rl.set_helper(Some(helper));
    let mut running_config = RunningConfig::new();
    if args.contains(&"-d".to_string()) {
        running_config.apply_settings();
        // Apply the configurations from the config file
        // The configurations are already applied in RunningConfig::new()
        // So we can simply exit after initializing
        println!("Configurations applied from config file. Exiting.");
        return;
    }
    println!("Enter 'exit' to quit.");
    loop {
        let readline = rl.readline("Router# ");
        match readline {
            Ok(line) => {
                let command = line.trim();
                if command.eq_ignore_ascii_case("exit") {
                    break;
                }
                let parts: Vec<&str> = command.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }
                let mut found_help = false;

                // Verificăm dacă unul dintre părți conține "?"
                for part in &parts {
                    if part == &"?" || part == &"help" {
                        build_help(&parts, &part);

                        found_help = true;
                        break;
                    }
                }

                if !found_help {
                    match parts[0] {
                        "set" => handle_set_command(&parts, &mut running_config),
                        "unset" => handle_unset_command(&parts, &mut running_config),
                        "show" => handle_show_command(&parts, &mut running_config),
                        "exec" => handle_exec_command(&parts),
                        "save" => {
                            if parts.len() == 2
                                && parts[0] == "save"
                                && parts[1] == "current-config"
                            {
                                let _ = match running_config.save_running_config() {
                                    Ok(_) => println!("Running configuration saved successfully."),
                                    Err(_) => println!("Unable to save running config"),
                                };
                            }
                        }
                        _ => println!("Unknown command"),
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                break;
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}

/// Handles the `set` command by parsing its arguments and applying the configuration.
///
/// This function takes a reference to the `RunningConfig` instance, which is used to store
/// the configuration settings. It also takes a slice of strings representing the command
/// parts (e.g., "set" and any additional arguments).
///
/// The function uses the `parse_set_command` function from the `commands::set` module to
/// parse the command parts and apply the configuration.
fn handle_set_command(parts: &[&str], running_config: &mut RunningConfig) {
    match crate::commands::set::parse_set_command(parts, running_config) {
        Ok(output) => println!("{}", output),
        Err(err) => println!("Error: {}", err),
    }
}
fn handle_unset_command(parts: &[&str], running_config: &mut RunningConfig) {
    match crate::commands::unset::parse_unset_command(parts, running_config) {
        Ok(output) => println!("{}", output),
        Err(err) => println!("Error: {}", err),
    }
}
fn handle_show_command(parts: &[&str], running_config: &mut RunningConfig) {
    let result = match parts[1] {
        "hostname" => show_hostname_command(parts),
        "interface" => show_interface(parts, running_config),
        "routes" => show_routes(parts),
        "firewall" => show_firewall(running_config),
        "current-config" => show_current_config_command(running_config),
        _ => Ok("Invalid show command".to_string()),
    };

    // Handle the result (e.g., print it)
    match result {
        Ok(msg) => println!("{}", msg),
        Err(err) => eprintln!("Error: {}", err),
    }
}
fn handle_exec_command(parts: &[&str]) {
    match crate::commands::exec::command::parse_exec_command(parts) {
        Ok(output) => println!("{}", output),
        Err(err) => println!("Error: {}", err),
    }
}

/// Prints help for a given context.
///
/// This function takes a list of help lines and an optional context string. It filters
/// the help lines based on the context and prints the resulting help messages.
fn build_help(parts: &[&str], _part: &str) {
    /// A list of help lines to be filtered.
    let help_lines = collect_help_lines();

    let context = if parts.last() == Some(&"?") {
        if parts.len() > 1 {
            Some(parts[..parts.len() - 1].join(" "))
        } else {
            None
        }
    } else {
        Some(parts.join(" "))
    };

    let filtered_help = help_for_context(help_lines, context);

    for (cmd, desc) in filtered_help {
        println!("{} - {}", cmd, desc);
    }
}

/// Collects and returns a list of help lines from various modules.
///
/// This function aggregates help commands from multiple source files,
/// returning them as a single vector.
fn collect_help_lines() -> Vec<(&'static str, &'static str)> {
    let mut help_lines = Vec::new();
    help_lines.extend(commands::set::hostname::help_commands());
    help_lines.extend(commands::set::interface::help_commands());
    help_lines.extend(commands::set::route::help_command());
    help_lines.extend(commands::show::routes::help_command());
    help_lines.extend(commands::show::currentconfig::help_command());
    help_lines.extend(commands::unset::interface::help_commands());
    help_lines.extend(commands::show::hostname::help_command());
    help_lines.extend(commands::show::interface::help_command());
    help_lines.extend(commands::set::system::help_command());
    help_lines.extend(commands::set::nat::help_command());
    help_lines.extend(commands::help::help_command());
    help_lines.extend(commands::set::firewall::help_commands());
    help_lines.extend(commands::show::firewall::help_commands());
    help_lines.extend(commands::set::service::help_commands());
    help_lines.extend(commands::set::protocol::help_commands());
    help_lines.extend(commands::exec::command::help_commands());
    help_lines
}
