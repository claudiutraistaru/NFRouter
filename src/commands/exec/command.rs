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

use ctrlc;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Once;
use std::thread;
// Use `Once` to ensure the handler is only set once
static HANDLER_ONCE: Once = Once::new();
/// Parse a "set protocol rip" command and update the running configuration accordingly.
///
/// # Parameters
///
/// * `parts`: The parts of the command to parse, as an array of strings.
/// * `running_config`: A mutable reference to the running configuration.
///
/// # Returns
///
/// A `Result` containing a JSON string representing the updated running configuration,
/// or an error message if the command is invalid.

pub fn parse_exec_command(parts: &[&str]) -> Result<String, String> {
    match parts {
        // Enable RIP protocol
        ["exec", "command", "ping", args @ ..] => exec_command_ping(args),
        ["exec", "command", "traceroute", args @ ..] => exec_command_traceroute(args),

        _ => Err("Invalid exec command".to_string()),
    }
}

// This function executes the ping command with arguments
pub fn exec_command_ping(args: &[&str]) -> Result<String, String> {
    if args.is_empty() {
        return Err("No target provided for ping.".to_string());
    }

    // Target for the ping command (the first argument after "ping")
    let target = args[0];

    // Create a shared atomic flag to signal when to stop the ping process
    let running = Arc::new(AtomicBool::new(true));

    // Handle Ctrl+C
    let running_clone = Arc::clone(&running);
    HANDLER_ONCE.call_once(|| {
        let running_clone = Arc::clone(&running);
        ctrlc::set_handler(move || {
            println!("\nCtrl+C pressed! Stopping...");
            running_clone.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    });

    // Spawn the ping command
    let mut child = Command::new("ping")
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start ping process");

    // Capture the output in a separate thread
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    // Print the output line by line
    for line in reader.lines() {
        if !running.load(Ordering::SeqCst) {
            break; // Exit the loop when Ctrl+C is pressed
        }

        match line {
            Ok(output) => println!("{}", output),
            Err(err) => eprintln!("Error reading line: {}", err),
        }
    }

    // Gracefully kill the child process if still running
    let _ = child.kill();
    println!("Ping process terminated.");

    Ok(format!(""))
}

pub fn exec_command_traceroute(args: &[&str]) -> Result<String, String> {
    if args.is_empty() {
        return Err("No target provided for ping.".to_string());
    }

    // Target for the ping command (the first argument after "ping")
    let target = args[0];

    // Create a shared atomic flag to signal when to stop the ping process
    let running = Arc::new(AtomicBool::new(true));

    // Handle Ctrl+C
    let running_clone = Arc::clone(&running);
    HANDLER_ONCE.call_once(|| {
        let running_clone = Arc::clone(&running);
        ctrlc::set_handler(move || {
            println!("\nCtrl+C pressed! Stopping...");
            running_clone.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    });

    // Spawn the ping command
    let mut child = Command::new("traceroute")
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start traceroute process");

    // Capture the output in a separate thread
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    // Print the output line by line
    for line in reader.lines() {
        if !running.load(Ordering::SeqCst) {
            break; // Exit the loop when Ctrl+C is pressed
        }

        match line {
            Ok(output) => println!("{}", output),
            Err(err) => eprintln!("Error reading line: {}", err),
        }
    }

    // Gracefully kill the child process if still running
    let _ = child.kill();
    println!("Ping process terminated.");

    Ok(format!(""))
}
pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("exec command ping <..arguments>", "Execute ping command"),
        (
            "exec command traceroute <..arguments>",
            "Execute traceroute command",
        ),
    ]
}
