/// Show commands to display the current configuration of RIP parameters.
/// These commands will retrieve the current state of RIP settings and output them.
use crate::config::RunningConfig;
use serde_json::Value;
use std::process::Command;

pub fn show_rip() -> Result<String, String> {
    let output = Command::new("vtysh")
        .arg("-c")
        .arg("show ip rip")
        .output()
        .map_err(|e| format!("Failed to execute vtysh command: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!(
            "Failed to execute show RIP command: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

pub fn help_command() -> Vec<(&'static str, &'static str)> {
    vec![("show rip", "Show RIP informations.")]
}
