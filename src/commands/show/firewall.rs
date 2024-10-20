use crate::config::RunningConfig;

pub fn parse_show_firewall(running_config: &RunningConfig) -> Result<String, String> {
    // Retrieve the firewall configuration
    let firewall_config = running_config.config["firewall"]
        .as_object()
        .ok_or_else(|| "Firewall configuration is not a valid object".to_string())?;

    // Start building the output string for all rule sets
    let mut output = String::new();

    // Iterate over all rule sets in the firewall configuration
    for (rule_set_name, rule_set_value) in firewall_config.iter() {
        // Retrieve the specific rule set object
        let rule_set = rule_set_value
            .as_object()
            .ok_or_else(|| format!("Rule set {} is not a valid object", rule_set_name))?;

        // Retrieve the default policy, if it exists
        let default_policy = rule_set
            .get("default-policy")
            .and_then(|policy| policy.as_str())
            .unwrap_or("None");

        // Retrieve the rules array
        let rules = rule_set
            .get("rules")
            .and_then(|rules| rules.as_array())
            .ok_or_else(|| format!("No rules found in rule set {}", rule_set_name))?;

        // Append the rule set name and default policy to the output
        output.push_str(&format!(
            "Firewall Rule Set: {}\nDefault Policy: {}\n",
            rule_set_name, default_policy
        ));
        output.push_str("Rules:\n");

        // Iterate over the rules and format each rule with its number and details
        for (index, rule) in rules.iter().enumerate() {
            let action = rule
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");

            let source = rule.get("source").and_then(|v| v.as_str()).unwrap_or("Any");

            let destination = rule
                .get("destination")
                .and_then(|v| v.as_str())
                .unwrap_or("Any");

            let protocol = rule
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("Any");

            let port = rule.get("port").and_then(|v| v.as_u64()).unwrap_or(0);

            // Append rule details to the output
            output.push_str(&format!(
                "{}. Action: {}, Source: {}, Destination: {}, Protocol: {}, Port: {}\n",
                index + 1,
                action,
                source,
                destination,
                protocol,
                if port > 0 {
                    port.to_string()
                } else {
                    "Any".to_string()
                }
            ));
        }
        output.push_str("\n"); // Separate rule sets by a newline
    }

    Ok(output)
}

pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![(
        "show firewall <rule-set-name>",
        "Show the rules and default policy for the specified rule set.",
    )]
}
