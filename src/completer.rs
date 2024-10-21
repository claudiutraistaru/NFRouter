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
use crate::collect_help_lines;
use crate::commands::help::help_for_context;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::validate::{ValidationContext, ValidationResult};
use rustyline::Context;
use rustyline::Helper;
use std::collections::HashMap;
pub struct CommandCompleter {
    commands: HashMap<String, Vec<String>>,
}

impl CommandCompleter {
    pub fn new(help_lines: Vec<(&'static str, &'static str)>) -> Self {
        let mut commands = HashMap::new();

        for (cmd, _) in help_lines {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.len() > 1 {
                let entry = commands.entry(parts[0].to_string()).or_insert(Vec::new());
                entry.push(parts[1..].join(" "));
            } else {
                commands.entry(parts[0].to_string()).or_insert(Vec::new());
            }
        }

        CommandCompleter { commands }
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let mut start = 0;
        let mut suggestions = Vec::new();

        let parts: Vec<&str> = line[..pos].split_whitespace().collect();
        if parts.is_empty() {
            return Ok((start, suggestions));
        }

        if parts.len() == 1 {
            start = 0;
            suggestions = self
                .commands
                .keys()
                .filter(|&cmd| cmd.starts_with(parts[0]))
                .map(|cmd| Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                })
                .collect();
        } else {
            let mut current_subcommands: Option<&Vec<String>> = None;

            // Navigate through the command tree to find the appropriate subcommands.
            for i in 0..(parts.len() - 1) {
                if let Some(sub_commands) = self.commands.get(parts[i]) {
                    current_subcommands = Some(sub_commands);
                } else {
                    return Ok((start, suggestions)); // No valid command path, return empty suggestions.
                }
            }

            // If we found subcommands, filter and suggest based on the last part.
            if let Some(sub_commands) = current_subcommands {
                start = line[..pos].find(' ').unwrap_or(0) + 1;
                let prefix = &line[start..pos];

                suggestions = sub_commands
                    .iter()
                    .filter(|cmd| cmd.starts_with(prefix))
                    .map(|cmd| Pair {
                        display: cmd.to_string(),
                        replacement: cmd.to_string(),
                        //This suggest the whole command as it si shown in help but it doubles set
                        //replacement: format!("{}{}", &line[..start], cmd),

                        //This suggest next word only but after first suggestion it doesn`t suggest as it should
                        //replacement:   cmd.split_whitespace().next().unwrap_or("").to_string(),
                    })
                    .collect();
            }
        }

        Ok((start, suggestions))
    }
}

pub struct MyHelper {
    completer: CommandCompleter,
}

impl MyHelper {
    pub fn new(help_lines: Vec<(&'static str, &'static str)>) -> Self {
        Self {
            completer: CommandCompleter::new(help_lines),
        }
    }
}

impl Completer for MyHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let help_lines = collect_help_lines();

        // Find the start of the word to be completed
        let start = line[..pos]
            .rfind(|c: char| c.is_whitespace())
            .map_or(0, |i| i + 1);

        let current_word = &line[start..pos];
        let context = line[..start].trim_end();
        let context_parts: Vec<&str> = context.split_whitespace().collect();

        let context_str = if context_parts.is_empty() {
            None
        } else {
            Some(context_parts.join(" "))
        };

        let filtered_help = help_for_context(help_lines, context_str);

        let suggestions = filtered_help
            .into_iter()
            .filter(|(cmd, _)| cmd.starts_with(current_word))
            .map(|(cmd, _)| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();

        Ok((start, suggestions))
    }
}

//impl Hinter for MyHelper {}

impl Highlighter for MyHelper {}
impl Hinter for MyHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Validator for MyHelper {
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None))
    }
}
impl Helper for MyHelper {}
