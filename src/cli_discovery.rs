use std::collections::HashMap;

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::json;
use tokio::process::Command;

use crate::protocol::Tool;

/// Discover MCP tools from a CLI binary by parsing its --help output.
pub async fn discover_tools(
    command: &str,
    base_args: &[String],
    env: &HashMap<String, String>,
    help_flag: &str,
    depth: u8,
    only: &[String],
) -> Result<Vec<Tool>> {
    let help_output = run_help(command, base_args, env, help_flag).await?;
    let subcommands = parse_subcommands(&help_output);

    let mut tools = Vec::new();

    if subcommands.is_empty() {
        // No subcommands — expose the command itself as a single tool
        let flags = parse_flags(&help_output);
        let tool_name = command
            .rsplit('/')
            .next()
            .unwrap_or(command)
            .replace('-', "_");
        let description = parse_description(&help_output);
        tools.push(build_tool(&tool_name, &description, &flags));
        return Ok(tools);
    }

    for (sub_name, sub_desc) in &subcommands {
        if !only.is_empty() && !only.iter().any(|o| o == sub_name) {
            continue;
        }

        let tool_name = format!(
            "{}_{}",
            command
                .rsplit('/')
                .next()
                .unwrap_or(command)
                .replace('-', "_"),
            sub_name.replace('-', "_")
        );

        if depth > 1 {
            // Get flags from subcommand's own --help
            let mut sub_args = base_args.to_vec();
            sub_args.push(sub_name.clone());
            if let Ok(sub_help) = run_help(command, &sub_args, env, help_flag).await {
                let flags = parse_flags(&sub_help);
                let desc = if sub_desc.is_empty() {
                    parse_description(&sub_help)
                } else {
                    sub_desc.clone()
                };
                tools.push(build_tool(&tool_name, &desc, &flags));
                continue;
            }
        }

        tools.push(build_tool(&tool_name, sub_desc, &[]));
    }

    Ok(tools)
}

async fn run_help(
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
    help_flag: &str,
) -> Result<String> {
    let mut cmd = Command::new(command);
    cmd.args(args).arg(help_flag).envs(env);

    let output = cmd
        .output()
        .await
        .with_context(|| format!("failed to run {command} {help_flag}"))?;

    // Some CLIs write help to stderr (e.g. when exit code != 0)
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    Ok(text)
}

#[derive(Debug, Clone)]
struct Flag {
    long: String,
    value_type: Option<String>,
    description: String,
    is_bool: bool,
}

fn parse_description(help: &str) -> String {
    // Take the first non-empty line that isn't "Usage:" as description
    for line in help.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("Usage:")
            || trimmed.starts_with("usage:")
            || trimmed.starts_with("USAGE:")
        {
            continue;
        }
        // Skip lines that look like flags or subcommands
        if trimmed.starts_with('-')
            || trimmed.starts_with("Available")
            || trimmed.starts_with("Commands:")
        {
            continue;
        }
        return trimmed.to_string();
    }
    String::new()
}

/// Parse subcommands from help output.
/// Looks for patterns like:
///   command_name   Description text
/// in sections labeled "Commands:", "Available Commands:", "SUBCOMMANDS:", etc.
fn parse_subcommands(help: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let mut in_commands_section = false;

    // Match section headers like:
    //   "Commands:", "Available Commands:", "SUBCOMMANDS:",
    //   "Basic Commands (Beginner):", "Deploy Commands:", etc.
    // Match section headers containing "command" or "subcommand" followed by ":"
    // e.g. "Commands:", "Basic Commands (Beginner):", "Subcommands provided by plugins:"
    let section_re = Regex::new(r"(?i)^.*\b(sub)?commands?\b.*:\s*$").unwrap();
    let cmd_re = Regex::new(r"^\s{2,}(\w[\w-]*)\s{2,}(.*)$").unwrap();

    for line in help.lines() {
        let trimmed = line.trim();

        if section_re.is_match(trimmed) {
            in_commands_section = true;
            continue;
        }

        if in_commands_section {
            // Empty line or new section ends the commands block
            if trimmed.is_empty() {
                // Could be spacing between commands, peek ahead
                continue;
            }
            if !line.starts_with(' ') && !line.starts_with('\t') {
                in_commands_section = false;
                continue;
            }

            if let Some(caps) = cmd_re.captures(line) {
                let name = caps[1].to_string();
                let desc = caps[2].trim().to_string();
                // Skip help command itself
                if name != "help" && name != "completion" {
                    results.push((name, desc));
                }
            }
        }
    }

    results
}

/// Parse flags/options from help output.
/// Handles common patterns:
///   -o, --output <format>   Output format           (clap/cobra inline)
///   -n, --namespace string  Namespace               (clap/cobra inline)
///   -A, --all-namespaces    List across all ns       (boolean, no value)
///       --timeout int       Timeout in seconds       (long-only)
///   -o, --output='':                                 (kubectl-style, desc on next line)
///   -A, --all-namespaces=false:                      (kubectl-style boolean)
fn parse_flags(help: &str) -> Vec<Flag> {
    let mut flags = Vec::new();

    // Pattern 1: inline description (clap, cobra, argparse)
    //   -o, --output <format>   Output format
    let inline_re = Regex::new(
        r"^\s+(?:-(\w),\s+)?--(\w[\w-]*)(?:\s+[<\[]?(\w+)[>\]]?|\s*=\s*[<\[]?(\w+)[>\]]?)?\s{2,}(.*)"
    ).unwrap();

    // Pattern 2: kubectl-style with default value and colon
    //   -o, --output='':
    //   -A, --all-namespaces=false:
    //       --chunk-size=500:
    let kubectl_re = Regex::new(r"^\s+(?:-(\w),\s+)?--(\w[\w-]*)=([^:]*):$").unwrap();

    let lines: Vec<&str> = help.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Try kubectl-style first (flag=default: with desc on next line)
        if let Some(caps) = kubectl_re.captures(line) {
            let long = caps[2].to_string();
            if long != "help" && long != "version" {
                let default_val = caps[3].trim().to_string();
                let is_bool = default_val == "false" || default_val == "true";

                // Description is on the next line (tab-indented)
                let description = if i + 1 < lines.len() && lines[i + 1].starts_with('\t') {
                    i += 1;
                    lines[i].trim().to_string()
                } else {
                    String::new()
                };

                let value_type = if is_bool {
                    None
                } else {
                    Some("string".to_string())
                };

                flags.push(Flag {
                    long,
                    value_type,
                    description,
                    is_bool,
                });
            }
            i += 1;
            continue;
        }

        // Try inline-style (clap, cobra, argparse)
        if let Some(caps) = inline_re.captures(line) {
            let long = caps[2].to_string();
            if long != "help" && long != "version" {
                let value_hint = caps
                    .get(3)
                    .or_else(|| caps.get(4))
                    .map(|m| m.as_str().to_lowercase());

                let is_bool = value_hint.is_none();
                let description = caps
                    .get(5)
                    .map(|m| m.as_str().trim().to_string())
                    .unwrap_or_default();

                let value_type = if is_bool {
                    None
                } else {
                    Some(map_value_type(value_hint.as_deref().unwrap_or("string")))
                };

                flags.push(Flag {
                    long,
                    value_type,
                    description,
                    is_bool,
                });
            }
        }

        i += 1;
    }

    flags
}

fn map_value_type(hint: &str) -> String {
    match hint {
        "int" | "integer" | "number" | "uint" | "count" | "n" => "integer".to_string(),
        "float" | "double" | "decimal" => "number".to_string(),
        "bool" | "boolean" => "boolean".to_string(),
        _ => "string".to_string(),
    }
}

fn build_tool(name: &str, description: &str, flags: &[Flag]) -> Tool {
    let mut properties = serde_json::Map::new();

    // Always include a free-form args parameter for positional arguments
    properties.insert(
        "args".to_string(),
        json!({
            "type": "string",
            "description": "Additional positional arguments"
        }),
    );

    for flag in flags {
        let prop = if flag.is_bool {
            json!({
                "type": "boolean",
                "description": flag.description
            })
        } else {
            json!({
                "type": flag.value_type.as_deref().unwrap_or("string"),
                "description": flag.description
            })
        };
        properties.insert(flag.long.replace('-', "_"), prop);
    }

    let schema = json!({
        "type": "object",
        "properties": properties
    });

    Tool {
        name: name.to_string(),
        description: if description.is_empty() {
            None
        } else {
            Some(description.to_string())
        },
        input_schema: Some(schema),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subcommands_kubectl_style() {
        let help = r#"kubectl controls the Kubernetes cluster manager.

Available Commands:
  get          Display one or many resources
  apply        Apply a configuration to a resource
  delete       Delete resources
  help         Help about any command

Flags:
  -h, --help   help for kubectl
"#;
        let subs = parse_subcommands(help);
        assert_eq!(subs.len(), 3);
        assert_eq!(subs[0].0, "get");
        assert_eq!(subs[0].1, "Display one or many resources");
        assert_eq!(subs[1].0, "apply");
        assert_eq!(subs[2].0, "delete");
    }

    #[test]
    fn test_parse_subcommands_git_style() {
        let help = r#"usage: git [-v | --version] [-h | --help]

Commands:
  clone       Clone a repository
  init        Create an empty Git repository
  add         Add file contents to the index
  commit      Record changes to the repository
"#;
        let subs = parse_subcommands(help);
        assert_eq!(subs.len(), 4);
        assert_eq!(subs[0].0, "clone");
    }

    #[test]
    fn test_parse_flags() {
        let help = r#"Usage: kubectl get [flags]

Flags:
  -o, --output string       Output format (json|yaml|wide)
  -n, --namespace string    Namespace
  -A, --all-namespaces      List across all namespaces
      --timeout int         Timeout in seconds
  -h, --help                help for get
"#;
        let flags = parse_flags(help);
        assert_eq!(flags.len(), 4);

        assert_eq!(flags[0].long, "output");
        assert!(!flags[0].is_bool);
        assert_eq!(flags[0].value_type.as_deref(), Some("string"));

        assert_eq!(flags[1].long, "namespace");
        assert!(!flags[1].is_bool);

        assert_eq!(flags[2].long, "all-namespaces");
        assert!(flags[2].is_bool);

        assert_eq!(flags[3].long, "timeout");
        assert_eq!(flags[3].value_type.as_deref(), Some("integer"));
    }

    #[test]
    fn test_parse_flags_with_angle_brackets() {
        let help = r#"Options:
  -f, --file <path>         Input file path
      --format <type>       Output format
  -v, --verbose             Enable verbose output
"#;
        let flags = parse_flags(help);
        assert_eq!(flags.len(), 3);
        assert_eq!(flags[0].long, "file");
        assert!(!flags[0].is_bool);
        assert_eq!(flags[2].long, "verbose");
        assert!(flags[2].is_bool);
    }

    #[test]
    fn test_parse_description() {
        let help = "kubectl controls the Kubernetes cluster manager.\n\nUsage: kubectl [flags]\n";
        assert_eq!(
            parse_description(help),
            "kubectl controls the Kubernetes cluster manager."
        );
    }

    #[test]
    fn test_build_tool() {
        let flags = vec![
            Flag {
                long: "output".to_string(),
                value_type: Some("string".to_string()),
                description: "Output format".to_string(),
                is_bool: false,
            },
            Flag {
                long: "all-namespaces".to_string(),
                value_type: None,
                description: "All namespaces".to_string(),
                is_bool: true,
            },
        ];

        let tool = build_tool("kubectl_get", "Get resources", &flags);
        assert_eq!(tool.name, "kubectl_get");
        assert_eq!(tool.description.as_deref(), Some("Get resources"));

        let schema = tool.input_schema.unwrap();
        let props = schema["properties"].as_object().unwrap();
        assert!(props.contains_key("args"));
        assert!(props.contains_key("output"));
        assert!(props.contains_key("all_namespaces"));
        assert_eq!(props["output"]["type"], "string");
        assert_eq!(props["all_namespaces"]["type"], "boolean");
    }

    #[test]
    fn test_no_subcommands_single_tool() {
        let help = r#"jq - commandline JSON processor

Usage: jq [OPTIONS...] [file...]

  -r, --raw-output    output raw strings
  -c, --compact       compact output
  -S, --sort-keys     sort object keys
"#;
        let subs = parse_subcommands(help);
        assert!(subs.is_empty());

        let flags = parse_flags(help);
        assert_eq!(flags.len(), 3);
    }

    #[test]
    fn test_parse_flags_kubectl_style() {
        let help = "Options:\n    -A, --all-namespaces=false:\n\tList across all namespaces\n    -o, --output='':\n\tOutput format\n        --chunk-size=500:\n\tChunk size for large results\n    -h, --help=false:\n\thelp for get\n";
        let flags = parse_flags(help);
        assert_eq!(flags.len(), 3);

        assert_eq!(flags[0].long, "all-namespaces");
        assert!(flags[0].is_bool);
        assert_eq!(flags[0].description, "List across all namespaces");

        assert_eq!(flags[1].long, "output");
        assert!(!flags[1].is_bool);
        assert_eq!(flags[1].description, "Output format");

        assert_eq!(flags[2].long, "chunk-size");
        assert!(!flags[2].is_bool);
    }

    #[test]
    fn test_parse_subcommands_kubectl_categorized() {
        let help = r#"kubectl controls the Kubernetes cluster manager.

Basic Commands (Beginner):
  create          Create a resource from a file or from stdin
  expose          Take a replication controller, service, deployment or pod

Basic Commands (Intermediate):
  get             Display one or many resources
  delete          Delete resources

Deploy Commands:
  rollout         Manage the rollout of a resource
  scale           Set a new size for a deployment

Subcommands provided by plugins:
  ctx           The command ctx is a plugin installed by the user
"#;
        let subs = parse_subcommands(help);
        let names: Vec<&str> = subs.iter().map(|s| s.0.as_str()).collect();
        assert!(names.contains(&"create"));
        assert!(names.contains(&"get"));
        assert!(names.contains(&"rollout"));
        assert!(names.contains(&"scale"));
        assert!(names.contains(&"ctx"));
        assert_eq!(subs.len(), 7);
    }

    #[test]
    fn test_map_value_type() {
        assert_eq!(map_value_type("int"), "integer");
        assert_eq!(map_value_type("string"), "string");
        assert_eq!(map_value_type("float"), "number");
        assert_eq!(map_value_type("bool"), "boolean");
        assert_eq!(map_value_type("path"), "string");
    }
}
