use anyhow::{bail, Result};

const SUBCOMMANDS: &[&str] = &[
    "search",
    "add",
    "remove",
    "update",
    "serve",
    "logs",
    "acl",
    "config",
    "completions",
    "healthcheck",
];

pub fn handle_completions_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: mcp completions <bash|zsh|fish>");
    }
    match args[0].as_str() {
        "bash" => print!("{}", bash_completions()),
        "zsh" => print!("{}", zsh_completions()),
        "fish" => print!("{}", fish_completions()),
        other => bail!("unsupported shell: {other} (use bash, zsh, or fish)"),
    }
    Ok(())
}

fn fish_completions() -> String {
    let mut out = String::from("# mcp fish completions\n");
    out.push_str("# Install: mcp completions fish > ~/.config/fish/completions/mcp.fish\n\n");

    // Disable file completions by default
    out.push_str("complete -c mcp -f\n\n");

    // Global flags
    out.push_str("complete -c mcp -l json -d 'Force JSON output'\n");
    out.push_str("complete -c mcp -l insecure -d 'Allow HTTP on non-loopback interfaces'\n");
    out.push_str("complete -c mcp -l list -d 'List configured servers'\n");
    out.push_str("complete -c mcp -l help -s h -d 'Show help'\n\n");

    // Subcommands (only when no subcommand is selected yet)
    for cmd in SUBCOMMANDS {
        let desc = subcommand_description(cmd);
        out.push_str(&format!(
            "complete -c mcp -n '__fish_use_subcommand' -a '{cmd}' -d '{desc}'\n"
        ));
    }
    out.push('\n');

    // config subcommands
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from config' -a 'path' -d 'Show config file path'\n",
    );
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from config' -a 'edit' -d 'Open config in editor'\n",
    );
    out.push('\n');

    // completions subcommands
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish' -d 'Shell type'\n",
    );
    out.push('\n');

    // acl subcommands
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from acl' -a 'classify' -d 'Classify tools as read/write'\n",
    );
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from acl' -a 'check' -d 'Check ACL decision'\n",
    );
    out.push('\n');

    // logs flags
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from logs' -l limit -d 'Max entries' -r\n",
    );
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from logs' -l server -d 'Filter by server' -r\n",
    );
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from logs' -l tool -d 'Filter by tool prefix' -r\n",
    );
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from logs' -l errors -d 'Show only failures'\n",
    );
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from logs' -l since -d 'Time filter (5m, 1h, 24h, 7d)' -r\n",
    );
    out.push_str("complete -c mcp -n '__fish_seen_subcommand_from logs' -s f -d 'Follow mode'\n");
    out.push('\n');

    // serve flags
    out.push_str(
        "complete -c mcp -n '__fish_seen_subcommand_from serve' -l http -d 'HTTP mode with optional bind address' -r\n",
    );

    out
}

fn bash_completions() -> String {
    let cmds = SUBCOMMANDS.join(" ");
    format!(
        r#"# mcp bash completions
# Install: eval "$(mcp completions bash)" or add to ~/.bashrc

_mcp() {{
    local cur prev words cword
    _init_completion || return

    local subcommands="{cmds}"
    local global_flags="--list --json --insecure --help -h"

    case "${{words[1]}}" in
        config)
            COMPREPLY=( $(compgen -W "path edit" -- "$cur") )
            return
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            return
            ;;
        acl)
            COMPREPLY=( $(compgen -W "classify check" -- "$cur") )
            return
            ;;
        logs)
            COMPREPLY=( $(compgen -W "--limit --server --tool --errors --since -f" -- "$cur") )
            return
            ;;
        serve)
            COMPREPLY=( $(compgen -W "--http --insecure" -- "$cur") )
            return
            ;;
    esac

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcommands $global_flags" -- "$cur") )
    fi
}}

complete -F _mcp mcp
"#
    )
}

fn zsh_completions() -> String {
    let cmds_list: String = SUBCOMMANDS
        .iter()
        .map(|c| format!("            '{c}:{}'", subcommand_description(c)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"#compdef mcp
# mcp zsh completions
# Install: mcp completions zsh > ${{fpath[1]}}/_mcp

_mcp() {{
    local -a subcommands
    subcommands=(
{cmds_list}
    )

    _arguments -C \
        '--list[List configured servers]' \
        '--json[Force JSON output]' \
        '--insecure[Allow HTTP on non-loopback]' \
        '(-h --help){{-h,--help}}[Show help]' \
        '1:subcommand:->subcmd' \
        '*::arg:->args'

    case $state in
        subcmd)
            _describe 'subcommand' subcommands
            ;;
        args)
            case $words[1] in
                config)
                    _values 'config subcommand' 'path[Show config file path]' 'edit[Open config in editor]'
                    ;;
                completions)
                    _values 'shell' bash zsh fish
                    ;;
                acl)
                    _values 'acl subcommand' 'classify[Classify tools]' 'check[Check ACL decision]'
                    ;;
                logs)
                    _arguments \
                        '--limit[Max entries]:limit' \
                        '--server[Filter by server]:server' \
                        '--tool[Filter by tool prefix]:tool' \
                        '--errors[Show only failures]' \
                        '--since[Time filter]:duration' \
                        '-f[Follow mode]'
                    ;;
                serve)
                    _arguments \
                        '--http[HTTP mode with bind address]:address' \
                        '--insecure[Allow HTTP on non-loopback]'
                    ;;
            esac
            ;;
    esac
}}

_mcp "$@"
"#
    )
}

fn subcommand_description(cmd: &str) -> &str {
    match cmd {
        "search" => "Search MCP registry",
        "add" => "Add server from registry",
        "remove" => "Remove server from config",
        "update" => "Refresh server config from registry",
        "serve" => "Start proxy server",
        "logs" => "Show audit log entries",
        "acl" => "Manage access control",
        "config" => "Manage configuration",
        "completions" => "Generate shell completions",
        "healthcheck" => "HTTP health probe",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fish_completions_contains_subcommands() {
        let output = fish_completions();
        for cmd in SUBCOMMANDS {
            assert!(output.contains(cmd), "missing subcommand: {cmd}");
        }
        assert!(output.contains("complete -c mcp"));
    }

    #[test]
    fn test_bash_completions_contains_subcommands() {
        let output = bash_completions();
        for cmd in SUBCOMMANDS {
            assert!(output.contains(cmd), "missing subcommand: {cmd}");
        }
        assert!(output.contains("complete -F _mcp mcp"));
    }

    #[test]
    fn test_zsh_completions_contains_subcommands() {
        let output = zsh_completions();
        for cmd in SUBCOMMANDS {
            assert!(output.contains(cmd), "missing subcommand: {cmd}");
        }
        assert!(output.contains("#compdef mcp"));
    }

    #[test]
    fn test_unsupported_shell() {
        let args = vec!["powershell".to_string()];
        assert!(handle_completions_command(&args).is_err());
    }

    #[test]
    fn test_empty_args() {
        let args: Vec<String> = vec![];
        assert!(handle_completions_command(&args).is_err());
    }
}
