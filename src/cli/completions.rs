use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::config::Config;

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
    "reload",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    /// Lowercase shell name, as the CLI spells it on input and in output.
    pub fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            other => bail!("unsupported shell: {other} (use bash, zsh, or fish)"),
        }
    }
}

pub fn handle_completions_command(args: &[String], cfg: &Config) -> Result<()> {
    if args.is_empty() {
        bail!("usage: mcp completions <bash|zsh|fish>");
    }
    print!("{}", render(Shell::parse(&args[0])?, cfg));
    Ok(())
}

pub fn render(shell: Shell, cfg: &Config) -> String {
    let servers = server_names(cfg);
    match shell {
        Shell::Bash => bash_completions(&servers),
        Shell::Zsh => zsh_completions(&servers),
        Shell::Fish => fish_completions(&servers),
    }
}

/// Standard install paths that ALREADY exist. Never creates one.
///
/// Bash is deliberately absent: its documented install is an append to
/// `.bashrc` (or an `eval`), and rewriting a user's rc file is not this
/// command's business. Zsh's documented `${fpath[1]}/_mcp` can't be resolved
/// from outside zsh, so the usual locations are probed instead.
pub fn existing_install_paths() -> Vec<(Shell, PathBuf)> {
    match dirs::home_dir() {
        Some(home) => existing_install_paths_in(&home),
        None => Vec::new(),
    }
}

fn existing_install_paths_in(home: &Path) -> Vec<(Shell, PathBuf)> {
    let candidates = [
        (Shell::Fish, home.join(".config/fish/completions/mcp.fish")),
        (Shell::Zsh, home.join(".zsh/completions/_mcp")),
        (Shell::Zsh, home.join(".oh-my-zsh/completions/_mcp")),
        (
            Shell::Zsh,
            PathBuf::from("/usr/local/share/zsh/site-functions/_mcp"),
        ),
        (
            Shell::Zsh,
            PathBuf::from("/opt/homebrew/share/zsh/site-functions/_mcp"),
        ),
    ];
    candidates.into_iter().filter(|(_, p)| p.exists()).collect()
}

/// Sorted, because `cfg.servers` is a `HashMap` and a reload that rewrites the
/// file in a different order each run is noise. Names are pasted into shell
/// string literals, so anything outside a conservative charset is skipped
/// rather than escaped: a broken completion script breaks every new shell.
/// Names that shadow a built-in subcommand are skipped too (duplicate entries).
fn server_names(cfg: &Config) -> Vec<&str> {
    let mut names: Vec<&str> = cfg
        .servers
        .keys()
        .map(String::as_str)
        .filter(|n| {
            !n.is_empty()
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                && !SUBCOMMANDS.contains(n)
        })
        .collect();
    names.sort_unstable();
    names
}

fn fish_completions(servers: &[&str]) -> String {
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
    for name in servers {
        out.push_str(&format!(
            "complete -c mcp -n '__fish_use_subcommand' -a '{name}' -d 'Configured server'\n"
        ));
    }
    out.push('\n');

    if !servers.is_empty() {
        out.push_str(&format!(
            "complete -c mcp -n '__fish_seen_subcommand_from remove update' -a '{}' -d 'Configured server'\n\n",
            servers.join(" ")
        ));
    }

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

fn bash_completions(servers: &[&str]) -> String {
    let cmds = SUBCOMMANDS
        .iter()
        .chain(servers)
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    let server_case = if servers.is_empty() {
        String::new()
    } else {
        format!(
            "        remove|update)\n            COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )\n            return\n            ;;\n",
            servers.join(" ")
        )
    };
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
{server_case}    esac

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcommands $global_flags" -- "$cur") )
    fi
}}

complete -F _mcp mcp
"#
    )
}

fn zsh_completions(servers: &[&str]) -> String {
    let cmds_list: String = SUBCOMMANDS
        .iter()
        .map(|c| format!("            '{c}:{}'", subcommand_description(c)))
        .chain(
            servers
                .iter()
                .map(|s| format!("            '{s}:Configured server'")),
        )
        .collect::<Vec<_>>()
        .join("\n");
    let server_case = if servers.is_empty() {
        String::new()
    } else {
        format!(
            "                remove|update)\n                    _values 'server' {}\n                    ;;\n",
            servers.join(" ")
        )
    };

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
            case $words[2] in
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
{server_case}            esac
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
        "reload" => "Reload config, caches and running proxies",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config_from_path;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const SHELLS: [Shell; 3] = [Shell::Bash, Shell::Zsh, Shell::Fish];

    fn config_from_json(json: &str) -> Config {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{json}").unwrap();
        load_config_from_path(&file.path().to_path_buf()).unwrap()
    }

    fn cfg_with(names: &[&str]) -> Config {
        let servers: Vec<String> = names
            .iter()
            .map(|n| format!(r#""{n}": {{"command": "true", "args": []}}"#))
            .collect();
        config_from_json(&format!(r#"{{"mcpServers": {{{}}}}}"#, servers.join(",")))
    }

    #[test]
    fn test_fish_completions_contains_subcommands() {
        let output = render(Shell::Fish, &cfg_with(&[]));
        for cmd in SUBCOMMANDS {
            assert!(output.contains(cmd), "missing subcommand: {cmd}");
        }
        assert!(output.contains("complete -c mcp"));
    }

    #[test]
    fn test_bash_completions_contains_subcommands() {
        let output = render(Shell::Bash, &cfg_with(&[]));
        for cmd in SUBCOMMANDS {
            assert!(output.contains(cmd), "missing subcommand: {cmd}");
        }
        assert!(output.contains("complete -F _mcp mcp"));
    }

    #[test]
    fn test_zsh_completions_contains_subcommands() {
        let output = render(Shell::Zsh, &cfg_with(&[]));
        for cmd in SUBCOMMANDS {
            assert!(output.contains(cmd), "missing subcommand: {cmd}");
        }
        assert!(output.contains("#compdef mcp"));
    }

    #[test]
    fn test_unsupported_shell() {
        let args = vec!["powershell".to_string()];
        assert!(handle_completions_command(&args, &cfg_with(&[])).is_err());
    }

    #[test]
    fn test_empty_args() {
        let args: Vec<String> = vec![];
        assert!(handle_completions_command(&args, &cfg_with(&[])).is_err());
    }

    #[test]
    fn test_render_includes_server_names() {
        let cfg = cfg_with(&["roam", "grafana", "buser"]);
        for shell in SHELLS {
            let out = render(shell, &cfg);
            for name in ["roam", "grafana", "buser"] {
                assert!(out.contains(name), "{shell:?} missing server {name}");
            }
        }
    }

    #[test]
    fn test_servers_complete_after_remove_and_update() {
        let cfg = cfg_with(&["roam", "grafana"]);
        assert!(render(Shell::Fish, &cfg)
            .contains("__fish_seen_subcommand_from remove update' -a 'grafana roam'"));
        assert!(render(Shell::Bash, &cfg).contains("remove|update)"));
        assert!(render(Shell::Zsh, &cfg).contains("remove|update)"));
    }

    #[test]
    fn test_render_is_deterministic_and_sorted() {
        let cfg = cfg_with(&["zeta", "alpha", "mid", "beta", "omega", "gamma"]);
        for shell in SHELLS {
            let first = render(shell, &cfg);
            assert_eq!(first, render(shell, &cfg), "{shell:?} not deterministic");
            let pos = |n: &str| first.find(n).unwrap();
            assert!(pos("alpha") < pos("beta") && pos("beta") < pos("zeta"));
        }
    }

    #[test]
    fn test_invalid_server_name_is_omitted() {
        let cfg = cfg_with(&["roam", "it's", "has space", "a$b", "back`tick"]);
        assert_eq!(server_names(&cfg), vec!["roam"]);
        for shell in SHELLS {
            let out = render(shell, &cfg);
            assert!(out.contains("roam"));
            for bad in ["it's", "has space", "a$b", "back`tick"] {
                assert!(!out.contains(bad), "{shell:?} leaked {bad:?}");
            }
            assert_eq!(out, render(shell, &cfg_with(&["roam"])));
        }
    }

    #[test]
    fn test_server_named_like_subcommand_is_not_duplicated() {
        let cfg = cfg_with(&["search", "roam"]);
        assert_eq!(server_names(&cfg), vec!["roam"]);
    }

    #[test]
    fn test_reload_in_subcommands_for_all_shells() {
        let cfg = cfg_with(&[]);
        assert_eq!(
            subcommand_description("reload"),
            "Reload config, caches and running proxies"
        );
        assert!(render(Shell::Bash, &cfg).contains("reload"));
        assert!(
            render(Shell::Zsh, &cfg).contains("'reload:Reload config, caches and running proxies'")
        );
        assert!(render(Shell::Fish, &cfg).contains("-a 'reload'"));
    }

    #[test]
    fn test_empty_config_has_no_dangling_server_list() {
        let cfg = cfg_with(&[]);
        let fish = render(Shell::Fish, &cfg);
        assert!(!fish.contains("-a ''"));
        assert!(!fish.contains("remove update"));
        assert!(!render(Shell::Bash, &cfg).contains("remove|update"));
        assert!(!render(Shell::Zsh, &cfg).contains("remove|update"));
        assert!(!render(Shell::Zsh, &cfg).contains("Configured server"));
    }

    #[test]
    fn test_existing_install_paths_only_reports_and_never_creates() {
        let home = tempfile::tempdir().unwrap();
        let fish_dir = home.path().join(".config/fish/completions");
        assert!(existing_install_paths_in(home.path())
            .iter()
            .all(|(_, p)| !p.starts_with(home.path())));
        assert!(!home.path().join(".config").exists());
        assert!(!home.path().join(".zsh").exists());

        std::fs::create_dir_all(&fish_dir).unwrap();
        let fish_file = fish_dir.join("mcp.fish");
        std::fs::write(&fish_file, "").unwrap();
        let found = existing_install_paths_in(home.path());
        assert!(found.contains(&(Shell::Fish, fish_file)));
        assert!(found.iter().all(|(s, _)| *s != Shell::Bash));
    }
}
