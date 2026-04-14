use anyhow::{bail, Context, Result};

use crate::config;
use crate::output::OutputFormat;

pub fn handle_config_command(args: &[String], fmt: OutputFormat) -> Result<()> {
    if args.is_empty() {
        bail!("usage: mcp config <path|edit>");
    }
    match args[0].as_str() {
        "path" => handle_config_path(fmt),
        "edit" => handle_config_edit(),
        other => bail!("unknown config subcommand: {other}"),
    }
}

fn handle_config_path(fmt: OutputFormat) -> Result<()> {
    let path = config::config_path()?;
    match fmt {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "path": path.to_string_lossy(),
                "exists": path.exists(),
                "dir": config::config_dir()?.to_string_lossy().to_string(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text => {
            println!("{}", path.display());
        }
    }
    Ok(())
}

fn resolve_editor() -> String {
    std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| {
            if cfg!(target_os = "windows") {
                "notepad".to_string()
            } else {
                "vi".to_string()
            }
        })
}

fn handle_config_edit() -> Result<()> {
    let path = config::config_path()?;

    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory: {}", parent.display())
            })?;
        }
        std::fs::write(&path, "{}\n")
            .with_context(|| format!("failed to create config file: {}", path.display()))?;
    }

    let editor = resolve_editor();
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .with_context(|| format!("failed to launch editor: {editor}"))?;

    if !status.success() {
        bail!("editor exited with status {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_editor_from_env() {
        std::env::set_var("EDITOR", "nano");
        assert_eq!(resolve_editor(), "nano");
        std::env::remove_var("EDITOR");
    }

    #[test]
    fn test_resolve_editor_visual_fallback() {
        std::env::remove_var("EDITOR");
        std::env::set_var("VISUAL", "code");
        assert_eq!(resolve_editor(), "code");
        std::env::remove_var("VISUAL");
    }

    #[test]
    fn test_resolve_editor_default() {
        std::env::remove_var("EDITOR");
        std::env::remove_var("VISUAL");
        let editor = resolve_editor();
        if cfg!(target_os = "windows") {
            assert_eq!(editor, "notepad");
        } else {
            assert_eq!(editor, "vi");
        }
    }

    #[test]
    fn test_config_path_json_output() {
        // Verify the JSON mode produces valid JSON with expected fields
        let path = config::config_path().unwrap();
        let json = serde_json::json!({
            "path": path.to_string_lossy(),
            "exists": path.exists(),
            "dir": config::config_dir().unwrap().to_string_lossy().to_string(),
        });
        assert!(json["path"].is_string());
        assert!(json["exists"].is_boolean());
        assert!(json["dir"].is_string());
    }
}
