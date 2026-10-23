//! Template rendering.
//!
//! Templates are embedded with `include_str!`, so the binary carries the UI and
//! there is no build step, no asset directory to deploy, and no way for the
//! running binary to disagree with the templates it was compiled with.

use minijinja::Environment;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use super::{urlencode, Flash, MapExt, UiState, Viewer};

const TEMPLATES: &[(&str, &str)] = &[
    ("base.html", include_str!("templates/base.html")),
    ("overview.html", include_str!("templates/overview.html")),
    ("servers.html", include_str!("templates/servers.html")),
    ("server.html", include_str!("templates/server.html")),
    ("edit.html", include_str!("templates/edit.html")),
    ("playground.html", include_str!("templates/playground.html")),
    ("activity.html", include_str!("templates/activity.html")),
    ("access.html", include_str!("templates/access.html")),
    ("settings.html", include_str!("templates/settings.html")),
    ("login.html", include_str!("templates/login.html")),
    (
        "access_token.html",
        include_str!("templates/access_token.html"),
    ),
    (
        "partials/plan.html",
        include_str!("templates/partials/plan.html"),
    ),
    (
        "partials/activity_rows.html",
        include_str!("templates/partials/activity_rows.html"),
    ),
    (
        "partials/verdict.html",
        include_str!("templates/partials/verdict.html"),
    ),
    (
        "partials/result.html",
        include_str!("templates/partials/result.html"),
    ),
];

#[derive(Debug)]
pub struct RenderError(pub String);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RenderError {}

fn env() -> Result<&'static Environment<'static>, RenderError> {
    static ENV: OnceLock<Result<Environment<'static>, String>> = OnceLock::new();
    match ENV.get_or_init(|| {
        let mut env = Environment::new();
        for (name, source) in TEMPLATES {
            env.add_template(name, source)
                .map_err(|e| format!("template {name} is invalid: {e}"))?;
        }
        env.add_filter("urlencode", |value: String| urlencode(&value));
        env.add_filter("json", |value: String| {
            serde_json::from_str::<serde_json::Value>(&value)
                .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
                .unwrap_or(value)
        });
        Ok(env)
    }) {
        Ok(env) => Ok(env),
        Err(message) => Err(RenderError(message.clone())),
    }
}

/// Renders a whole page, or a fragment when the template has no `base.html`
/// parent.
pub fn render(name: &str, ctx: Map<String, Value>) -> Result<String, RenderError> {
    let template = env()?
        .get_template(name)
        .map_err(|e| RenderError(format!("template {name}: {e}")))?;
    template
        .render(minijinja::value::Serde(Value::Object(ctx)))
        .map_err(|e| RenderError(format!("render {name}: {e:#}")))
}

pub fn page(name: &str, ctx: Map<String, Value>) -> Result<String, RenderError> {
    render(name, ctx)
}

/// The chrome every page shares: navigation state, session token, mode.
pub fn base_context(
    state: &UiState,
    active: &str,
    title: &str,
    server_count: usize,
    config_path: &str,
    viewer: &Viewer,
    flash: &Flash,
) -> Map<String, Value> {
    let mut ctx = Map::new();
    ctx.put("active", json!(active));
    ctx.put("page_title", json!(title));
    ctx.put("server_count", json!(server_count));
    ctx.put("token", json!(state.token));
    ctx.put("read_only", json!(state.read_only));
    ctx.put("read_only_reason", json!(read_only_reason(state)));
    ctx.put("addr", json!(state.addr));
    ctx.put("version", json!(env!("CARGO_PKG_VERSION")));
    ctx.put("uptime", json!(state.uptime()));
    ctx.put("config_path", json!(config_path));
    ctx.put("flash_ok", json!(flash.ok));
    ctx.put("flash_err", json!(flash.err));
    ctx.put("viewer_team", json!(!viewer.is_local()));
    ctx.put("viewer_admin", json!(viewer.admin));
    ctx.put("subject", json!(viewer.subject()));
    ctx.put("db_error", json!(state.db_error));
    ctx
}

fn read_only_reason(state: &UiState) -> Option<&'static str> {
    if state.read_only {
        Some("started with --read-only: every mutating route is disabled")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A broken template must fail here, not on the first request.
    #[test]
    fn every_template_compiles() {
        env().expect("templates must compile");
    }

    #[test]
    fn escaping_covers_the_dangerous_characters() {
        assert_eq!(
            escape("<a href='x'>&\""),
            "&lt;a href=&#39;x&#39;&gt;&amp;&quot;"
        );
    }
}

/// Escapes text for the few places that build HTML outside a template.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}
