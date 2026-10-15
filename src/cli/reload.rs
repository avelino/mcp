//! `mcp reload` — refresh everything derived from config: this process's
//! caches, the installed shell completions, and every running proxy.
//!
//! A proxy reads `servers.json` once, at boot, and keeps it in memory for the
//! life of the process. Without this command the only way to publish a config
//! change to a running proxy is to restart it, which kills every stdio backend
//! child and every open session along with it.

use anyhow::{bail, Context, Result};
use console::style;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

use super::completions;
use crate::audit::{AuditEntry, AuditLogger};
use crate::cache::{BackendToolCache, ToolCacheStore};
use crate::classifier_cache::ClassifierCache;
use crate::config::{self, Config};
use crate::db::DbPool;
use crate::instances;
use crate::output::OutputFormat;

/// Bearer token for `--url`. An env var and not a flag on purpose: a token
/// passed on the command line lands in `ps` output and in shell history.
const ADMIN_TOKEN_ENV: &str = "MCP_ADMIN_TOKEN";

const REMOTE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct Options {
    url: Option<String>,
    insecure: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut url = None;
        let mut insecure = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--url" => {
                    let value = args
                        .get(i + 1)
                        .filter(|a| !a.starts_with("--"))
                        .ok_or_else(|| anyhow::anyhow!("--url requires a URL"))?;
                    url = Some(value.clone());
                    i += 2;
                }
                "--insecure" => {
                    insecure = true;
                    i += 1;
                }
                other => bail!("unknown argument for `mcp reload`: {other}"),
            }
        }
        Ok(Self { url, insecure })
    }
}

/// Refuse to put the admin token on the wire in the clear.
///
/// The token this sends administers a proxy that fronts every backend the
/// operator configured, so leaking it is worse than a failed reload. Plain
/// HTTP to a loopback address stays allowed: it never leaves the machine, and
/// that is how the local proxies are reached.
fn check_remote_url(url: &str, has_token: bool, insecure: bool) -> Result<()> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid URL: {url}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match parsed.host() {
                Some(url::Host::Domain(host)) => host == "localhost",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if loopback || !has_token || insecure {
                return Ok(());
            }
            bail!(
                "refusing to send {ADMIN_TOKEN_ENV} to {url} over plaintext HTTP, \
                 use https or pass --insecure to accept the risk"
            )
        }
        other => bail!("unsupported URL scheme for --url: {other}"),
    }
}

#[derive(Debug, Default, Serialize)]
struct CacheReport {
    evicted: Vec<String>,
    classifications_forgotten: usize,
}

#[derive(Debug, Serialize)]
struct CompletionReport {
    shell: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct InstanceReport {
    pid: u32,
    target: String,
    /// The catalog narrowing this instance was started with, when it has one.
    /// Two proxies on one machine routinely publish different tool counts,
    /// and this is what explains the difference.
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<String>,
    reloaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RemoteReport {
    url: String,
    /// Whether the request carried a bearer token. Explains a 401 without
    /// putting the token itself anywhere near the output.
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReloadReport {
    config_path: String,
    servers: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    name_conflicts: Vec<String>,
    caches: CacheReport,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    completions: Vec<CompletionReport>,
    instances: Vec<InstanceReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<RemoteReport>,
}

impl ReloadReport {
    /// The first thing worth a non-zero exit status.
    ///
    /// Finding no running proxy is not one: the caches and completions were
    /// still refreshed, and the next `serve` will read the new config anyway.
    fn first_failure(&self) -> Option<String> {
        if let Some(inst) = self.instances.iter().find(|i| !i.reloaded) {
            let detail = inst.error.as_deref().unwrap_or("unknown error");
            return Some(format!(
                "could not reload instance {} ({}): {detail}",
                inst.pid, inst.target
            ));
        }
        if let Some(remote) = &self.remote {
            if let Some(err) = &remote.error {
                return Some(format!("could not reload {}: {err}", remote.url));
            }
            if let Some(status) = remote.status.filter(|s| !(200..300).contains(s)) {
                let hint = match (status, remote.authenticated) {
                    (401, false) => {
                        format!(", set {ADMIN_TOKEN_ENV} to authenticate")
                    }
                    (401, true) => ", the token was rejected".to_string(),
                    (403, _) => {
                        ", the identity has no role listed in serverAuth.adminRoles".to_string()
                    }
                    (404, _) => {
                        ", reload is disabled on that proxy (serverAuth.adminRoles is empty)"
                            .to_string()
                    }
                    _ => String::new(),
                };
                return Some(format!("{} answered HTTP {status}{hint}", remote.url));
            }
        }
        None
    }
}

pub async fn handle_reload_command(
    args: &[String],
    fmt: OutputFormat,
    audit: &Arc<AuditLogger>,
    db_pool: Arc<DbPool>,
) -> Result<()> {
    let opts = Options::parse(args)?;
    let start = std::time::Instant::now();

    let outcome = run_reload(&opts, db_pool).await;

    audit.log(AuditEntry {
        timestamp: chrono::Local::now().to_rfc3339(),
        source: "cli".to_string(),
        method: "config/reload".to_string(),
        tool_name: None,
        server_name: None,
        identity: "local".to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
        success: outcome.is_ok(),
        error_message: outcome.as_ref().err().map(|e| format!("{e:#}")),
        arguments: opts.url.as_ref().map(|url| serde_json::json!({"url": url})),
        acl_decision: None,
        acl_matched_rule: None,
        acl_access_kind: None,
        classification_kind: None,
        classification_source: None,
        classification_confidence: None,
    });

    let report = outcome?;
    print_report(&report, fmt)?;

    // Printed before failing: a partial reload still has to tell the operator
    // which parts went through.
    if let Some(failure) = report.first_failure() {
        bail!(failure);
    }
    Ok(())
}

async fn run_reload(opts: &Options, db_pool: Arc<DbPool>) -> Result<ReloadReport> {
    // First, and on its own: every later step assumes the config parses, and
    // signalling proxies to pick up a broken file would be worse than not
    // reloading at all.
    let cfg = config::load_config().context("config is invalid, nothing was reloaded")?;
    let name_conflicts = config::validate_server_names(&cfg);

    // Checked up front, with the rest of the validation: a rejected URL must
    // not leave caches evicted and completions rewritten behind it.
    let token = admin_token();
    if let Some(url) = &opts.url {
        check_remote_url(url, token.is_some(), opts.insecure)?;
    }

    let caches = evict_stale_caches(&cfg, db_pool);
    let completions = rewrite_completions(&cfg);
    let instances = signal_instances();
    let remote = match &opts.url {
        Some(url) => Some(post_reload(url, token.as_deref()).await),
        None => None,
    };

    Ok(ReloadReport {
        config_path: cfg.path.display().to_string(),
        servers: cfg.servers.len(),
        name_conflicts,
        caches,
        completions,
        instances,
        remote,
    })
}

/// Whether a cached tool list can still be served.
///
/// A backend that left the config is the case `load_valid_backends` cannot
/// see: it only looks up names the config still knows, so an orphan would sit
/// in the database forever.
fn is_stale(config_hash: Option<&String>, cached: Option<&BackendToolCache>) -> bool {
    match (config_hash, cached) {
        (None, _) => true,
        (Some(expected), Some(entry)) => entry.config_hash != *expected,
        (Some(_), None) => false,
    }
}

fn evict_stale_caches(cfg: &Config, pool: Arc<DbPool>) -> CacheReport {
    let store = ToolCacheStore::new(pool);
    let mut evicted = Vec::new();
    for name in store.list_cached_backends() {
        let cached = store.load_backend(&name);
        if is_stale(cfg.config_hashes.get(&name), cached.as_ref()) {
            store.delete_backend(&name);
            evicted.push(name);
        }
    }

    // Classifications outlive their tool cache entry, so the eviction list is
    // not enough: a backend classified without one would keep its entries in
    // the file forever. Anything the config no longer knows goes too.
    let mut cache = ClassifierCache::load();
    let mut forget: Vec<String> = evicted.clone();
    forget.extend(
        cache
            .known_servers()
            .into_iter()
            .filter(|server| !cfg.servers.contains_key(server)),
    );
    forget.sort();
    forget.dedup();

    let mut classifications_forgotten = 0;
    for name in &forget {
        classifications_forgotten += cache.forget_server(name);
    }
    if classifications_forgotten > 0 {
        cache.save();
    }

    CacheReport {
        evicted,
        classifications_forgotten,
    }
}

fn rewrite_completions(cfg: &Config) -> Vec<CompletionReport> {
    let mut written = Vec::new();
    for (shell, path) in completions::existing_install_paths() {
        match std::fs::write(&path, completions::render(shell, cfg)) {
            Ok(()) => written.push(CompletionReport {
                shell: shell.name().to_string(),
                path: path.display().to_string(),
            }),
            // Not worth failing the reload over: the proxies still need to
            // hear about the new config, and a shell file the user cannot
            // write is their packaging to fix.
            Err(e) => tracing::warn!(
                path = %path.display(),
                error = %e,
                "could not rewrite completions"
            ),
        }
    }
    written
}

/// Render an instance's filter as the flags that produced it.
fn describe_filter(filter: &instances::InstanceFilter) -> Option<String> {
    if filter.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if let Some(only) = &filter.only {
        parts.push(format!("only={only}"));
    }
    if let Some(exclude) = &filter.exclude {
        parts.push(format!("exclude={exclude}"));
    }
    Some(parts.join(" "))
}

fn signal_instances() -> Vec<InstanceReport> {
    let live = match instances::list_live() {
        Ok(live) => live,
        Err(e) => {
            tracing::warn!(error = format!("{e:#}"), "could not list running instances");
            return Vec::new();
        }
    };

    live.iter()
        .map(|rec| {
            let filter = describe_filter(&rec.filter());
            match instances::signal_reload(rec) {
                Ok(()) => InstanceReport {
                    pid: rec.pid,
                    target: rec.label(),
                    filter,
                    reloaded: true,
                    error: None,
                },
                Err(e) => InstanceReport {
                    pid: rec.pid,
                    target: rec.label(),
                    filter,
                    reloaded: false,
                    error: Some(format!("{e:#}")),
                },
            }
        })
        .collect()
}

/// Build the reload URL from whatever the operator typed: a bare origin, a
/// path, or the endpoint itself.
fn reload_endpoint(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    if trimmed.ends_with("/reload") {
        return trimmed.to_string();
    }
    format!("{trimmed}/reload")
}

/// The admin token, if the operator exported a non-empty one.
fn admin_token() -> Option<String> {
    std::env::var(ADMIN_TOKEN_ENV)
        .ok()
        .filter(|token| !token.is_empty())
}

async fn post_reload(url: &str, token: Option<&str>) -> RemoteReport {
    let endpoint = reload_endpoint(url);
    let authenticated = token.is_some();
    let failed = |error: String| RemoteReport {
        url: endpoint.clone(),
        authenticated,
        status: None,
        body: None,
        error: Some(error),
    };

    let client = match reqwest::Client::builder().timeout(REMOTE_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => return failed(format!("{e}")),
    };

    let mut request = client.post(&endpoint);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }

    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => return failed(format!("{e}")),
    };
    let status = response.status().as_u16();
    let body = response.json::<serde_json::Value>().await.ok();

    RemoteReport {
        url: endpoint,
        authenticated,
        status: Some(status),
        body,
        error: None,
    }
}

fn print_report(report: &ReloadReport, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        OutputFormat::Text => print_report_text(report),
    }
    Ok(())
}

fn print_report_text(report: &ReloadReport) {
    println!(
        "{:<10} {} ({} servers)",
        style("config").bold(),
        report.config_path,
        report.servers
    );
    for name in &report.name_conflicts {
        println!(
            "{:<10} server {name} shadows a built-in command, rename it",
            style("warn").yellow().bold()
        );
    }

    let caches = &report.caches;
    if caches.evicted.is_empty() {
        println!(
            "{:<10} {}",
            style("caches").bold(),
            style("up to date").dim()
        );
    } else {
        println!(
            "{:<10} {} evicted: {}, {} classifications dropped",
            style("caches").bold(),
            caches.evicted.len(),
            caches.evicted.join(", "),
            caches.classifications_forgotten
        );
    }

    for entry in &report.completions {
        println!(
            "{:<10} {} {}",
            style("shell").bold(),
            entry.shell,
            entry.path
        );
    }

    if report.instances.is_empty() {
        println!(
            "{:<10} {}",
            style("instance").bold(),
            style("none running").dim()
        );
    }
    for inst in &report.instances {
        let filter = match &inst.filter {
            Some(f) => format!(" ({f})"),
            None => String::new(),
        };
        if inst.reloaded {
            println!(
                "{:<10} {} pid {} {}{}",
                style("instance").bold(),
                inst.target,
                inst.pid,
                style("reloaded").green(),
                style(filter).dim()
            );
        } else {
            println!(
                "{:<10} {} pid {}{} {}: {}",
                style("instance").bold(),
                inst.target,
                inst.pid,
                style(filter).dim(),
                style("failed").red(),
                inst.error.as_deref().unwrap_or("unknown error")
            );
        }
    }

    if let Some(remote) = &report.remote {
        match (&remote.error, remote.status) {
            (Some(err), _) => println!(
                "{:<10} {} {}: {err}",
                style("remote").bold(),
                remote.url,
                style("failed").red()
            ),
            (None, Some(status)) if (200..300).contains(&status) => {
                let diff = remote
                    .body
                    .as_ref()
                    .map(summarize_remote)
                    .unwrap_or_else(|| "reloaded".to_string());
                println!(
                    "{:<10} {} {}",
                    style("remote").bold(),
                    remote.url,
                    style(diff).green()
                );
            }
            (None, Some(status)) => println!(
                "{:<10} {} {}",
                style("remote").bold(),
                remote.url,
                style(format!("HTTP {status}")).red()
            ),
            (None, None) => {}
        }
    }
}

/// Condense the proxy's reload response into one line: `+1 ~2 -0`.
fn summarize_remote(body: &serde_json::Value) -> String {
    let count = |key: &str| body.get(key).and_then(|v| v.as_array()).map_or(0, Vec::len);
    let mut out = format!(
        "+{} ~{} -{}",
        count("added"),
        count("changed"),
        count("removed")
    );
    if let Some(tools) = body.get("tools").and_then(serde_json::Value::as_u64) {
        out.push_str(&format!(", {tools} tools"));
    }
    let restart = body
        .get("requires_restart")
        .and_then(|v| v.as_array())
        .map_or(0, Vec::len);
    if restart > 0 {
        out.push_str(&format!(", {restart} change(s) need a restart"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(args: &[&str]) -> Result<Options> {
        let owned: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        Options::parse(&owned)
    }

    #[test]
    fn no_arguments_reloads_locally() {
        assert!(opts(&[]).unwrap().url.is_none());
    }

    #[test]
    fn url_flag_is_parsed() {
        assert_eq!(
            opts(&["--url", "http://127.0.0.1:7332"]).unwrap().url,
            Some("http://127.0.0.1:7332".to_string())
        );
    }

    #[test]
    fn url_without_a_value_is_rejected() {
        assert!(opts(&["--url"]).is_err());
        assert!(opts(&["--url", "--json"]).is_err());
    }

    /// A typo must not silently reload the local instances instead of the
    /// remote one the operator meant to target.
    #[test]
    fn unknown_arguments_are_rejected() {
        let err = opts(&["--urll", "http://x"]).unwrap_err();
        assert!(format!("{err:#}").contains("unknown argument"));
    }

    #[test]
    fn endpoint_accepts_origin_path_or_endpoint() {
        for input in [
            "http://127.0.0.1:7332",
            "http://127.0.0.1:7332/",
            "http://127.0.0.1:7332/reload",
            "http://127.0.0.1:7332/reload/",
        ] {
            assert_eq!(
                reload_endpoint(input),
                "http://127.0.0.1:7332/reload",
                "input {input} must resolve to the reload endpoint"
            );
        }
    }

    #[test]
    fn endpoint_keeps_a_mount_prefix() {
        assert_eq!(
            reload_endpoint("https://proxy.example.com/mcp-proxy"),
            "https://proxy.example.com/mcp-proxy/reload"
        );
    }

    fn cached(hash: &str) -> BackendToolCache {
        BackendToolCache {
            config_hash: hash.to_string(),
            tools: Vec::new(),
            cached_at: "2026-10-09T00:00:00-03:00".to_string(),
        }
    }

    /// The orphan case: nothing else in the codebase can reclaim it.
    #[test]
    fn a_backend_that_left_the_config_is_stale() {
        assert!(is_stale(None, Some(&cached("abc"))));
        assert!(is_stale(None, None));
    }

    #[test]
    fn a_changed_config_hash_is_stale() {
        assert!(is_stale(Some(&"new".to_string()), Some(&cached("old"))));
    }

    #[test]
    fn a_matching_hash_is_kept() {
        assert!(!is_stale(Some(&"same".to_string()), Some(&cached("same"))));
    }

    /// Evicting a backend that has no cache entry would delete nothing and
    /// report a lie in the summary.
    #[test]
    fn a_configured_backend_without_cache_is_not_stale() {
        assert!(!is_stale(Some(&"abc".to_string()), None));
    }

    fn report_with(instances: Vec<InstanceReport>, remote: Option<RemoteReport>) -> ReloadReport {
        ReloadReport {
            config_path: "/tmp/servers.json".to_string(),
            servers: 2,
            name_conflicts: Vec::new(),
            caches: CacheReport::default(),
            completions: Vec::new(),
            instances,
            remote,
        }
    }

    /// Refreshing caches and completions with no proxy running is a success:
    /// the next `serve` reads the new config on its own.
    #[test]
    fn no_running_instance_is_not_a_failure() {
        assert!(report_with(Vec::new(), None).first_failure().is_none());
    }

    #[test]
    fn a_signalled_instance_is_not_a_failure() {
        let report = report_with(
            vec![InstanceReport {
                pid: 1932,
                target: "http 127.0.0.1:7332".to_string(),
                filter: None,
                reloaded: true,
                error: None,
            }],
            None,
        );
        assert!(report.first_failure().is_none());
    }

    #[test]
    fn a_failed_instance_is_reported() {
        let report = report_with(
            vec![InstanceReport {
                pid: 1932,
                target: "http 127.0.0.1:7332".to_string(),
                filter: None,
                reloaded: false,
                error: Some("no longer running".to_string()),
            }],
            None,
        );
        let failure = report.first_failure().expect("must fail");
        assert!(failure.contains("1932"), "{failure}");
        assert!(failure.contains("no longer running"), "{failure}");
    }

    #[test]
    fn a_full_catalog_instance_has_no_filter_to_show() {
        assert!(describe_filter(&instances::InstanceFilter::default()).is_none());
    }

    #[test]
    fn a_filter_is_rendered_as_the_flags_that_made_it() {
        let only = instances::InstanceFilter {
            only: Some("roam,grafana".to_string()),
            exclude: None,
        };
        assert_eq!(describe_filter(&only).unwrap(), "only=roam,grafana");

        let exclude = instances::InstanceFilter {
            only: None,
            exclude: Some("ai-memory".to_string()),
        };
        assert_eq!(describe_filter(&exclude).unwrap(), "exclude=ai-memory");

        let both = instances::InstanceFilter {
            only: Some("a,b".to_string()),
            exclude: Some("b".to_string()),
        };
        assert_eq!(describe_filter(&both).unwrap(), "only=a,b exclude=b");
    }

    #[test]
    fn a_remote_error_is_reported() {
        let report = report_with(
            Vec::new(),
            Some(RemoteReport {
                url: "http://x/reload".to_string(),
                authenticated: true,
                status: None,
                body: None,
                error: Some("connection refused".to_string()),
            }),
        );
        assert!(report
            .first_failure()
            .is_some_and(|f| f.contains("connection refused")));
    }

    /// A 403 from the proxy means the reload did not happen, so the command
    /// must not exit 0 and let a script believe it did.
    #[test]
    fn a_non_2xx_remote_status_is_reported() {
        let report = report_with(
            Vec::new(),
            Some(RemoteReport {
                url: "http://x/reload".to_string(),
                authenticated: true,
                status: Some(403),
                body: None,
                error: None,
            }),
        );
        assert!(report.first_failure().is_some_and(|f| f.contains("403")));
    }

    #[test]
    fn a_2xx_remote_status_is_not_a_failure() {
        for status in [200, 204, 299] {
            let report = report_with(
                Vec::new(),
                Some(RemoteReport {
                    url: "http://x/reload".to_string(),
                    authenticated: true,
                    status: Some(status),
                    body: None,
                    error: None,
                }),
            );
            assert!(
                report.first_failure().is_none(),
                "HTTP {status} must count as reloaded"
            );
        }
    }

    fn remote_status(status: u16, authenticated: bool) -> ReloadReport {
        report_with(
            Vec::new(),
            Some(RemoteReport {
                url: "http://x/reload".to_string(),
                authenticated,
                status: Some(status),
                body: None,
                error: None,
            }),
        )
    }

    /// Each rejection has exactly one cause an operator can act on, and
    /// guessing between them is the slow part of fixing a reload.
    #[test]
    fn auth_rejections_name_what_to_fix() {
        let cases = [
            (401, false, ADMIN_TOKEN_ENV),
            (401, true, "token was rejected"),
            (403, true, "adminRoles"),
            (404, true, "reload is disabled"),
        ];
        for (status, authenticated, expected) in cases {
            let failure = remote_status(status, authenticated)
                .first_failure()
                .unwrap_or_else(|| panic!("HTTP {status} must fail"));
            assert!(
                failure.contains(expected),
                "HTTP {status} (authenticated={authenticated}) should mention {expected:?}, got {failure:?}"
            );
        }
    }

    #[test]
    fn https_is_always_allowed() {
        assert!(check_remote_url("https://proxy.example.com", true, false).is_ok());
    }

    /// This is how the local proxies are reached, and the request never
    /// leaves the machine.
    #[test]
    fn plaintext_http_to_loopback_is_allowed_with_a_token() {
        for url in [
            "http://127.0.0.1:7332",
            "http://localhost:7332",
            "http://[::1]:7332",
        ] {
            assert!(
                check_remote_url(url, true, false).is_ok(),
                "{url} is loopback and must be allowed"
            );
        }
    }

    /// The admin token fronts every configured backend. Leaking it in the
    /// clear is worse than a failed reload.
    #[test]
    fn plaintext_http_to_a_remote_host_refuses_to_send_the_token() {
        let err = check_remote_url("http://proxy.example.com", true, false).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains(ADMIN_TOKEN_ENV), "{message}");
        assert!(message.contains("--insecure"), "{message}");
    }

    #[test]
    fn insecure_accepts_the_risk_explicitly() {
        assert!(check_remote_url("http://proxy.example.com", true, true).is_ok());
    }

    /// With no token there is no secret to leak, so the reload is allowed to
    /// go out over plain HTTP and be rejected by the proxy on its own terms.
    #[test]
    fn plaintext_http_without_a_token_is_allowed() {
        assert!(check_remote_url("http://proxy.example.com", false, false).is_ok());
    }

    #[test]
    fn other_schemes_and_malformed_urls_are_rejected() {
        assert!(check_remote_url("ftp://proxy.example.com", false, false).is_err());
        assert!(check_remote_url("not a url", false, false).is_err());
    }

    #[test]
    fn remote_summary_reads_as_a_diff() {
        let body = serde_json::json!({
            "reloaded": true,
            "added": ["novo"],
            "changed": ["roam", "grafana"],
            "removed": [],
            "tools": 148,
            "requires_restart": [],
        });
        assert_eq!(summarize_remote(&body), "+1 ~2 -0, 148 tools");
    }

    #[test]
    fn remote_summary_flags_pending_restarts() {
        let body = serde_json::json!({
            "added": [], "changed": [], "removed": [],
            "requires_restart": ["audit.output"],
        });
        assert_eq!(
            summarize_remote(&body),
            "+0 ~0 -0, 1 change(s) need a restart"
        );
    }

    #[test]
    fn remote_summary_tolerates_a_body_it_does_not_recognize() {
        assert_eq!(summarize_remote(&serde_json::json!({})), "+0 ~0 -0");
        assert_eq!(summarize_remote(&serde_json::json!(null)), "+0 ~0 -0");
    }
}
