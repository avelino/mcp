//! End-to-end coverage of `POST /reload` and of [`reload_in_place`].
//!
//! Reload is a write surface on a running proxy, so the gate is tested the way
//! the project tests every auth change: bypass, escalation and
//! backwards-compat, not just the happy path. Every status assertion here goes
//! over a real socket through [`super::http::test_router`] — the same handlers
//! `run_http` mounts — because the ordering that matters (a 404 answered
//! *before* a credential is demanded) only exists in the handler, not in the
//! gate function the `server_auth` unit tests already cover.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, OnceLock};

use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::audit::{AuditLogger, AuditOutput};
use crate::cache::ToolCacheStore;
use crate::config::{self, Config};
use crate::instances::InstanceFilter;
use crate::server_auth::build_auth_provider;

use super::http::test_router;
use super::proxy::{ProxyServer, SharedProxy};
use super::reload::{reload_in_place, AuthSnapshot, BootInvariants, ReloadContext, SharedAuth};

const ADMIN: &str = "Bearer tok-admin";
const DEV: &str = "Bearer tok-dev";

// --- harness -----------------------------------------------------------

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| StdMutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Points `load_config()` at a config this test owns, and restores the
/// environment on drop.
///
/// Serialized through one mutex because both variables are process-wide:
/// `load_config` reads `MCP_SERVERS_CONFIG`, and the classifier cache a reload
/// rewrites lives under `MCP_CONFIG_DIR`. Two reload tests running at once
/// would reload each other's config and scribble on the developer's real
/// cache file.
struct ConfigEnv {
    _dir: tempfile::TempDir,
    previous_config: Option<String>,
    previous_dir: Option<String>,
    _guard: MutexGuard<'static, ()>,
}

impl ConfigEnv {
    fn new(config: Value) -> Self {
        let guard = env_lock();
        let previous_config = std::env::var("MCP_SERVERS_CONFIG").ok();
        let previous_dir = std::env::var("MCP_CONFIG_DIR").ok();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("MCP_CONFIG_DIR", dir.path());
        std::env::set_var("MCP_SERVERS_CONFIG", config.to_string());
        Self {
            _dir: dir,
            previous_config,
            previous_dir,
            _guard: guard,
        }
    }

    /// Replace what the next `load_config()` will read — the test's stand-in
    /// for an operator editing `servers.json`.
    fn write(&self, config: Value) {
        std::env::set_var("MCP_SERVERS_CONFIG", config.to_string());
    }

    fn load(&self) -> Config {
        config::load_config().unwrap()
    }
}

impl Drop for ConfigEnv {
    fn drop(&mut self) {
        let restore = |key: &str, value: &Option<String>| match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        };
        restore("MCP_SERVERS_CONFIG", &self.previous_config);
        restore("MCP_CONFIG_DIR", &self.previous_dir);
    }
}

/// A `serverAuth` block with two bearer tokens: `alice` holds the admin role,
/// `bob` does not.
fn bearer_auth(admin_roles: &[&str]) -> Value {
    json!({
        "providers": ["bearer"],
        "bearer": {
            "tokens": {
                "tok-admin": {"subject": "alice", "roles": ["admin"]},
                "tok-dev": {"subject": "bob", "roles": ["dev"]},
            }
        },
        "adminRoles": admin_roles,
    })
}

/// A config whose only backend is unreachable on purpose: discovery fails at
/// spawn instead of waiting on a child that will never speak MCP.
fn config_with(servers: &[&str], server_auth: Value) -> Value {
    let servers: serde_json::Map<String, Value> = servers
        .iter()
        .map(|name| {
            (
                (*name).to_string(),
                json!({"command": "mcp-reload-test-no-such-binary"}),
            )
        })
        .collect();
    json!({"mcpServers": servers, "serverAuth": server_auth})
}

fn empty_proxy() -> SharedProxy {
    let pool = Arc::new(crate::db::DbPool::disabled());
    Arc::new(Mutex::new(ProxyServer::new(
        Arc::new(AuditLogger::Disabled),
        HashMap::new(),
        HashMap::new(),
        ToolCacheStore::new(pool),
    )))
}

/// The real router, serving an empty proxy with `config`'s auth block and the
/// boot invariants `run_http` would have captured from the same config.
struct Endpoint {
    base: String,
    auth: SharedAuth,
    proxy: SharedProxy,
    reload: ReloadContext,
    /// Held so the router's shutdown receiver never sees the channel close.
    _shutdown: tokio::sync::watch::Sender<bool>,
}

impl Endpoint {
    async fn start(config: &Config, filter: InstanceFilter) -> Self {
        let provider = build_auth_provider(&config.server_auth, None).unwrap();
        let auth = AuthSnapshot::new(
            provider,
            config.server_auth.acl.clone(),
            config.server_auth.admin_roles.clone(),
        )
        .shared();
        let reload = ReloadContext {
            filter: Arc::new(filter),
            boot: Arc::new(BootInvariants {
                oauth_as_enabled: config.server_auth.providers.iter().any(|p| p == "oauth_as"),
                audit_output: config.audit.output.clone(),
                bind_addr: Some("127.0.0.1:0".to_string()),
            }),
            as_state: None,
        };
        let proxy = empty_proxy();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let app = test_router(proxy.clone(), auth.clone(), reload.clone(), rx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        Self {
            base: format!("http://{addr}"),
            auth,
            proxy,
            reload,
            _shutdown: tx,
        }
    }

    async fn post(&self, path: &str, authorization: Option<&str>, body: Value) -> (u16, Value) {
        let mut req = reqwest::Client::new()
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json");
        if let Some(value) = authorization {
            req = req.header("authorization", value);
        }
        let resp = req.json(&body).send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn reload(&self, authorization: Option<&str>) -> (u16, Value) {
        self.post("/reload", authorization, json!({})).await
    }

    /// A `/mcp` call that only needs to prove authentication, not routing.
    async fn tools_list(&self, authorization: Option<&str>) -> u16 {
        self.post(
            "/mcp",
            authorization,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await
        .0
    }

    /// Call `reload_in_place` directly, on the same state the router serves.
    async fn reload_in_place(&self) -> anyhow::Result<super::reload::ReloadOutcome> {
        reload_in_place(
            &self.proxy,
            &self.auth,
            &self.reload.filter,
            &self.reload.boot,
            self.reload.as_state.as_ref(),
        )
        .await
    }

    async fn published(&self) -> Vec<String> {
        let mut names: Vec<String> = self.proxy.lock().await.configs.keys().cloned().collect();
        names.sort();
        names
    }
}

fn names(body: &Value, field: &str) -> Vec<String> {
    body[field]
        .as_array()
        .unwrap_or_else(|| panic!("response has no {field} array: {body}"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

// --- gate --------------------------------------------------------------

/// An operator who never set `adminRoles` gets no write surface *and* no hint
/// that one exists: the answer has to be the router's own 404, byte for byte,
/// and it has to come without a credential being demanded first.
#[tokio::test]
async fn reload_is_not_routed_without_admin_roles() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&[])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    let unrouted = endpoint.post("/no-such-route", None, json!({})).await;
    for authorization in [None, Some(ADMIN)] {
        assert_eq!(
            endpoint.reload(authorization).await,
            unrouted,
            "a disabled /reload must be indistinguishable from an unrouted path"
        );
    }
}

#[tokio::test]
async fn reload_without_credentials_is_unauthorized() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    let (status, _) = endpoint.reload(None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn reload_with_an_unknown_token_is_unauthorized() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    let (status, _) = endpoint.reload(Some("Bearer tok-nope")).await;
    assert_eq!(status, 401);
}

/// Authenticated is not administrative.
#[tokio::test]
async fn reload_without_an_admin_role_is_forbidden() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    let (status, _) = endpoint.reload(Some(DEV)).await;
    assert_eq!(status, 403);
}

/// Escalation: `bob` is allowed every tool on the proxy, which is a long way
/// from being allowed to replace the config every other client is served
/// from. Only `adminRoles` grants that.
#[tokio::test]
async fn an_acl_tool_grant_does_not_imply_reload() {
    let mut server_auth = bearer_auth(&["admin"]);
    server_auth["acl"] = json!({
        "default": "deny",
        "rules": [{"roles": ["dev"], "tools": ["*"], "policy": "allow"}],
    });
    let env = ConfigEnv::new(config_with(&[], server_auth));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    assert_eq!(
        endpoint.tools_list(Some(DEV)).await,
        200,
        "the tool grant has to be real for the escalation to be meaningful"
    );
    let (status, _) = endpoint.reload(Some(DEV)).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn reload_with_an_admin_role_returns_the_diff() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    env.write(config_with(&["roam"], bearer_auth(&["admin"])));
    let (status, body) = endpoint.reload(Some(ADMIN)).await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["reloaded"], json!(true));
    assert_eq!(names(&body, "added"), vec!["roam".to_string()]);
    assert!(names(&body, "changed").is_empty());
    assert!(names(&body, "removed").is_empty());
    assert!(names(&body, "requires_restart").is_empty());
    assert!(body["tools"].is_u64(), "tools must be a count: {body}");
    assert_eq!(endpoint.published().await, vec!["roam".to_string()]);
}

// --- atomic rejection --------------------------------------------------

/// The one test the whole ordering exists for. A `serverAuth` that cannot
/// build has to leave the previous snapshot *exactly* in place: the token that
/// authenticated before the attempt still authenticates after it, and the one
/// that was rejected is still rejected.
///
/// The failure this guards against is not a 500 — it is a proxy that drops to
/// `NoAuth` because the new provider never got built but the old one was
/// already gone.
#[tokio::test]
async fn a_broken_server_auth_leaves_the_previous_one_in_force() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;
    assert_eq!(endpoint.tools_list(Some(ADMIN)).await, 200);

    // `providers: ["bearer"]` with no `bearer` block: this is exactly the
    // shape `build_auth_provider` refuses rather than silently weakening.
    env.write(config_with(
        &["roam"],
        json!({"providers": ["bearer"], "adminRoles": ["admin"]}),
    ));

    let (status, body) = endpoint.reload(Some(ADMIN)).await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(body["reloaded"], json!(false));

    assert_eq!(
        endpoint.tools_list(Some(ADMIN)).await,
        200,
        "the token that worked before the rejected reload must still work"
    );
    assert_eq!(
        endpoint.tools_list(Some("Bearer tok-nope")).await,
        401,
        "a rejected reload must not have dropped the proxy to NoAuth"
    );
    assert_eq!(
        endpoint.tools_list(None).await,
        401,
        "nor opened it to callers with no credentials at all"
    );
    assert_eq!(
        *AuthSnapshot::read(&endpoint.auth).admin_roles,
        vec!["admin".to_string()],
        "the admin roles are part of the same snapshot and must not have moved"
    );
    assert!(
        endpoint.published().await.is_empty(),
        "the backend change travelled in the same rejected config and must not have landed"
    );
}

// --- boot invariants ---------------------------------------------------

/// `audit.output` opens a db pool and a logger at boot, so a reload cannot
/// apply it. It is reported, and everything else in the same config still
/// lands — reporting is not refusing.
#[tokio::test]
async fn a_changed_audit_output_is_reported_and_the_rest_still_applies() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    let mut next = config_with(&["roam"], bearer_auth(&["admin"]));
    next["audit"] = json!({"output": "stderr"});
    env.write(next);

    let (status, body) = endpoint.reload(Some(ADMIN)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        names(&body, "requires_restart"),
        vec!["audit.output".to_string()]
    );
    assert_eq!(
        names(&body, "added"),
        vec!["roam".to_string()],
        "the applicable half of the config still has to be applied"
    );
}

/// Turning `oauth_as` on needs the sub-router mounted, which happens at boot.
/// The rest of the chain is applied unchanged and the change is reported —
/// the alternative, failing the build for want of an AS state this process
/// never loaded, would throw away the backend changes too.
#[tokio::test]
async fn turning_oauth_as_on_is_reported_and_bearer_keeps_working() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    let mut server_auth = bearer_auth(&["admin"]);
    server_auth["providers"] = json!(["bearer", "oauth_as"]);
    env.write(config_with(&[], server_auth));

    let (status, body) = endpoint.reload(Some(ADMIN)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        names(&body, "requires_restart"),
        vec!["serverAuth.providers.oauth_as".to_string()]
    );
    assert_eq!(
        endpoint.tools_list(Some(ADMIN)).await,
        200,
        "the bearer half of the chain must survive the reload"
    );
    assert_eq!(endpoint.tools_list(Some("Bearer tok-nope")).await, 401);
}

/// An `audit.output` the operator spelled out but did not change is not a
/// change. Without the raw-value comparison every reload of such a config
/// would claim a restart was needed.
#[tokio::test]
async fn an_unchanged_audit_output_is_not_reported() {
    let mut first = config_with(&[], bearer_auth(&["admin"]));
    first["audit"] = json!({"output": "stderr"});
    let env = ConfigEnv::new(first.clone());
    let config = env.load();
    assert_eq!(config.audit.output, Some(AuditOutput::Stderr));
    let endpoint = Endpoint::start(&config, InstanceFilter::default()).await;

    let (status, body) = endpoint.reload(Some(ADMIN)).await;
    assert_eq!(status, 200, "{body}");
    assert!(names(&body, "requires_restart").is_empty());
}

// --- filter preservation -----------------------------------------------

/// An instance started with `--exclude a,b` must never publish `a` or `b`,
/// however the file on disk changes. The reload re-applies the filter rather
/// than trusting the config to still agree with it.
#[tokio::test]
async fn a_reload_does_not_widen_an_excluded_catalog() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let filter = InstanceFilter {
        only: None,
        exclude: Some("a,b".to_string()),
    };
    let endpoint = Endpoint::start(&env.load(), filter).await;

    env.write(config_with(&["a", "b", "c"], bearer_auth(&["admin"])));
    let outcome = endpoint.reload_in_place().await.unwrap();

    assert_eq!(outcome.added, vec!["c".to_string()]);
    assert_eq!(
        endpoint.published().await,
        vec!["c".to_string()],
        "a and b are in the config on disk and must still not be published"
    );
}

/// The same promise for `--only`: a config that grew does not widen the
/// catalog.
#[tokio::test]
async fn a_reload_honors_only() {
    let env = ConfigEnv::new(config_with(&[], bearer_auth(&["admin"])));
    let filter = InstanceFilter {
        only: Some("roam".to_string()),
        exclude: None,
    };
    let endpoint = Endpoint::start(&env.load(), filter).await;

    env.write(config_with(&["roam", "grafana"], bearer_auth(&["admin"])));
    endpoint.reload_in_place().await.unwrap();

    assert_eq!(endpoint.published().await, vec!["roam".to_string()]);
}

// --- backwards compatibility -------------------------------------------

/// A config that predates `adminRoles` deserializes, serves `/mcp` exactly as
/// it did, and exposes no reload surface at all.
#[tokio::test]
async fn a_config_without_admin_roles_leaves_mcp_authenticating_as_before() {
    let env = ConfigEnv::new(json!({
        "mcpServers": {},
        "serverAuth": {
            "providers": ["bearer"],
            "bearer": {"tokens": {"tok-admin": "alice"}},
        },
    }));
    let config = env.load();
    assert!(
        config.server_auth.admin_roles.is_empty(),
        "an absent adminRoles key must deserialize to no roles"
    );
    let endpoint = Endpoint::start(&config, InstanceFilter::default()).await;

    assert_eq!(endpoint.tools_list(Some(ADMIN)).await, 200);
    assert_eq!(endpoint.tools_list(Some("Bearer tok-nope")).await, 401);
    assert_eq!(endpoint.tools_list(None).await, 401);
    assert_eq!(endpoint.reload(Some(ADMIN)).await.0, 404);
}

/// A reload of an unchanged config is a no-op that still succeeds: the
/// operator who ran `mcp reload` after editing nothing gets an empty diff, not
/// an error.
#[tokio::test]
async fn reloading_the_same_config_twice_is_an_empty_diff() {
    let env = ConfigEnv::new(config_with(&["roam"], bearer_auth(&["admin"])));
    let endpoint = Endpoint::start(&env.load(), InstanceFilter::default()).await;

    let first = endpoint.reload_in_place().await.unwrap();
    assert_eq!(first.added, vec!["roam".to_string()]);

    let second = endpoint.reload_in_place().await.unwrap();
    assert!(second.added.is_empty());
    assert!(second.changed.is_empty());
    assert!(second.removed.is_empty());
}
