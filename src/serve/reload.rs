//! In-place config reload for a running `mcp serve`.
//!
//! The only alternative to this module is a restart, and a restart costs every
//! stdio backend child and every open session. So a reload re-reads the config
//! from disk, validates it whole, and swaps what can be swapped — leaving the
//! backends nobody edited running exactly as they were.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::audit::AuditOutput;
use crate::config::{self, Config};
use crate::instances::InstanceFilter;
use crate::server_auth::oauth_as::AsState;
use crate::server_auth::{self, AclConfig, AuthProvider, ServerAuthConfig};

use super::discovery::discover_pending_backends;
use super::proxy::{shutdown_clients_in_parallel, SharedProxy};

/// The authentication state every request reads, swapped as one value.
///
/// Provider, ACL and admin roles travel together because they are *decided*
/// together. Published one at a time there is a window where a subject
/// authenticated by the new provider is matched against rules written for the
/// previous one — which is to say a window where the proxy enforces a policy
/// no operator ever wrote.
#[derive(Clone)]
pub(crate) struct AuthSnapshot {
    pub(crate) provider: Arc<dyn AuthProvider>,
    pub(crate) acl: Arc<Option<AclConfig>>,
    /// Roles allowed to reload. Lives in the snapshot rather than being
    /// captured at boot, or editing `adminRoles` would need the restart this
    /// whole feature exists to avoid.
    pub(crate) admin_roles: Arc<Vec<String>>,
}

pub(crate) type SharedAuth = Arc<std::sync::RwLock<AuthSnapshot>>;

impl AuthSnapshot {
    pub(crate) fn new(
        provider: Arc<dyn AuthProvider>,
        acl: Option<AclConfig>,
        admin_roles: Vec<String>,
    ) -> Self {
        Self {
            provider,
            acl: Arc::new(acl),
            admin_roles: Arc::new(admin_roles),
        }
    }

    pub(crate) fn shared(self) -> SharedAuth {
        Arc::new(std::sync::RwLock::new(self))
    }

    /// Clone the current snapshot out of the lock.
    ///
    /// Owned, with the guard already dropped, because a `std::sync::RwLock`
    /// guard held across an `.await` makes the surrounding future non-`Send`
    /// and axum refuses such a handler. Cloning three `Arc`s is the entire
    /// cost of never holding it.
    ///
    /// A poisoned lock recovers rather than panics. The snapshot is swapped
    /// whole, in one write, so there is no half-written state to protect
    /// against, and panicking here would take down the authentication path
    /// for every subsequent request instead of one.
    pub(crate) fn read(auth: &SharedAuth) -> Self {
        auth.read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// What this process baked in before it started serving, and therefore cannot
/// change without starting again.
#[derive(Debug, Default, Clone)]
pub(crate) struct BootInvariants {
    /// Whether the OAuth AS sub-router was mounted. The router is built once,
    /// around the listener.
    pub(crate) oauth_as_enabled: bool,
    /// `audit.output` exactly as it was read from disk, *before*
    /// `resolve_for_serve` filled in the serve-mode default. The raw value is
    /// what the new config can be compared against; the resolved one would
    /// report a change every time an operator spelled out the default.
    pub(crate) audit_output: Option<AuditOutput>,
    /// Address this instance listens on, `None` for stdio.
    ///
    /// Nothing in the config file can change it — it comes from `--http` — so
    /// it never lands in `requires_restart`. It is captured because a reload
    /// has to say *which* instance reloaded: several proxies run on one
    /// machine, and "config reloaded" with no address does not identify one.
    pub(crate) bind_addr: Option<String>,
}

/// Everything a reload needs that is fixed for the process's life.
///
/// Grouped so `POST /reload` and the SIGHUP task carry one value instead of
/// three, and so adding to it later does not rewrite every call site.
#[derive(Default, Clone)]
pub(crate) struct ReloadContext {
    pub(crate) filter: Arc<InstanceFilter>,
    pub(crate) boot: Arc<BootInvariants>,
    pub(crate) as_state: Option<Arc<AsState>>,
}

/// What a reload did, as reported to the operator who asked for it.
pub(crate) struct ReloadOutcome {
    pub(crate) added: Vec<String>,
    pub(crate) changed: Vec<String>,
    pub(crate) removed: Vec<String>,
    pub(crate) tools: usize,
    /// Changes that were parsed and accepted but could not be applied in
    /// place. Reported rather than silently dropped: an operator who edited
    /// `audit.output` and got a plain "reloaded" would believe it took.
    pub(crate) requires_restart: Vec<String>,
}

/// The `serverAuth` block this process can actually build a provider from.
///
/// `oauth_as` is the one provider a reload cannot turn on: its sub-router and
/// its on-disk client store are wired before the listener exists, so this
/// process has no AS state to hand the JWT validator. Building the chain with
/// it would just fail and take the whole reload with it — including the
/// backend changes that *are* applicable. Dropping it leaves the chain
/// behaving exactly as it did before the attempt, and the change is reported
/// in `requires_restart`.
///
/// Unless it was the only provider: `build_auth_provider` reads an empty
/// `providers` list as `NoAuth`, so stripping it there would turn a reload
/// into the thing that opened the proxy. That is refused outright.
fn applicable_server_auth(
    mut config: ServerAuthConfig,
    as_state: Option<&Arc<AsState>>,
) -> Result<ServerAuthConfig> {
    if as_state.is_some() || !config.providers.iter().any(|p| p == "oauth_as") {
        return Ok(config);
    }
    config.providers.retain(|p| p != "oauth_as");
    if config.providers.is_empty() {
        anyhow::bail!(
            "serverAuth.providers is ['oauth_as'], which this instance did not start with: \
             applying it needs a restart, and applying the rest would leave no provider at all"
        );
    }
    Ok(config)
}

/// Changes the new config asks for that only a restart can deliver.
fn restart_required_by(boot: &BootInvariants, config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let oauth_as_now = config.server_auth.providers.iter().any(|p| p == "oauth_as");
    if oauth_as_now != boot.oauth_as_enabled {
        out.push("serverAuth.providers.oauth_as".to_string());
    }
    if config.audit.output != boot.audit_output {
        out.push("audit.output".to_string());
    }
    out
}

/// Re-read the config from disk, validate it whole, and apply it to a running
/// proxy.
///
/// Returns `Err` having mutated nothing when the new config does not parse or
/// its `serverAuth` does not build. That is the property the whole function is
/// arranged around: a broken auth block has to become a rejected reload, never
/// a proxy left serving with auth half-applied.
///
/// `as_state` is reused, never reloaded. It is the same on-disk source either
/// way, and the background GC task holds a clone of the `Arc`.
pub(crate) async fn reload_in_place(
    proxy: &SharedProxy,
    auth: &SharedAuth,
    filter: &InstanceFilter,
    boot: &BootInvariants,
    as_state: Option<&Arc<AsState>>,
) -> Result<ReloadOutcome> {
    // --- validate; nothing below this block has mutated anything ----------
    let mut config = config::load_config().context("failed to re-read config")?;

    // The filter this instance started with, re-applied. A reload must never
    // widen the catalog a proxy publishes.
    for name in config::filter_servers(
        &mut config,
        filter.only.as_deref(),
        filter.exclude.as_deref(),
    ) {
        tracing::warn!(server = %name, "unknown server in this instance's filter — ignored");
    }

    // Reserved names only warn at boot, so they only warn here: a reload that
    // rejected a config `mcp serve` would have started with would be a second,
    // stricter schema nobody documented.
    for name in config::validate_server_names(&config) {
        tracing::warn!(server = %name, "server name is reserved by the proxy");
    }

    let auth_config = applicable_server_auth(config.server_auth.clone(), as_state)?;
    let provider = server_auth::build_auth_provider(&auth_config, as_state)
        .context("new serverAuth is invalid — the previous one is still in force")?;

    let requires_restart = restart_required_by(boot, &config);

    // --- apply ------------------------------------------------------------
    // The clients come back for the caller to close because `shutdown()`
    // waits on a child's exit, and waiting for that under the proxy lock
    // stalls every in-flight request.
    let (diff, retired, cache_store) = {
        let mut p = proxy.lock().await;
        let (diff, retired) = p.apply_config(config.servers, config.config_hashes);
        (diff, retired, p.cache_store.clone())
    };
    shutdown_clients_in_parallel(retired).await;

    // Both derived caches are keyed by the config that produced them, so a
    // backend that changed or left has to be forgotten on disk too, or the
    // next boot serves a tool list for a config nobody runs any more. Both
    // touch disk, which is why the tool cache is evicted with the lock
    // released.
    for name in diff.changed.iter().chain(diff.removed.iter()) {
        cache_store.delete_backend(name);
    }
    if !diff.changed.is_empty() || !diff.removed.is_empty() {
        let mut p = proxy.lock().await;
        for name in diff.changed.iter().chain(diff.removed.iter()) {
            p.classifier_cache.forget_server(name);
        }
        p.classifier_cache.save();
    }

    // One write, so no request can observe the new provider against the old
    // ACL. See [`AuthSnapshot`].
    *auth
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = AuthSnapshot::new(
        provider,
        config.server_auth.acl.clone(),
        config.server_auth.admin_roles.clone(),
    );

    discover_pending_backends(proxy).await;

    let tools = proxy.lock().await.tools.len();
    let instance = boot.bind_addr.as_deref().unwrap_or("stdio");
    if diff.is_empty() {
        // Said out loud, because it is the answer to a question the operator
        // is about to ask: someone who just edited `servers.json` and reads
        // "no backend changes" learns the edit did not land where they think.
        tracing::info!(instance, tools, "config reloaded — no backend changes");
    } else {
        tracing::info!(
            instance,
            added = diff.added.len(),
            changed = diff.changed.len(),
            removed = diff.removed.len(),
            tools,
            "config reloaded"
        );
    }
    if !requires_restart.is_empty() {
        tracing::warn!(
            fields = requires_restart.join(", "),
            "applied everything else; these were parsed but need a restart to take effect"
        );
    }

    Ok(ReloadOutcome {
        added: diff.added,
        changed: diff.changed,
        removed: diff.removed,
        tools,
        requires_restart,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_auth::NoAuth;

    fn server_auth(providers: &[&str]) -> ServerAuthConfig {
        ServerAuthConfig {
            providers: providers.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
    }

    fn config_with_audit(output: Option<AuditOutput>) -> Config {
        Config {
            servers: Default::default(),
            server_auth: ServerAuthConfig::default(),
            audit: crate::audit::AuditConfig {
                output,
                ..Default::default()
            },
            path: std::path::PathBuf::from("<test>"),
            config_hashes: Default::default(),
        }
    }

    #[test]
    fn audit_output_change_requires_a_restart() {
        let boot = BootInvariants {
            audit_output: None,
            ..Default::default()
        };
        let config = config_with_audit(Some(AuditOutput::Stderr));
        assert_eq!(
            restart_required_by(&boot, &config),
            vec!["audit.output".to_string()]
        );
    }

    #[test]
    fn an_unchanged_audit_output_requires_nothing() {
        let boot = BootInvariants {
            audit_output: Some(AuditOutput::File),
            ..Default::default()
        };
        let config = config_with_audit(Some(AuditOutput::File));
        assert!(restart_required_by(&boot, &config).is_empty());
    }

    #[test]
    fn toggling_oauth_as_either_way_requires_a_restart() {
        let mut config = config_with_audit(None);
        config.server_auth = server_auth(&["bearer", "oauth_as"]);
        assert_eq!(
            restart_required_by(&BootInvariants::default(), &config),
            vec!["serverAuth.providers.oauth_as".to_string()],
            "turning it on needs the sub-router mounted"
        );

        config.server_auth = server_auth(&["bearer"]);
        let boot = BootInvariants {
            oauth_as_enabled: true,
            ..Default::default()
        };
        assert_eq!(
            restart_required_by(&boot, &config),
            vec!["serverAuth.providers.oauth_as".to_string()],
            "turning it off leaves the sub-router mounted"
        );
    }

    /// Without the boot-time AS state there is nothing to validate JWTs
    /// against, so the provider is built without `oauth_as` instead of failing
    /// the whole reload.
    #[test]
    fn oauth_as_is_dropped_when_this_process_has_no_as_state() {
        let applied = applicable_server_auth(server_auth(&["bearer", "oauth_as"]), None).unwrap();
        assert_eq!(applied.providers, vec!["bearer".to_string()]);
    }

    #[test]
    fn oauth_as_as_the_only_provider_is_refused_rather_than_stripped() {
        let err = applicable_server_auth(server_auth(&["oauth_as"]), None).unwrap_err();
        assert!(
            err.to_string().contains("no provider at all"),
            "stripping the only provider would boot as NoAuth: {err}"
        );
    }

    #[test]
    fn a_snapshot_read_hands_back_the_values_it_was_built_with() {
        let auth = AuthSnapshot::new(Arc::new(NoAuth), None, vec!["admin".to_string()]).shared();
        let snapshot = AuthSnapshot::read(&auth);
        assert_eq!(*snapshot.admin_roles, vec!["admin".to_string()]);
        assert!(snapshot.acl.is_none());
    }
}
