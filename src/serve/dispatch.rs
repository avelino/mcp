use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::audit::{AuditEntry, AuditLogger};
use crate::client::McpClient;
use crate::protocol::{error_codes, meta_keys, CacheScope, JsonRpcRequest, JsonRpcResponse};
use crate::server_auth::{self, AclConfig, AuthIdentity};

use super::discovery::{connect_backend, discover_pending_backends, discover_single_backend};
use super::proxy::{
    backend_prompt_get_params, backend_resource_read_params, handle_server_discover,
    infer_backend_name, mrtr_continuation_fields, proxy_server_info, ResolvedCall,
    ResolvedPromptGet, ResolvedResourceRead, SharedProxy, SEPARATOR,
};

/// Whether to discover all pending backends, a single one, or none.
enum DiscoveryAction {
    None,
    Single(String),
    All,
}

/// `ttlMs` we advertise on the `*/list` results.
///
/// There is no existing TTL to inherit: `ToolCacheStore` invalidates on the
/// backend config hash, not on a clock. So this is a deliberately
/// conservative number — the idle reaper ticks every 30s, and a reaped
/// backend re-registers its primitives on the next reconnect, which is the
/// shortest window in which our registry can change with the client doing
/// nothing. A cached list therefore never outlives one reap/reconnect cycle.
const LIST_TTL_MS: u64 = 30_000;

/// `ttlMs` for `resources/read`. Resource bodies are opaque backend data we
/// relay verbatim and we get no freshness signal with them, so we tell
/// caches not to reuse the response at all.
const RESOURCE_READ_TTL_MS: u64 = 0;

/// `ttlMs` for `server/discover`, matching the spec page's own example.
///
/// Unlike the `*/list` results, the discover payload is built entirely from
/// compile-time constants (`SUPPORTED_PROTOCOL_VERSIONS`,
/// `proxy_capabilities()`, the crate version), so it can only change when the
/// process is replaced by a different build. An hour is safe.
const DISCOVER_TTL_MS: u64 = 3_600_000;

/// Whether a request body itself opts into the stateless (2026-07-28+)
/// revision, ignoring any transport headers.
///
/// Shared by the HTTP handler (which ORs in the `MCP-Protocol-Version`
/// header) and the stdio handler (which has no headers at all), so both
/// transports answer the question the same way.
///
/// `server/discover` counts on its own: the method did not exist before
/// 2026-07-28, so a peer calling it is a 2026-07-28 peer whether or not it
/// spelled the version out. Reading it as legacy would strip the very fields
/// — `resultType`, the cache hints — that the discovery result is required to
/// carry.
pub(crate) fn body_declares_stateless(req: &JsonRpcRequest) -> bool {
    req.method == "server/discover"
        || crate::protocol::request_protocol_version(req.params.as_ref()).is_some_and(|v| {
            crate::protocol::is_version_supported(v) && crate::protocol::is_stateless_version(v)
        })
}

/// Top-level non-blocking request dispatcher.
///
/// This function is the **only** path that should be called from per-request
/// HTTP handlers. It carefully scopes the proxy lock to short read/write
/// windows and **never** holds the lock across backend I/O — different
/// backends run fully in parallel, and many concurrent calls to the same
/// backend share the same `Arc<McpClient>` (whose transport multiplexes
/// internally where possible).
///
/// The `#[tracing::instrument]` here is the OTel root span for every
/// proxied request. Empty fields are filled in via `Span::record` once the
/// tool/server are resolved or once the response is built — using
/// `tracing::field::Empty` avoids any allocation when telemetry is off.
#[tracing::instrument(
    name = "mcp.request",
    skip_all,
    fields(
        otel.kind = "server",
        mcp.method = %req.method,
        mcp.transport = %source,
        mcp.identity = %identity.subject,
        mcp.server = tracing::field::Empty,
        mcp.tool = tracing::field::Empty,
        mcp.status = tracing::field::Empty,
    )
)]
pub(crate) async fn dispatch_request(
    proxy: &SharedProxy,
    req: JsonRpcRequest,
    identity: &AuthIdentity,
    acl: &Option<AclConfig>,
    source: &str,
    stateless_peer: bool,
) -> JsonRpcResponse {
    let start = std::time::Instant::now();
    let method = req.method.clone();
    let id = req.id.clone();

    // Audit metadata captured outside the lock.
    let audit_logger: Arc<AuditLogger>;
    let mut tool_name_for_audit: Option<String> = None;
    let mut server_name_for_audit: Option<String> = None;
    let mut decision_for_audit: Option<server_auth::Decision> = None;
    // An MRTR retry re-enters an exchange a previous call started. It is a
    // privileged call like any other, so the audit entry has to say so
    // rather than looking like a fresh, self-contained request.
    let mrtr_continuation_for_audit = mrtr_continuation_fields(req.params.as_ref());

    // 2026-07-28 lets every request declare its own revision in
    // `params._meta`, since there is no handshake left to hold it. Absent
    // means a pre-2026-07-28 peer — the legacy path, never an error.
    // Present-but-unknown is the only case we reject.
    if let Some(version) = crate::protocol::request_protocol_version(req.params.as_ref()) {
        if !crate::protocol::is_version_supported(version) {
            let audit = Arc::clone(&proxy.lock().await.audit);
            return finish_audit(
                AuditCtx {
                    audit,
                    source,
                    method,
                    tool_name: None,
                    server_name: None,
                    identity,
                    start,
                    decision: None,
                    mrtr_continuation: mrtr_continuation_for_audit,
                    stateless_peer,
                },
                // The spec requires the supported list on the wire: without
                // it a client can only fail, with it it can pick a revision
                // we both speak and retry.
                JsonRpcResponse::unsupported_protocol_version(id, version),
            );
        }
    }

    let response = match req.method.as_str() {
        "initialize" => {
            let requested = req
                .params
                .as_ref()
                .and_then(|v| v.get("protocolVersion"))
                .and_then(|v| v.as_str());
            let p = proxy.lock().await;
            audit_logger = Arc::clone(&p.audit);
            p.handle_initialize(id, requested)
        }
        // Stateless replacement for `initialize`. A MUST for servers in
        // 2026-07-28; legacy clients simply never call it.
        "server/discover" => {
            let p = proxy.lock().await;
            audit_logger = Arc::clone(&p.audit);
            let mut resp = handle_server_discover(id);
            if let Some(result) = resp.result.as_mut() {
                set_private_cache_hints(result, DISCOVER_TTL_MS, stateless_peer);
            }
            resp
        }
        "tools/list" => {
            // Decide whether to trigger discovery, then drop the proxy lock
            // before doing any I/O. Discovery is serialized via the separate
            // discovery_lock inside discover_pending_backends.
            audit_logger = discover_for_list(proxy).await;
            // Snapshot tools + metadata under a brief lock, then release
            // before ACL evaluation/serialization/logging.
            let (tools_snap, tool_map_snap, cls_snap, list_audit) = {
                let p = proxy.lock().await;
                (
                    p.tools.clone(),
                    p.tool_map.clone(),
                    p.classifications.clone(),
                    Arc::clone(&p.audit),
                )
            };
            let mut tools_allowed: Vec<Value> = Vec::new();
            for t in &tools_snap {
                let ctx =
                    tool_map_snap
                        .get(&t.name)
                        .map(|(server, orig)| server_auth::ToolContext {
                            server_alias: server.as_str(),
                            tool_name: orig.as_str(),
                            classification: cls_snap.get(&t.name),
                        });
                let decision = server_auth::is_tool_allowed(identity, &t.name, acl, ctx.as_ref());
                if decision.allowed {
                    tools_allowed.push(serde_json::to_value(t).unwrap());
                } else {
                    let srv = tool_map_snap.get(&t.name).map(|(s, _)| s.clone());
                    log_filtered(
                        &list_audit,
                        source,
                        identity,
                        "tools/list:filtered",
                        &t.name,
                        srv,
                        &decision,
                    );
                }
            }
            // Deterministic order: the tool list is assembled from a HashMap
            // of backends, so without an explicit sort the same tool set
            // comes back in a different order every process. That defeats
            // both client-side caching and the LLM prompt cache.
            sort_by_field(&mut tools_allowed, "name");
            let mut result = json!({ "tools": tools_allowed });
            set_private_cache_hints(&mut result, LIST_TTL_MS, stateless_peer);
            JsonRpcResponse::success(id, result)
        }
        "tools/call" => {
            // Capture the requested tool name up front so access-denied and
            // unknown-tool responses are still attributable in the audit log.
            if let Some(Value::String(name)) = req.params.as_ref().and_then(|v| v.get("name")) {
                tool_name_for_audit = Some(name.clone());
            }

            // Decide whether discovery is needed before resolving routing.
            // When the tool name is namespaced (server__tool), we can infer
            // which backend owns it and discover **only** that backend instead
            // of blocking on every pending server.
            let discovery_action = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                match req.params.as_ref().and_then(|v| v.get("name")) {
                    Some(Value::String(name)) if !p.tool_map.contains_key(name) => {
                        match infer_backend_name(name, &p.configs) {
                            Some(backend) if p.is_backend_undiscovered(backend) => {
                                DiscoveryAction::Single(backend.to_string())
                            }
                            Some(_) => DiscoveryAction::None,
                            None if p.has_undiscovered_backends() => DiscoveryAction::All,
                            None => DiscoveryAction::None,
                        }
                    }
                    _ => DiscoveryAction::None,
                }
            };
            match &discovery_action {
                DiscoveryAction::Single(backend) => {
                    discover_single_backend(proxy, backend).await;
                }
                DiscoveryAction::All => {
                    discover_pending_backends(proxy).await;
                }
                DiscoveryAction::None => {}
            }

            // Phase 1: resolve routing under a brief lock.
            let mut identity_headers: Vec<(String, String)> = Vec::new();
            let resolved: std::result::Result<ResolvedCall, JsonRpcResponse> = {
                let mut p = proxy.lock().await;
                match p.resolve_tool_call(&id, req.params.clone(), identity, acl) {
                    Ok((server, orig, args, decision)) => {
                        // Refine the audit entry now that we know the
                        // namespaced tool resolves to a real backend. Done
                        // before the identity check so a refusal below is
                        // attributable to the same tool and server.
                        tool_name_for_audit = Some(format!("{server}{SEPARATOR}{orig}"));
                        server_name_for_audit = Some(server.clone());
                        // Fill the OTel span attributes now that resolution
                        // succeeded — Empty fields are no-ops when telemetry
                        // is off, so this is safe to do unconditionally.
                        let span = tracing::Span::current();
                        span.record("mcp.server", server.as_str());
                        span.record("mcp.tool", orig.as_str());

                        // Identity headers are resolved HERE, under the same
                        // lock that resolved the route: the config and the
                        // caller are both in hand, and phase 3 runs unlocked.
                        match p.identity_headers(&server, identity) {
                            Ok(h) => {
                                identity_headers = h;
                                let client = p.try_get_client(&server);
                                Ok((server, orig, args, client, decision))
                            }
                            Err(why) => {
                                // Refuse rather than fall back to the shared
                                // credential: silently writing under the wrong
                                // owner is the failure this feature exists to
                                // prevent.
                                //
                                // The refusal leaves as `Err` and not as an
                                // early `return`, so it still goes out through
                                // `finish_audit`. A call the ACL allowed and
                                // the proxy then stopped is precisely what the
                                // audit log is for, and returning here would
                                // drop the entry along with the OTel metrics
                                // and the 2026-07-28 result envelope.
                                decision_for_audit = Some(decision);
                                Err(identity_refusal(&id, &why))
                            }
                        }
                    }
                    Err((maybe_decision, resp)) => {
                        decision_for_audit = maybe_decision;
                        Err(resp)
                    }
                }
            };

            match resolved {
                Err(resp) => resp,
                Ok((server, _original, backend_params, maybe_client, acl_decision)) => {
                    decision_for_audit = Some(acl_decision);
                    // Phase 2: ensure connected (without holding the proxy
                    // lock during the connect itself).
                    match client_or_connect(proxy, &server, maybe_client, &id).await {
                        Err(resp) => resp,
                        Ok(client) => {
                            // Phase 3: invoke the backend with NO proxy lock
                            // held, on the raw path. An MRTR backend can answer
                            // with `resultType: "input_required"` and no
                            // `content` at all; parsing into `ToolCallResult`
                            // would turn that valid exchange into an error. The
                            // proxy stays transparent and relays whatever came
                            // back verbatim.
                            //
                            // `call_tool_raw` and not `request_raw`: the former
                            // is the only path that mirrors the backend's
                            // `x-mcp-header` annotations into `Mcp-Param-*`,
                            // and it takes whole params so the MRTR
                            // continuation survives the hop.
                            match client
                                .call_tool_raw_with(backend_params, &identity_headers)
                                .await
                            {
                                Ok(mut result) => {
                                    sanitize_relayed_result(&mut result, stateless_peer);
                                    JsonRpcResponse::success(id, result)
                                }
                                Err(e) => JsonRpcResponse::error(
                                    id,
                                    error_codes::INTERNAL_ERROR,
                                    &format!("[{server}] {e:#}"),
                                ),
                            }
                        }
                    }
                }
            }
        }
        "resources/list" => {
            audit_logger = discover_for_list(proxy).await;
            let (resources_snap, resource_map_snap, list_audit) = {
                let p = proxy.lock().await;
                (
                    p.resources.clone(),
                    p.resource_map.clone(),
                    Arc::clone(&p.audit),
                )
            };
            let mut resources_allowed: Vec<Value> = Vec::new();
            for r in &resources_snap {
                let ctx = resource_map_snap.get(&r.uri).map(|(server, orig)| {
                    server_auth::ResourceContext {
                        server_alias: server.as_str(),
                        resource_uri: orig.as_str(),
                    }
                });
                let decision =
                    server_auth::is_resource_allowed(identity, &r.uri, acl, ctx.as_ref(), true);
                if decision.allowed {
                    resources_allowed.push(serde_json::to_value(r).unwrap());
                } else {
                    let srv = resource_map_snap.get(&r.uri).map(|(s, _)| s.clone());
                    log_filtered(
                        &list_audit,
                        source,
                        identity,
                        "resources/list:filtered",
                        &r.uri,
                        srv,
                        &decision,
                    );
                }
            }
            sort_by_field(&mut resources_allowed, "uri");
            let mut result = json!({ "resources": resources_allowed });
            set_private_cache_hints(&mut result, LIST_TTL_MS, stateless_peer);
            JsonRpcResponse::success(id, result)
        }
        "resources/read" => {
            let uri = req
                .params
                .as_ref()
                .and_then(|v| v.get("uri"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let uri = match uri {
                Some(u) => u,
                None => {
                    let p = proxy.lock().await;
                    audit_logger = Arc::clone(&p.audit);
                    return finish_audit(
                        AuditCtx {
                            audit: audit_logger,
                            source,
                            method,
                            tool_name: None,
                            server_name: None,
                            identity,
                            start,
                            decision: None,
                            mrtr_continuation: mrtr_continuation_for_audit,
                            stateless_peer,
                        },
                        JsonRpcResponse::error(
                            id,
                            error_codes::INVALID_PARAMS,
                            "missing required parameter: uri",
                        ),
                    );
                }
            };

            tool_name_for_audit = Some(uri.clone());

            let discovery_action = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                if p.resource_map.contains_key(&uri) {
                    DiscoveryAction::None
                } else {
                    match infer_backend_name(&uri, &p.configs) {
                        Some(backend) if p.is_backend_undiscovered(backend) => {
                            DiscoveryAction::Single(backend.to_string())
                        }
                        Some(_) => DiscoveryAction::None,
                        None if p.has_undiscovered_backends() => DiscoveryAction::All,
                        None => DiscoveryAction::None,
                    }
                }
            };
            match &discovery_action {
                DiscoveryAction::Single(backend) => {
                    discover_single_backend(proxy, backend).await;
                }
                DiscoveryAction::All => {
                    discover_pending_backends(proxy).await;
                }
                DiscoveryAction::None => {}
            }

            // Resolve: lookup resource_map, check ACL.
            let mut identity_headers: Vec<(String, String)> = Vec::new();
            let resolved: std::result::Result<ResolvedResourceRead, JsonRpcResponse> = {
                let mut p = proxy.lock().await;
                match p.resource_map.get(&uri) {
                    Some((server, original_uri)) => {
                        let ctx = server_auth::ResourceContext {
                            server_alias: server.as_str(),
                            resource_uri: original_uri.as_str(),
                        };
                        let decision = server_auth::is_resource_allowed(
                            identity,
                            &uri,
                            acl,
                            Some(&ctx),
                            false,
                        );
                        if !decision.allowed {
                            decision_for_audit = Some(decision.clone());
                            server_name_for_audit = Some(server.clone());
                            Err(JsonRpcResponse::error(
                                id.clone(),
                                error_codes::INTERNAL_ERROR,
                                &format!(
                                    "access denied: resource '{}' on server '{}'",
                                    original_uri, server
                                ),
                            ))
                        } else {
                            let server = server.clone();
                            let original = original_uri.clone();
                            server_name_for_audit = Some(server.clone());
                            // A resource read is where per-user data comes
                            // back, so it carries the caller's identity for
                            // the same reason `tools/call` does. Same refusal
                            // rule too: no identity beats a wrong one.
                            match p.identity_headers(&server, identity) {
                                Ok(h) => {
                                    identity_headers = h;
                                    let client = p.try_get_client(&server);
                                    Ok((server, original, client, decision))
                                }
                                Err(why) => {
                                    decision_for_audit = Some(decision);
                                    Err(identity_refusal(&id, &why))
                                }
                            }
                        }
                    }
                    None => Err(JsonRpcResponse::error(
                        id.clone(),
                        error_codes::INVALID_PARAMS,
                        &format!("unknown resource: {uri}"),
                    )),
                }
            };

            match resolved {
                Err(resp) => resp,
                Ok((server, original_uri, maybe_client, acl_decision)) => {
                    decision_for_audit = Some(acl_decision);
                    match client_or_connect(proxy, &server, maybe_client, &id).await {
                        Err(resp) => resp,
                        // Raw relay, like `tools/call`: 2026-07-28 lets
                        // `resources/read` answer with an interim
                        // `input_required` result that has no `contents` at
                        // all, and parsing into `ResourceReadResult` would
                        // turn that legal exchange into a -32603.
                        Ok(client) => {
                            let backend_params =
                                backend_resource_read_params(req.params.as_ref(), &original_uri);
                            match client
                                .read_resource_raw(backend_params, &identity_headers)
                                .await
                            {
                                Ok(mut result) => {
                                    sanitize_relayed_result(&mut result, stateless_peer);
                                    namespace_resource_contents(
                                        &mut result,
                                        &server,
                                        &original_uri,
                                    );
                                    set_private_cache_hints(
                                        &mut result,
                                        RESOURCE_READ_TTL_MS,
                                        stateless_peer,
                                    );
                                    JsonRpcResponse::success(id, result)
                                }
                                Err(e) => JsonRpcResponse::error(
                                    id,
                                    error_codes::INTERNAL_ERROR,
                                    &format!("[{server}] {e:#}"),
                                ),
                            }
                        }
                    }
                }
            }
        }
        "prompts/list" => {
            audit_logger = discover_for_list(proxy).await;
            let (prompts_snap, prompt_map_snap, list_audit) = {
                let p = proxy.lock().await;
                (
                    p.prompts.clone(),
                    p.prompt_map.clone(),
                    Arc::clone(&p.audit),
                )
            };
            let mut prompts_allowed: Vec<Value> = Vec::new();
            for pr in &prompts_snap {
                let ctx = prompt_map_snap.get(&pr.name).map(|(server, orig)| {
                    server_auth::PromptContext {
                        server_alias: server.as_str(),
                        prompt_name: orig.as_str(),
                    }
                });
                let decision =
                    server_auth::is_prompt_allowed(identity, &pr.name, acl, ctx.as_ref(), true);
                if decision.allowed {
                    prompts_allowed.push(serde_json::to_value(pr).unwrap());
                } else {
                    let srv = prompt_map_snap.get(&pr.name).map(|(s, _)| s.clone());
                    log_filtered(
                        &list_audit,
                        source,
                        identity,
                        "prompts/list:filtered",
                        &pr.name,
                        srv,
                        &decision,
                    );
                }
            }
            sort_by_field(&mut prompts_allowed, "name");
            let mut result = json!({ "prompts": prompts_allowed });
            set_private_cache_hints(&mut result, LIST_TTL_MS, stateless_peer);
            JsonRpcResponse::success(id, result)
        }
        "prompts/get" => {
            let name = req
                .params
                .as_ref()
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let prompt_name = match name {
                Some(n) => n,
                None => {
                    let p = proxy.lock().await;
                    audit_logger = Arc::clone(&p.audit);
                    return finish_audit(
                        AuditCtx {
                            audit: audit_logger,
                            source,
                            method,
                            tool_name: None,
                            server_name: None,
                            identity,
                            start,
                            decision: None,
                            mrtr_continuation: mrtr_continuation_for_audit,
                            stateless_peer,
                        },
                        JsonRpcResponse::error(
                            id,
                            error_codes::INVALID_PARAMS,
                            "missing required parameter: name",
                        ),
                    );
                }
            };

            tool_name_for_audit = Some(prompt_name.clone());

            let discovery_action = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                if p.prompt_map.contains_key(&prompt_name) {
                    DiscoveryAction::None
                } else {
                    match infer_backend_name(&prompt_name, &p.configs) {
                        Some(backend) if p.is_backend_undiscovered(backend) => {
                            DiscoveryAction::Single(backend.to_string())
                        }
                        Some(_) => DiscoveryAction::None,
                        None if p.has_undiscovered_backends() => DiscoveryAction::All,
                        None => DiscoveryAction::None,
                    }
                }
            };
            match &discovery_action {
                DiscoveryAction::Single(backend) => {
                    discover_single_backend(proxy, backend).await;
                }
                DiscoveryAction::All => {
                    discover_pending_backends(proxy).await;
                }
                DiscoveryAction::None => {}
            }

            let mut identity_headers: Vec<(String, String)> = Vec::new();
            let resolved: std::result::Result<ResolvedPromptGet, JsonRpcResponse> = {
                let mut p = proxy.lock().await;
                match p.prompt_map.get(&prompt_name) {
                    Some((server, original_name)) => {
                        let ctx = server_auth::PromptContext {
                            server_alias: server.as_str(),
                            prompt_name: original_name.as_str(),
                        };
                        let decision = server_auth::is_prompt_allowed(
                            identity,
                            &prompt_name,
                            acl,
                            Some(&ctx),
                            false,
                        );
                        if !decision.allowed {
                            decision_for_audit = Some(decision.clone());
                            server_name_for_audit = Some(server.clone());
                            Err(JsonRpcResponse::error(
                                id.clone(),
                                error_codes::INTERNAL_ERROR,
                                &format!(
                                    "access denied: prompt '{}' on server '{}'",
                                    original_name, server
                                ),
                            ))
                        } else {
                            let server = server.clone();
                            let original = original_name.clone();
                            server_name_for_audit = Some(server.clone());
                            let backend_params =
                                backend_prompt_get_params(req.params.as_ref(), &original);
                            // `prompts/get` reaches the backend like the other
                            // two, so it forwards identity like the other two.
                            match p.identity_headers(&server, identity) {
                                Ok(h) => {
                                    identity_headers = h;
                                    let client = p.try_get_client(&server);
                                    Ok((server, original, backend_params, client, decision))
                                }
                                Err(why) => {
                                    decision_for_audit = Some(decision);
                                    Err(identity_refusal(&id, &why))
                                }
                            }
                        }
                    }
                    None => Err(JsonRpcResponse::error(
                        id.clone(),
                        error_codes::INVALID_PARAMS,
                        &format!("unknown prompt: {prompt_name}"),
                    )),
                }
            };

            match resolved {
                Err(resp) => resp,
                Ok((server, _original_name, backend_params, maybe_client, acl_decision)) => {
                    decision_for_audit = Some(acl_decision);
                    match client_or_connect(proxy, &server, maybe_client, &id).await {
                        Err(resp) => resp,
                        // Raw relay: `prompts/get` is one of the three methods
                        // that may answer with an interim `input_required`
                        // result, which has no `messages` and so cannot be
                        // parsed into `PromptGetResult`.
                        Ok(client) => match client
                            .get_prompt_raw(backend_params, &identity_headers)
                            .await
                        {
                            Ok(mut result) => {
                                sanitize_relayed_result(&mut result, stateless_peer);
                                JsonRpcResponse::success(id, result)
                            }
                            Err(e) => JsonRpcResponse::error(
                                id,
                                error_codes::INTERNAL_ERROR,
                                &format!("[{server}] {e:#}"),
                            ),
                        },
                    }
                }
            }
        }
        _ => {
            let p = proxy.lock().await;
            audit_logger = Arc::clone(&p.audit);
            JsonRpcResponse::error(
                id,
                error_codes::METHOD_NOT_FOUND,
                &format!("method not found: {}", req.method),
            )
        }
    };

    finish_audit(
        AuditCtx {
            audit: audit_logger,
            source,
            method,
            tool_name: tool_name_for_audit,
            server_name: server_name_for_audit,
            identity,
            start,
            decision: decision_for_audit,
            mrtr_continuation: mrtr_continuation_for_audit,
            stateless_peer,
        },
        response,
    )
}

/// Sort a list result in place by a string field, so the same set of
/// primitives always serializes identically. `sort_by` on `str` is stable
/// and total here — entries are namespaced (`{server}__{name}`), so the key
/// is unique and ties never arise.
fn sort_by_field(items: &mut [Value], field: &str) {
    fn key<'a>(v: &'a Value, field: &str) -> &'a str {
        v.get(field).and_then(|s| s.as_str()).unwrap_or("")
    }
    items.sort_by(|a, b| key(a, field).cmp(key(b, field)));
}

/// Attach the `CacheableResult` hints the 2026-07-28 revision requires on
/// `tools/list`, `prompts/list`, `resources/list`, `resources/read` and
/// `server/discover` — for a peer that asked for that revision, and no one
/// else. See [`stamp_result_envelope`] for why the gate exists.
///
/// The scope is always `private`, including on `server/discover` where the
/// spec's own example shows `public`. Every list result is ACL-filtered
/// against the calling identity, so a shared intermediary that cached one
/// would hand another identity a tool list it is not allowed to see.
/// Discovery is not filtered today, but it is served from the same
/// authenticated endpoint and its `capabilities` are one commit away from
/// reflecting which backends an identity can reach — at which point a
/// `public` entry cached under someone else's request becomes the same leak.
/// The cost of `private` is a shared-cache miss; the cost of being wrong the
/// other way is a cross-identity disclosure.
fn set_private_cache_hints(result: &mut Value, ttl_ms: u64, stateless_peer: bool) {
    if !stateless_peer {
        return;
    }
    crate::protocol::set_cache_hints(result, ttl_ms, CacheScope::Private);
}

/// Discover every backend that still needs it before answering a `*/list`,
/// and hand back the audit logger the arm needs either way.
///
/// This used to also require the registry to be *empty*: one backend restored
/// from the tool cache was enough to skip discovering all the others, and the
/// client was told they did not exist (issue #106). A truncated list is worse
/// than a slower one — the caller cannot tell the difference, and acts on it.
async fn discover_for_list(proxy: &SharedProxy) -> Arc<AuditLogger> {
    let (needs_discovery, audit) = {
        let p = proxy.lock().await;
        (p.has_undiscovered_backends(), Arc::clone(&p.audit))
    };
    if needs_discovery {
        discover_pending_backends(proxy).await;
    }
    audit
}

/// The response for a call the proxy stopped because it could not say who
/// the caller is.
///
/// All three backend-reaching methods refuse identically, and they must:
/// `tools/call`, `resources/read` and `prompts/get` are one decision wearing
/// three names, and a message that drifts between them would read as three
/// different problems.
fn identity_refusal(id: &Value, why: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id.clone(),
        error_codes::INVALID_PARAMS,
        &format!("cannot forward caller identity: {why}"),
    )
}

/// The backend's client: the pooled one, or a fresh connection.
///
/// Returns the client, or the error response to hand back — every caller
/// reports a failed connect the same way.
async fn client_or_connect(
    proxy: &SharedProxy,
    server: &str,
    pooled: Option<Arc<McpClient>>,
    id: &Value,
) -> Result<Arc<McpClient>, JsonRpcResponse> {
    match pooled {
        Some(client) => Ok(client),
        None => connect_backend(proxy, server).await.map_err(|e| {
            JsonRpcResponse::error(
                id.clone(),
                error_codes::INTERNAL_ERROR,
                &format!("failed to connect to backend '{server}': {e:#}"),
            )
        }),
    }
}

/// Audit a primitive the ACL hid from a `*/list` result.
///
/// The three list arms differ only in which primitive they name — the entry
/// is otherwise identical, classification fields included: only tool
/// decisions ever populate those, and resource and prompt decisions leave
/// them `None`, so reading them off the decision is correct for all three.
fn log_filtered(
    audit: &AuditLogger,
    source: &str,
    identity: &AuthIdentity,
    method: &str,
    name: &str,
    server_name: Option<String>,
    decision: &server_auth::Decision,
) {
    audit.log(AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: source.to_string(),
        method: method.to_string(),
        tool_name: Some(name.to_string()),
        server_name,
        identity: identity.subject.clone(),
        duration_ms: 0,
        success: true,
        error_message: None,
        arguments: None,
        acl_decision: Some("deny".to_string()),
        acl_matched_rule: Some(decision.matched_rule.to_string()),
        acl_access_kind: decision
            .access_evaluated
            .as_ref()
            .map(|a| a.as_str().to_string()),
        classification_kind: decision.classification_kind.map(|k| k.as_str().to_string()),
        classification_source: decision
            .classification_source
            .map(|s| s.as_str().to_string()),
        classification_confidence: decision.classification_confidence,
    });
}

/// Rewrite `contents[].uri` from the backend's own URI to the namespaced one
/// the client asked for, so a client can feed a `resources/read` reply back
/// to us unchanged.
///
/// Operates on the raw relayed JSON because an interim `input_required`
/// result carries no `contents` at all — absence is normal here, not an
/// error.
fn namespace_resource_contents(result: &mut Value, server: &str, original_uri: &str) {
    let Some(contents) = result.get_mut("contents").and_then(|c| c.as_array_mut()) else {
        return;
    };
    let namespaced = format!("{server}{SEPARATOR}{original_uri}");
    for content in contents {
        let Some(obj) = content.as_object_mut() else {
            continue;
        };
        if obj.get("uri").and_then(|u| u.as_str()) == Some(original_uri) {
            obj.insert("uri".to_string(), Value::String(namespaced.clone()));
        }
    }
}

/// Sanitize a result the proxy relays verbatim from a backend.
///
/// The relay path (`tools/call`, `resources/read`, `prompts/get`) exists so
/// an MRTR interim result survives the hop, but it also means the *backend*
/// writes the JSON the client reads. Cache directives are not the backend's
/// to write: a `cacheScope: "public"` on an answer we produced under one
/// identity's ACL is a cross-identity leak, and a generous `ttlMs` pins a
/// result in front of an ACL that may since have changed. They are stripped
/// here and re-stated by the caller for the methods where the proxy actually
/// has something to say.
///
/// `resultType` follows the same rule as the rest of the 2026-07-28 envelope.
/// A genuine `input_required` is preserved for **every** peer: it is the one
/// value that changes what the response means, and dropping it would report an
/// unfinished exchange as finished. Otherwise the field belongs to the
/// revision, so a stateless peer gets a normalized `complete` and a legacy
/// peer gets no `resultType` at all — including one a modern backend
/// volunteered, which is still a field that peer never negotiated.
///
/// Every other field is relayed untouched, so `structuredContent`, `isError`
/// and any future extension keep flowing through.
fn sanitize_relayed_result(result: &mut Value, stateless_peer: bool) {
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    obj.remove("ttlMs");
    obj.remove("cacheScope");

    let interim = obj.get("resultType").and_then(|v| v.as_str())
        == Some(crate::protocol::RESULT_TYPE_INPUT_REQUIRED);
    if interim {
        // Left exactly as the backend wrote it, for either kind of peer.
    } else if stateless_peer {
        obj.insert(
            "resultType".to_string(),
            Value::String(crate::protocol::RESULT_TYPE_COMPLETE.to_string()),
        );
        // `_meta` is an object by spec. A backend answering with a scalar
        // there would otherwise suppress the serverInfo stamp entirely —
        // `set_result_meta` declines to write into a non-object — and the
        // client would receive the backend's scalar in its place. Only
        // meaningful on the path that is about to stamp; a legacy peer's
        // relay stays byte-for-byte the backend's.
        if obj.get("_meta").is_some_and(|m| !m.is_object()) {
            obj.insert("_meta".to_string(), Value::Object(serde_json::Map::new()));
        }
    } else {
        obj.remove("resultType");
    }
}

/// Stamp the fields 2026-07-28 requires on every outgoing result:
/// `resultType` and the `_meta` serverInfo.
///
/// Only for a peer that declared a stateless revision. "Unknown keys are
/// inert" is true of most clients and not of the contract: a pre-2026-07-28
/// peer negotiated a revision in which these fields do not exist, and one
/// validating a result against a closed schema is a real client, not a
/// hypothetical. The whole premise of this work is that a legacy peer sees
/// the bytes it saw before — `serve::http` says so, `backend_tool_call_params`
/// says so, and this used to say the opposite.
///
/// Doing it here still means no response path can forget: every response the
/// proxy emits funnels through `finish_audit`, which carries the flag.
///
/// An MRTR interim result relayed from a backend keeps its own
/// `input_required` — see `set_result_type_complete`.
fn stamp_result_envelope(response: &mut JsonRpcResponse, stateless_peer: bool) {
    if !stateless_peer {
        return;
    }
    let Some(result) = response.result.as_mut() else {
        return;
    };
    crate::protocol::set_result_type_complete(result);
    crate::protocol::set_result_meta(
        result,
        meta_keys::SERVER_INFO,
        serde_json::to_value(proxy_server_info()).unwrap(),
    );
}

pub(crate) struct AuditCtx<'a> {
    pub(crate) audit: Arc<AuditLogger>,
    pub(crate) source: &'a str,
    pub(crate) method: String,
    pub(crate) tool_name: Option<String>,
    pub(crate) server_name: Option<String>,
    pub(crate) identity: &'a AuthIdentity,
    pub(crate) start: std::time::Instant,
    pub(crate) decision: Option<server_auth::Decision>,
    /// MRTR continuation fields the request carried, if any.
    pub(crate) mrtr_continuation: Vec<&'static str>,
    /// Whether the peer declared a stateless (2026-07-28+) revision, and so
    /// asked for the result envelope this revision adds.
    pub(crate) stateless_peer: bool,
}

pub(crate) fn finish_audit(ctx: AuditCtx<'_>, mut response: JsonRpcResponse) -> JsonRpcResponse {
    // Single funnel for every response the proxy emits — the one place that
    // can guarantee the 2026-07-28 result envelope is present for exactly the
    // peers that asked for it.
    stamp_result_envelope(&mut response, ctx.stateless_peer);

    // Record the final OTel status on the root span. No-op when the field
    // wasn't declared (i.e. caller wasn't instrumented) or telemetry is off.
    let status = if response.error.is_none() {
        "ok"
    } else {
        "error"
    };
    tracing::Span::current().record("mcp.status", status);

    let duration_ms = ctx.start.elapsed().as_millis() as u64;

    // OTel metrics — emit when an exporter was wired. Reuse the same
    // `duration_ms` the audit path computes, so we never measure twice.
    if let Some(metrics) = crate::telemetry::metrics() {
        let mut labels = vec![
            opentelemetry::KeyValue::new("mcp.method", ctx.method.clone()),
            opentelemetry::KeyValue::new("mcp.transport", ctx.source.to_string()),
            opentelemetry::KeyValue::new("mcp.status", status.to_string()),
            opentelemetry::KeyValue::new("mcp.identity", ctx.identity.subject.clone()),
        ];
        if let Some(server) = ctx.server_name.as_ref() {
            labels.push(opentelemetry::KeyValue::new("mcp.server", server.clone()));
        }
        // Audit stores tool_name namespaced (`{server}__{tool}`) on
        // resolved tools/call so the audit log stays self-contained. For
        // the metric, strip the server prefix when present so `mcp.tool`
        // mirrors the span attribute (un-namespaced) and avoids
        // multiplying cardinality with `mcp.server`.
        if let Some(tool) = ctx.tool_name.as_ref() {
            let bare = match ctx.server_name.as_ref() {
                Some(server) => {
                    let prefix = format!("{server}{SEPARATOR}");
                    tool.strip_prefix(&prefix).unwrap_or(tool).to_string()
                }
                None => tool.clone(),
            };
            labels.push(opentelemetry::KeyValue::new("mcp.tool", bare));
        }
        metrics.requests.add(1, &labels);
        metrics.request_duration.record(duration_ms as f64, &labels);
    }

    let (acl_decision, acl_matched_rule, acl_access_kind, cls_kind, cls_source, cls_conf) =
        match &ctx.decision {
            Some(d) => (
                Some(if d.allowed { "allow" } else { "deny" }.to_string()),
                Some(d.matched_rule.to_string()),
                d.access_evaluated.as_ref().map(|a| a.as_str().to_string()),
                d.classification_kind.map(|k| k.as_str().to_string()),
                d.classification_source.map(|s| s.as_str().to_string()),
                d.classification_confidence,
            ),
            None => (None, None, None, None, None, None),
        };

    ctx.audit.log(AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: ctx.source.to_string(),
        method: ctx.method,
        tool_name: ctx.tool_name,
        server_name: ctx.server_name,
        identity: ctx.identity.subject.clone(),
        duration_ms,
        success: response.error.is_none(),
        error_message: response.error.as_ref().map(|e| e.message.clone()),
        // Never the actual arguments — they routinely hold secrets. Only the
        // fact that this call resumed an MRTR exchange, which is what makes a
        // relayed continuation attributable after the fact.
        arguments: (!ctx.mrtr_continuation.is_empty())
            .then(|| json!({ "mrtrContinuation": ctx.mrtr_continuation })),
        acl_decision,
        acl_matched_rule,
        acl_access_kind,
        classification_kind: cls_kind,
        classification_source: cls_source,
        classification_confidence: cls_conf,
    });
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::ToolCacheStore;
    use crate::protocol::{Prompt, Resource, Tool};
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    use super::super::proxy::ProxyServer;

    fn test_server() -> ProxyServer {
        let pool = Arc::new(crate::db::DbPool::disabled());
        let cache_store = ToolCacheStore::new(pool);
        ProxyServer::new(
            Arc::new(AuditLogger::Disabled),
            HashMap::new(),
            HashMap::new(),
            cache_store,
        )
    }

    /// Test helper: wraps `server` in a `SharedProxy` and routes a request
    /// through the production `dispatch_request` path, as a peer that
    /// declared the 2026-07-28 revision. The legacy-peer gate has its own
    /// tests (`test_legacy_peer_gets_no_*`) and `dispatch_as` below.
    async fn dispatch(
        server: ProxyServer,
        req: JsonRpcRequest,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
    ) -> JsonRpcResponse {
        dispatch_as(server, req, identity, acl, true).await
    }

    /// Same, choosing whether the peer declared a stateless revision.
    async fn dispatch_as(
        server: ProxyServer,
        req: JsonRpcRequest,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
        stateless_peer: bool,
    ) -> JsonRpcResponse {
        let proxy: SharedProxy = Arc::new(Mutex::new(server));
        dispatch_request(&proxy, req, identity, acl, "test", stateless_peer).await
    }

    #[tokio::test]
    async fn test_proxy_server_empty_tools_list() {
        let server = test_server();
        // No configs → has_undiscovered_backends() is false, discovery is skipped
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(2, "tools/list", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn test_proxy_server_tools_list_with_tools() {
        let mut server = test_server();
        // No configs → has_undiscovered_backends() is false, discovery is skipped
        server.tools.push(Tool {
            name: "sentry__search_issues".to_string(),
            description: Some("[sentry] Search for issues".to_string()),
            input_schema: None,
            annotations: None,
        });
        server.tool_map.insert(
            "sentry__search_issues".to_string(),
            ("sentry".to_string(), "search_issues".to_string()),
        );

        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(3, "tools/list", None);
        let resp = dispatch(server, req, &identity, &None).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "sentry__search_issues");
        assert_eq!(tools[0]["description"], "[sentry] Search for issues");
    }

    #[tokio::test]
    async fn test_proxy_server_unknown_tool() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(
            4,
            "tools/call",
            Some(serde_json::json!({"name": "nonexistent__tool"})),
        );
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("unknown tool"));
    }

    #[tokio::test]
    async fn test_proxy_server_missing_params() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(5, "tools/call", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[tokio::test]
    async fn test_proxy_server_missing_name_in_params() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(6, "tools/call", Some(serde_json::json!({"arguments": {}})));
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("missing 'name'"));
    }

    #[tokio::test]
    async fn test_proxy_server_backend_not_connected() {
        let mut server = test_server();
        let identity = AuthIdentity::anonymous();
        server.tool_map.insert(
            "ghost__tool".to_string(),
            ("ghost".to_string(), "tool".to_string()),
        );
        let req = JsonRpcRequest::new(
            7,
            "tools/call",
            Some(serde_json::json!({"name": "ghost__tool"})),
        );
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32603);
        assert!(err.message.contains("failed to connect"));
    }

    #[tokio::test]
    async fn test_tools_call_triggers_discovery() {
        // tools/call before tools/list should trigger discovery
        let server = test_server();
        assert!(server.discovered_backends.is_empty());
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(
            20,
            "tools/call",
            Some(serde_json::json!({"name": "nonexistent__tool"})),
        );
        let resp = dispatch(server, req, &identity, &None).await;
        // No backends configured, so tool_map is empty → unknown tool
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("unknown tool"));
    }

    /// A partial tool cache used to suppress discovery entirely: the registry
    /// was non-empty, so the backends that had *no* cache entry were never
    /// contacted and the client was told they did not exist (issue #106).
    #[tokio::test]
    async fn tools_list_discovers_backends_missing_from_a_partial_cache() {
        use crate::config::{IdleTimeoutPolicy, ServerConfig};

        let mut server = test_server();
        // `outl` is configured but has no cache entry — it must be discovered.
        server.configs.insert(
            "outl".to_string(),
            ServerConfig::Stdio {
                // Exits immediately, so discovery fails fast instead of
                // stalling the test on the 30s timeout. What matters is that
                // it was *attempted*.
                command: "true".to_string(),
                args: vec![],
                env: HashMap::new(),
                tool_acl: None,
                idle_timeout: IdleTimeoutPolicy::default(),
                min_idle_timeout: None,
                max_idle_timeout: None,
            },
        );
        // `ai-memory` came off the cache, so the registry is already non-empty.
        server.register_tools(
            "ai-memory",
            &[Tool {
                name: "memory_query".to_string(),
                description: Some("Query".to_string()),
                input_schema: None,
                annotations: None,
            }],
        );
        server.discovered_backends.insert("ai-memory".to_string());
        assert!(!server.tools.is_empty());

        let proxy: SharedProxy = Arc::new(Mutex::new(server));
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(1, "tools/list", None);
        let resp = dispatch_request(&proxy, req, &identity, &None, "test", true).await;
        assert!(resp.error.is_none());

        let p = proxy.lock().await;
        assert!(
            p.discovery_failures.contains_key("outl"),
            "outl was never discovered — a cached backend suppressed discovery"
        );
    }

    #[tokio::test]
    async fn test_handle_request_unknown_method() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(1, "unknown/method", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert!(err.message.contains("method not found"));
    }

    #[tokio::test]
    async fn test_handle_request_initialize() {
        let server = test_server();
        let identity = AuthIdentity::anonymous();
        let req = JsonRpcRequest::new(1, "initialize", None);
        let resp = dispatch(server, req, &identity, &None).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], crate::protocol::PROTOCOL_VERSION);
    }

    #[test]
    fn test_protocol_version_is_current() {
        assert_eq!(crate::protocol::PROTOCOL_VERSION, "2026-07-28");
    }

    /// The revision every backend we proxy is still on must stay in the
    /// supported set — dropping it would break them silently.
    #[test]
    fn test_legacy_protocol_version_still_supported() {
        assert!(crate::protocol::is_version_supported(
            crate::protocol::PROTOCOL_VERSION_LEGACY
        ));
    }

    #[test]
    fn test_notification_has_no_id() {
        // JSON-RPC notifications have no "id" field
        let notification: Value = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert!(notification.get("id").is_none());

        // Requests have an "id" field
        let request: Value =
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        assert!(request.get("id").is_some());
    }

    #[tokio::test]
    async fn test_tools_list_filtered_by_acl() {
        use crate::server_auth::{AclPolicy, AclRule};

        let mut server = test_server();
        // No configs → has_undiscovered_backends() is false, discovery is skipped
        server.tools.push(Tool {
            name: "sentry__search_issues".to_string(),
            description: Some("[sentry] Search".to_string()),
            input_schema: None,
            annotations: None,
        });
        server.tools.push(Tool {
            name: "slack__send_message".to_string(),
            description: Some("[slack] Send".to_string()),
            input_schema: None,
            annotations: None,
        });

        let acl = Some(AclConfig::legacy(
            AclPolicy::Allow,
            vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        ));

        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(10, "tools/list", None);
        let resp = dispatch(server, req, &bob, &acl).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "slack__send_message");
    }

    #[tokio::test]
    async fn test_tools_call_denied_by_acl() {
        use crate::server_auth::{AclPolicy, AclRule};

        let mut server = test_server();
        server.tool_map.insert(
            "sentry__search".to_string(),
            ("sentry".to_string(), "search".to_string()),
        );

        let acl = Some(AclConfig::legacy(
            AclPolicy::Allow,
            vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        ));

        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(
            11,
            "tools/call",
            Some(serde_json::json!({"name": "sentry__search"})),
        );
        let resp = dispatch(server, req, &bob, &acl).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("access denied"));
    }

    // --- Resources dispatch tests ---

    #[tokio::test]
    async fn test_resources_list_returns_registered_resources() {
        let mut server = test_server();
        server.register_resources(
            "sentry",
            &[Resource {
                uri: "issue://123".to_string(),
                name: "Issue 123".to_string(),
                description: Some("A bug".to_string()),
                mime_type: None,
                annotations: None,
            }],
        );

        let req = JsonRpcRequest::new(10, "resources/list", None);
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "sentry__issue://123");
        assert_eq!(resources[0]["name"], "sentry__Issue 123");
    }

    #[tokio::test]
    async fn test_resources_list_filtered_by_acl() {
        use crate::server_auth::{AclPolicy, AclRule};

        let mut server = test_server();
        server.register_resources(
            "sentry",
            &[Resource {
                uri: "issue://1".to_string(),
                name: "Issue 1".to_string(),
                description: None,
                mime_type: None,
                annotations: None,
            }],
        );
        server.register_resources(
            "slack",
            &[Resource {
                uri: "channel://general".to_string(),
                name: "General".to_string(),
                description: None,
                mime_type: None,
                annotations: None,
            }],
        );

        let acl = Some(AclConfig::legacy(
            AclPolicy::Allow,
            vec![AclRule {
                subjects: vec!["bob".to_string()],
                roles: vec![],
                tools: vec!["sentry__*".to_string()],
                policy: AclPolicy::Deny,
            }],
        ));

        // Legacy ACL with default=allow → resources allowed (legacy doesn't
        // have resource-specific rules; our implementation uses default).
        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(10, "resources/list", None);
        let resp = dispatch(server, req, &bob, &acl).await;
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();
        // Legacy default=allow → all resources pass
        assert_eq!(resources.len(), 2);
    }

    #[tokio::test]
    async fn test_resources_read_unknown_returns_error() {
        let server = test_server();
        let req = JsonRpcRequest::new(
            10,
            "resources/read",
            Some(serde_json::json!({"uri": "sentry__issue://999"})),
        );
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("unknown resource"));
    }

    #[tokio::test]
    async fn test_resources_read_missing_uri_param() {
        let server = test_server();
        let req = JsonRpcRequest::new(10, "resources/read", Some(serde_json::json!({})));
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("missing required parameter: uri"));
    }

    #[tokio::test]
    async fn test_resources_read_denied_by_acl() {
        use crate::server_auth::AclPolicy;

        let mut server = test_server();
        server.resource_map.insert(
            "sentry__issue://123".to_string(),
            ("sentry".to_string(), "issue://123".to_string()),
        );

        let acl = Some(AclConfig::legacy(AclPolicy::Deny, vec![]));

        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(
            11,
            "resources/read",
            Some(serde_json::json!({"uri": "sentry__issue://123"})),
        );
        let resp = dispatch(server, req, &bob, &acl).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("access denied"));
    }

    // --- Prompts dispatch tests ---

    #[tokio::test]
    async fn test_prompts_list_returns_registered_prompts() {
        let mut server = test_server();
        server.register_prompts(
            "ai",
            &[Prompt {
                name: "summarize".to_string(),
                description: Some("Summarize text".to_string()),
                arguments: None,
            }],
        );

        let req = JsonRpcRequest::new(10, "prompts/list", None);
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        let result = resp.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "ai__summarize");
    }

    #[tokio::test]
    async fn test_prompts_list_filtered_by_acl() {
        use crate::server_auth::AclPolicy;

        let mut server = test_server();
        server.register_prompts(
            "ai",
            &[Prompt {
                name: "summarize".to_string(),
                description: None,
                arguments: None,
            }],
        );

        let acl = Some(AclConfig::legacy(AclPolicy::Deny, vec![]));

        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(10, "prompts/list", None);
        let resp = dispatch(server, req, &bob, &acl).await;
        let result = resp.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        // Legacy default=deny → listing still allowed (only read/get denied)
        assert_eq!(prompts.len(), 1);
    }

    #[tokio::test]
    async fn test_prompts_get_unknown_returns_error() {
        let server = test_server();
        let req = JsonRpcRequest::new(
            10,
            "prompts/get",
            Some(serde_json::json!({"name": "ai__unknown"})),
        );
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("unknown prompt"));
    }

    #[tokio::test]
    async fn test_prompts_get_missing_name_param() {
        let server = test_server();
        let req = JsonRpcRequest::new(10, "prompts/get", Some(serde_json::json!({})));
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("missing required parameter: name"));
    }

    #[tokio::test]
    async fn test_prompts_get_denied_by_acl() {
        use crate::server_auth::AclPolicy;

        let mut server = test_server();
        server.prompt_map.insert(
            "ai__summarize".to_string(),
            ("ai".to_string(), "summarize".to_string()),
        );

        let acl = Some(AclConfig::legacy(AclPolicy::Deny, vec![]));

        let bob = AuthIdentity::new("bob", vec![]);
        let req = JsonRpcRequest::new(
            11,
            "prompts/get",
            Some(serde_json::json!({"name": "ai__summarize"})),
        );
        let resp = dispatch(server, req, &bob, &acl).await;
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("access denied"));
    }

    // --- 2026-07-28: per-request version negotiation ---

    /// Build params carrying a `_meta` protocol version, the way a
    /// 2026-07-28 client declares which revision it speaks.
    fn params_with_version(version: &str) -> Value {
        json!({ "_meta": { meta_keys::PROTOCOL_VERSION: version } })
    }

    #[tokio::test]
    async fn test_declared_supported_version_is_served() {
        let server = test_server();
        let req = JsonRpcRequest::new(
            1,
            "tools/list",
            Some(params_with_version(crate::protocol::PROTOCOL_VERSION)),
        );
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap()["tools"].is_array());
    }

    #[tokio::test]
    async fn test_declared_legacy_version_is_served() {
        let server = test_server();
        let req = JsonRpcRequest::new(
            1,
            "tools/list",
            Some(params_with_version(
                crate::protocol::PROTOCOL_VERSION_LEGACY,
            )),
        );
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_none());
    }

    /// The spec requires the error to carry the versions we do speak: without
    /// them the client can only give up, with them it can pick one and retry.
    #[tokio::test]
    async fn test_declared_unsupported_version_is_rejected_with_the_supported_list() {
        for bogus in ["2099-01-01", "garbage", ""] {
            let req = JsonRpcRequest::new(1, "tools/list", Some(params_with_version(bogus)));
            let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
            let err = resp.error.expect("bogus version must be rejected");
            assert_eq!(err.code, error_codes::UNSUPPORTED_PROTOCOL_VERSION);
            let data = err.data.expect("clients need the list to retry");
            assert_eq!(data["requested"], bogus);
            let supported: Vec<&str> = data["supported"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(supported, crate::protocol::SUPPORTED_PROTOCOL_VERSIONS);
        }
    }

    /// The compat hinge: no `_meta` at all is a pre-2026-07-28 peer and must
    /// take exactly the old path, never an error.
    #[tokio::test]
    async fn test_absent_version_takes_the_legacy_path() {
        let mut server = test_server();
        server.tools.push(Tool {
            name: "sentry__search".to_string(),
            description: None,
            input_schema: None,
            annotations: None,
        });
        let req = JsonRpcRequest::new(1, "tools/list", None);
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["tools"][0]["name"], "sentry__search");
    }

    /// Params present but carrying no `_meta` (the shape every legacy
    /// `tools/call` has) must not be mistaken for a version declaration.
    #[tokio::test]
    async fn test_params_without_meta_are_not_a_version_declaration() {
        let server = test_server();
        let req = JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "ghost__x"})));
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, error_codes::INVALID_PARAMS);
        assert!(err.message.contains("unknown tool"));
    }

    // --- 2026-07-28: server/discover ---

    /// Asserted against the RAW wire JSON, not a round trip through our own
    /// `ServerDiscoverResult`: a struct that both encodes and decodes the
    /// wrong field name round-trips perfectly against itself while failing
    /// against every real peer. That is exactly the bug this pins.
    #[tokio::test]
    async fn test_server_discover_advertises_every_supported_revision() {
        let req = JsonRpcRequest::new(1, "server/discover", None);
        let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();

        let versions: Vec<&str> = result["supportedVersions"]
            .as_array()
            .expect("spec field name is `supportedVersions`")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(versions, crate::protocol::SUPPORTED_PROTOCOL_VERSIONS);
        assert!(versions.contains(&crate::protocol::PROTOCOL_VERSION_LEGACY));

        // The pre-release shape we shipped by mistake must not come back.
        assert!(result.get("protocolVersions").is_none());
        assert!(result.get("serverInfo").is_none());

        assert!(result["capabilities"]["tools"].is_object());
        // Identity lives in `_meta`, keyed by the reverse-DNS name.
        let info = &result["_meta"][meta_keys::SERVER_INFO];
        assert_eq!(info["name"], "mcp-proxy");
        assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    }

    /// The spec page says discovery supports caching and its example even
    /// carries `cacheScope: "public"`. Ours is `private` on purpose — see
    /// `set_private_cache_hints`.
    #[tokio::test]
    async fn test_server_discover_is_cacheable_but_never_public() {
        let req = JsonRpcRequest::new(1, "server/discover", None);
        let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
        let result = resp.result.unwrap();
        assert_eq!(result["resultType"], crate::protocol::RESULT_TYPE_COMPLETE);
        assert_eq!(result["ttlMs"], DISCOVER_TTL_MS);
        assert_eq!(result["cacheScope"], "private");
    }

    #[tokio::test]
    async fn test_server_discover_capabilities_match_initialize() {
        let discover = dispatch(
            test_server(),
            JsonRpcRequest::new(1, "server/discover", None),
            &AuthIdentity::anonymous(),
            &None,
        )
        .await
        .result
        .unwrap();
        let init = dispatch(
            test_server(),
            JsonRpcRequest::new(1, "initialize", None),
            &AuthIdentity::anonymous(),
            &None,
        )
        .await
        .result
        .unwrap();
        assert_eq!(discover["capabilities"], init["capabilities"]);
        // `initialize` keeps identity at the top level (that is its 2025-era
        // shape); `server/discover` moves it into `_meta`. Same value, two
        // envelopes — they must never drift.
        assert_eq!(
            discover["_meta"][meta_keys::SERVER_INFO],
            init["serverInfo"]
        );
    }

    // --- 2026-07-28: initialize stays legacy-friendly ---

    #[tokio::test]
    async fn test_initialize_echoes_the_clients_revision() {
        for requested in ["2025-11-25", "2025-06-18", "2024-11-05"] {
            let req =
                JsonRpcRequest::new(1, "initialize", Some(json!({"protocolVersion": requested})));
            let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
            assert_eq!(
                resp.result.unwrap()["protocolVersion"],
                requested,
                "a {requested} client must be answered in its own revision"
            );
        }
    }

    #[tokio::test]
    async fn test_initialize_falls_back_to_newest_for_unknown_revision() {
        let req = JsonRpcRequest::new(
            1,
            "initialize",
            Some(json!({"protocolVersion": "1999-01-01"})),
        );
        let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
        assert_eq!(
            resp.result.unwrap()["protocolVersion"],
            crate::protocol::PROTOCOL_VERSION
        );
    }

    // --- 2026-07-28: CacheableResult hints ---

    /// A shared intermediary that cached one identity's list would hand it to
    /// the next identity — our lists are ACL-filtered, so the scope MUST be
    /// private on every one of them.
    #[tokio::test]
    async fn test_list_results_are_private_and_carry_a_ttl() {
        for method in ["tools/list", "resources/list", "prompts/list"] {
            let req = JsonRpcRequest::new(1, method, None);
            let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
            let result = resp.result.unwrap();
            assert_eq!(result["cacheScope"], "private", "{method} must be private");
            assert_eq!(result["ttlMs"], LIST_TTL_MS, "{method} must carry a ttl");
        }
    }

    #[test]
    fn test_cache_hints_helper_never_marks_a_result_public() {
        let mut result = json!({"contents": []});
        set_private_cache_hints(&mut result, RESOURCE_READ_TTL_MS, true);
        assert_eq!(result["cacheScope"], "private");
        assert_eq!(result["ttlMs"], 0);
    }

    // --- 2026-07-28: result envelope ---

    #[tokio::test]
    async fn test_results_carry_result_type_and_server_info() {
        for method in [
            "initialize",
            "tools/list",
            "prompts/list",
            "server/discover",
        ] {
            let req = JsonRpcRequest::new(1, method, None);
            let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
            let result = resp.result.unwrap();
            assert_eq!(
                result["resultType"],
                crate::protocol::RESULT_TYPE_COMPLETE,
                "{method} must declare a resultType"
            );
            assert_eq!(result["_meta"][meta_keys::SERVER_INFO]["name"], "mcp-proxy");
        }
    }

    /// The envelope is additive: everything a legacy client already read is
    /// still exactly where it was.
    #[tokio::test]
    async fn test_result_envelope_does_not_disturb_legacy_fields() {
        let mut server = test_server();
        server.tools.push(Tool {
            name: "sentry__search".to_string(),
            description: Some("[sentry] Search".to_string()),
            input_schema: Some(json!({"type": "object"})),
            annotations: None,
        });
        let req = JsonRpcRequest::new(1, "tools/list", None);
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        let result = resp.result.unwrap();
        assert_eq!(
            result["tools"],
            json!([{
                "name": "sentry__search",
                "description": "[sentry] Search",
                "inputSchema": {"type": "object"}
            }])
        );
    }

    #[tokio::test]
    async fn test_error_responses_get_no_result_envelope() {
        let req = JsonRpcRequest::new(1, "unknown/method", None);
        let resp = dispatch(test_server(), req, &AuthIdentity::anonymous(), &None).await;
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, error_codes::METHOD_NOT_FOUND);
    }

    // --- 2026-07-28: deterministic list ordering ---

    #[tokio::test]
    async fn test_tools_list_is_sorted_regardless_of_registration_order() {
        let mut server = test_server();
        for name in ["zeta__b", "alpha__z", "zeta__a", "alpha__a"] {
            server.tools.push(Tool {
                name: name.to_string(),
                description: None,
                input_schema: None,
                annotations: None,
            });
        }
        let req = JsonRpcRequest::new(1, "tools/list", None);
        let resp = dispatch(server, req, &AuthIdentity::anonymous(), &None).await;
        let result = resp.result.unwrap();
        let names: Vec<&str> = result["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alpha__a", "alpha__z", "zeta__a", "zeta__b"]);
    }

    #[tokio::test]
    async fn test_prompts_and_resources_lists_are_sorted() {
        let mut server = test_server();
        server.register_prompts(
            "zz",
            &[Prompt {
                name: "p".to_string(),
                description: None,
                arguments: None,
            }],
        );
        server.register_prompts(
            "aa",
            &[Prompt {
                name: "p".to_string(),
                description: None,
                arguments: None,
            }],
        );
        server.register_resources(
            "zz",
            &[Resource {
                uri: "r://1".to_string(),
                name: "r".to_string(),
                description: None,
                mime_type: None,
                annotations: None,
            }],
        );
        server.register_resources(
            "aa",
            &[Resource {
                uri: "r://1".to_string(),
                name: "r".to_string(),
                description: None,
                mime_type: None,
                annotations: None,
            }],
        );
        let proxy: SharedProxy = Arc::new(Mutex::new(server));
        let id = AuthIdentity::anonymous();

        let prompts = dispatch_request(
            &proxy,
            JsonRpcRequest::new(1, "prompts/list", None),
            &id,
            &None,
            "test",
            true,
        )
        .await
        .result
        .unwrap();
        assert_eq!(prompts["prompts"][0]["name"], "aa__p");

        let resources = dispatch_request(
            &proxy,
            JsonRpcRequest::new(2, "resources/list", None),
            &id,
            &None,
            "test",
            true,
        )
        .await
        .result
        .unwrap();
        assert_eq!(resources["resources"][0]["uri"], "aa__r://1");
    }

    // --- 2026-07-28: MRTR relay through the proxy ---

    /// Params every `tools/call` the stub backend saw, in order.
    type SeenParams = Arc<Mutex<Vec<Value>>>;

    /// Spawn a minimal MCP backend over HTTP that answers `tools/call` with
    /// an MRTR interim result until the client comes back with
    /// `inputResponses`. Returns its URL and the params it observed.
    async fn spawn_mrtr_backend() -> (String, SeenParams) {
        use axum::extract::State;
        use axum::routing::post;

        let seen: SeenParams = Arc::new(Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route(
                "/",
                post(|State(seen): State<SeenParams>, body: String| async move {
                    let msg: Value = serde_json::from_str(&body).unwrap();
                    let Some(id) = msg.get("id").cloned() else {
                        // notifications/initialized
                        return axum::Json(Value::Null);
                    };
                    let params = msg.get("params").cloned().unwrap_or(json!({}));
                    let result = match msg["method"].as_str().unwrap() {
                        "initialize" => json!({
                            "protocolVersion": crate::protocol::PROTOCOL_VERSION_LEGACY,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "stub", "version": "0"}
                        }),
                        // All three methods the spec allows an
                        // `InputRequiredResult` on behave identically here.
                        "tools/call" | "resources/read" | "prompts/get" => {
                            seen.lock().await.push(params.clone());
                            if let Some(responses) = params.get("inputResponses") {
                                json!({
                                    "resultType": "complete",
                                    "content": [{"type": "text", "text": responses.to_string()}],
                                    // A `resources/read` reply's real payload,
                                    // so URI namespacing stays exercised.
                                    "contents": [{"uri": "doc://1", "text": "body"}],
                                    "messages": [],
                                    "echoedState": params.get("requestState"),
                                })
                            } else {
                                json!({
                                    "resultType": "input_required",
                                    "inputRequests": [{"id": "confirm", "prompt": "sure?"}],
                                    "requestState": "opaque-token"
                                })
                            }
                        }
                        other => panic!("stub backend got unexpected method {other}"),
                    };
                    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
                }),
            )
            .with_state(Arc::clone(&seen));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/"), seen)
    }

    /// A backend whose `tools/call` result carries a **scalar** `_meta`.
    /// `_meta` is an object by spec, but a backend is not obliged to be
    /// correct, and a scalar there used to silently swallow the proxy's own
    /// serverInfo stamp.
    async fn spawn_scalar_meta_backend() -> (String, SeenParams) {
        use axum::extract::State;
        use axum::routing::post;

        let seen: SeenParams = Arc::new(Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route(
                "/",
                post(|State(seen): State<SeenParams>, body: String| async move {
                    let msg: Value = serde_json::from_str(&body).unwrap();
                    let Some(id) = msg.get("id").cloned() else {
                        return axum::Json(Value::Null);
                    };
                    let params = msg.get("params").cloned().unwrap_or(json!({}));
                    let result = match msg["method"].as_str().unwrap() {
                        "initialize" => json!({
                            "protocolVersion": crate::protocol::PROTOCOL_VERSION_LEGACY,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "stub", "version": "0"}
                        }),
                        "tools/call" => {
                            seen.lock().await.push(params.clone());
                            json!({
                                "content": [{"type": "text", "text": "hi"}],
                                "_meta": "scalar",
                            })
                        }
                        other => panic!("stub backend got unexpected method {other}"),
                    };
                    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
                }),
            )
            .with_state(Arc::clone(&seen));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/"), seen)
    }

    /// Install a live client for `stub` exposing one primitive of each kind,
    /// so every method the spec allows an `InputRequiredResult` on is
    /// reachable through the real dispatch path.
    async fn proxy_with_stub_backend(url: &str) -> SharedProxy {
        let client = Arc::new(McpClient::connect_via_proxy(url).await.unwrap());
        let mut server = test_server();
        server.install_client(
            "stub",
            client,
            &[Tool {
                name: "ask".to_string(),
                description: None,
                input_schema: None,
                annotations: None,
            }],
            &[Resource {
                uri: "doc://1".to_string(),
                name: "doc".to_string(),
                description: None,
                mime_type: None,
                annotations: None,
            }],
            &[Prompt {
                name: "brief".to_string(),
                description: None,
                arguments: None,
            }],
        );
        Arc::new(Mutex::new(server))
    }

    #[tokio::test]
    async fn test_mrtr_round_trip_relays_both_directions() {
        let (url, seen) = spawn_mrtr_backend().await;
        let proxy = proxy_with_stub_backend(&url).await;
        let identity = AuthIdentity::anonymous();

        // Leg 1: the backend asks for more input. The proxy must hand that
        // back untouched instead of failing to parse a result with no
        // `content`.
        let first = dispatch_request(
            &proxy,
            JsonRpcRequest::new(
                1,
                "tools/call",
                Some(json!({"name": "stub__ask", "arguments": {"q": "delete?"}})),
            ),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        assert!(first.error.is_none(), "MRTR interim result must not error");
        let interim = first.result.unwrap();
        assert!(crate::protocol::is_input_required(&interim));
        assert_eq!(interim["inputRequests"][0]["id"], "confirm");
        assert_eq!(interim["requestState"], "opaque-token");

        // Leg 2: the client retries the original request carrying its
        // answers plus the opaque state it was given.
        let second = dispatch_request(
            &proxy,
            JsonRpcRequest::new(
                2,
                "tools/call",
                Some(json!({
                    "name": "stub__ask",
                    "arguments": {"q": "delete?"},
                    "inputResponses": [{"id": "confirm", "value": true}],
                    "requestState": interim["requestState"],
                })),
            ),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        assert!(second.error.is_none());
        let final_result = second.result.unwrap();
        assert_eq!(
            final_result["resultType"],
            crate::protocol::RESULT_TYPE_COMPLETE
        );
        assert_eq!(final_result["echoedState"], "opaque-token");

        // And the backend really received the MRTR fields, un-namespaced.
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0]["name"], "ask");
        assert_eq!(seen[0]["arguments"]["q"], "delete?");
        assert!(seen[0].get("inputResponses").is_none());
        assert_eq!(seen[1]["name"], "ask");
        assert_eq!(seen[1]["arguments"]["q"], "delete?");
        assert_eq!(seen[1]["inputResponses"][0]["value"], true);
        assert_eq!(seen[1]["requestState"], "opaque-token");
    }

    /// The interim result is relayed verbatim — in particular the envelope
    /// stamping must not overwrite `input_required` with `complete`.
    #[tokio::test]
    async fn test_relayed_interim_result_keeps_its_result_type() {
        let (url, _seen) = spawn_mrtr_backend().await;
        let proxy = proxy_with_stub_backend(&url).await;
        let resp = dispatch_request(
            &proxy,
            JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "stub__ask"}))),
            &AuthIdentity::anonymous(),
            &None,
            "test",
            true,
        )
        .await;
        assert_eq!(
            resp.result.unwrap()["resultType"],
            crate::protocol::RESULT_TYPE_INPUT_REQUIRED
        );
    }

    // --- 2026-07-28: MRTR on resources/read and prompts/get ---

    /// The spec permits an `InputRequiredResult` on `resources/read` and
    /// `prompts/get` too. Parsing them eagerly turned a legal interim result
    /// into a -32603, and a retry's answers never reached the backend.
    #[tokio::test]
    async fn test_mrtr_round_trip_on_resources_read() {
        let (url, seen) = spawn_mrtr_backend().await;
        let proxy = proxy_with_stub_backend(&url).await;
        let identity = AuthIdentity::anonymous();

        let first = dispatch_request(
            &proxy,
            JsonRpcRequest::new(1, "resources/read", Some(json!({"uri": "stub__doc://1"}))),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        assert!(first.error.is_none(), "an interim result must not error");
        let interim = first.result.unwrap();
        assert!(crate::protocol::is_input_required(&interim));
        assert_eq!(interim["requestState"], "opaque-token");

        let second = dispatch_request(
            &proxy,
            JsonRpcRequest::new(
                2,
                "resources/read",
                Some(json!({
                    "uri": "stub__doc://1",
                    "inputResponses": {"confirm": {"action": "accept"}},
                    "requestState": interim["requestState"],
                })),
            ),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        assert!(second.error.is_none());
        let final_result = second.result.unwrap();
        assert_eq!(final_result["echoedState"], "opaque-token");
        // Namespacing still happens on the raw relay path.
        assert_eq!(final_result["contents"][0]["uri"], "stub__doc://1");

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 2);
        // Un-namespaced URI, and the retry carried the continuation.
        assert_eq!(seen[0]["uri"], "doc://1");
        assert!(seen[0].get("inputResponses").is_none());
        assert_eq!(seen[1]["uri"], "doc://1");
        assert_eq!(seen[1]["inputResponses"]["confirm"]["action"], "accept");
        assert_eq!(seen[1]["requestState"], "opaque-token");
    }

    #[tokio::test]
    async fn test_mrtr_round_trip_on_prompts_get() {
        let (url, seen) = spawn_mrtr_backend().await;
        let proxy = proxy_with_stub_backend(&url).await;
        let identity = AuthIdentity::anonymous();

        let first = dispatch_request(
            &proxy,
            JsonRpcRequest::new(
                1,
                "prompts/get",
                Some(json!({"name": "stub__brief", "arguments": {"topic": "x"}})),
            ),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        assert!(first.error.is_none(), "an interim result must not error");
        let interim = first.result.unwrap();
        assert!(crate::protocol::is_input_required(&interim));

        let second = dispatch_request(
            &proxy,
            JsonRpcRequest::new(
                2,
                "prompts/get",
                Some(json!({
                    "name": "stub__brief",
                    "arguments": {"topic": "x"},
                    "inputResponses": {"confirm": {"action": "accept"}},
                    "requestState": interim["requestState"],
                })),
            ),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        assert!(second.error.is_none());
        assert_eq!(second.result.unwrap()["echoedState"], "opaque-token");

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0]["name"], "brief");
        assert_eq!(seen[0]["arguments"]["topic"], "x");
        assert_eq!(seen[1]["inputResponses"]["confirm"]["action"], "accept");
        assert_eq!(seen[1]["requestState"], "opaque-token");
    }

    // --- 2026-07-28: the relay path is not the backend's megaphone ---

    /// A backend that dictates cache directives defeats the whole
    /// "never public" invariant: the proxy, not the backend, decides who may
    /// cache an ACL-gated answer.
    async fn spawn_hostile_backend() -> String {
        use axum::routing::post;

        let app = axum::Router::new().route(
            "/",
            post(|body: String| async move {
                let msg: Value = serde_json::from_str(&body).unwrap();
                let Some(id) = msg.get("id").cloned() else {
                    return axum::Json(Value::Null);
                };
                let result = match msg["method"].as_str().unwrap() {
                    "initialize" => json!({
                        "protocolVersion": crate::protocol::PROTOCOL_VERSION_LEGACY,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "hostile", "version": "0"}
                    }),
                    _ => json!({
                        "resultType": "definitely-not-a-real-result-type",
                        "cacheScope": "public",
                        "ttlMs": 86_400_000u64,
                        "content": [{"type": "text", "text": "ok"}],
                        "contents": [{"uri": "doc://1", "text": "body"}],
                        // Unknown/extension fields must survive untouched.
                        "structuredContent": {"rows": [1, 2]},
                        "isError": false,
                        "_meta": {
                            crate::protocol::meta_keys::SERVER_INFO:
                                {"name": "totally-the-proxy", "version": "9.9.9"}
                        },
                    }),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn test_backend_cannot_dictate_cache_hints_or_identity() {
        let url = spawn_hostile_backend().await;
        let proxy = proxy_with_stub_backend(&url).await;
        let identity = AuthIdentity::anonymous();

        let call = dispatch_request(
            &proxy,
            JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "stub__ask"}))),
            &identity,
            &None,
            "test",
            true,
        )
        .await
        .result
        .unwrap();
        // `tools/call` is not a CacheableResult, so no hints at all.
        assert!(call.get("cacheScope").is_none());
        assert!(call.get("ttlMs").is_none());
        // An unrecognized resultType is normalized, never relayed.
        assert_eq!(call["resultType"], crate::protocol::RESULT_TYPE_COMPLETE);
        // Identity is ours, not whatever the backend claimed.
        assert_eq!(call["_meta"][meta_keys::SERVER_INFO]["name"], "mcp-proxy");
        // Everything else still passes through.
        assert_eq!(call["structuredContent"]["rows"][1], 2);
        assert_eq!(call["isError"], false);
        assert_eq!(call["content"][0]["text"], "ok");

        // `resources/read` is cacheable — the proxy re-stamps its own hints
        // over the backend's.
        let read = dispatch_request(
            &proxy,
            JsonRpcRequest::new(2, "resources/read", Some(json!({"uri": "stub__doc://1"}))),
            &identity,
            &None,
            "test",
            true,
        )
        .await
        .result
        .unwrap();
        assert_eq!(read["cacheScope"], "private");
        assert_eq!(read["ttlMs"], RESOURCE_READ_TTL_MS);
        assert_eq!(read["structuredContent"]["rows"][0], 1);

        let get = dispatch_request(
            &proxy,
            JsonRpcRequest::new(3, "prompts/get", Some(json!({"name": "stub__brief"}))),
            &identity,
            &None,
            "test",
            true,
        )
        .await
        .result
        .unwrap();
        assert!(get.get("cacheScope").is_none());
        assert!(get.get("ttlMs").is_none());
        assert_eq!(get["resultType"], crate::protocol::RESULT_TYPE_COMPLETE);
    }

    /// The sanitizer must not be able to swallow a genuine MRTR interim
    /// result — that is the one `resultType` a client has to see.
    #[test]
    fn test_sanitize_keeps_input_required_and_strips_cache_hints() {
        let interim = json!({
            "resultType": "input_required",
            "inputRequests": {"confirm": {}},
            "requestState": "opaque",
            "cacheScope": "public",
            "ttlMs": 999,
        });
        // Preserved for BOTH kinds of peer: dropping it would report an
        // unfinished exchange as finished.
        for stateless_peer in [true, false] {
            let mut interim = interim.clone();
            sanitize_relayed_result(&mut interim, stateless_peer);
            assert_eq!(
                interim["resultType"],
                crate::protocol::RESULT_TYPE_INPUT_REQUIRED,
                "stateless_peer={stateless_peer}"
            );
            assert_eq!(interim["requestState"], "opaque");
            // Cache directives are never the backend's to write, whoever asked.
            assert!(interim.get("cacheScope").is_none());
            assert!(interim.get("ttlMs").is_none());
        }

        // A pre-2026-07-28 backend omits the field entirely; that reads as
        // `complete`, exactly as it always did.
        let mut legacy = json!({"content": [{"type": "text", "text": "hi"}]});
        sanitize_relayed_result(&mut legacy, true);
        assert_eq!(legacy["resultType"], crate::protocol::RESULT_TYPE_COMPLETE);
        assert_eq!(legacy["content"][0]["text"], "hi");

        // Non-object results must not panic.
        let mut scalar = json!("nope");
        sanitize_relayed_result(&mut scalar, true);
        assert_eq!(scalar, json!("nope"));
    }

    /// Finding 7: a backend that answers with a scalar `_meta` must not be
    /// able to suppress the proxy's own serverInfo. `set_result_meta` refuses
    /// to write into a non-object, so without normalization the client got the
    /// backend's scalar and no serverInfo at all.
    #[tokio::test]
    async fn test_backend_scalar_meta_cannot_suppress_the_server_info_stamp() {
        let (url, _seen) = spawn_scalar_meta_backend().await;
        let proxy = proxy_with_stub_backend(&url).await;
        let resp = dispatch_request(
            &proxy,
            JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "stub__ask"}))),
            &AuthIdentity::anonymous(),
            &None,
            "test",
            true,
        )
        .await;
        let result = resp.result.expect("the call succeeded");
        assert_eq!(
            result["_meta"][meta_keys::SERVER_INFO]["name"],
            "mcp-proxy",
            "the backend's scalar _meta swallowed the stamp: {result}"
        );
        assert_eq!(result["content"][0]["text"], "hi");
    }

    /// Finding 2: a peer that never declared 2026-07-28 must not receive the
    /// fields that revision added. Two extra keys are not "inert" — the peer
    /// negotiated a revision in which they do not exist.
    #[tokio::test]
    async fn test_legacy_peer_gets_no_result_envelope_or_cache_hints() {
        for method in ["initialize", "tools/list", "prompts/list", "resources/list"] {
            let req = JsonRpcRequest::new(1, method, None);
            let result = dispatch_as(test_server(), req, &AuthIdentity::anonymous(), &None, false)
                .await
                .result
                .expect("{method} succeeded");
            for field in ["resultType", "ttlMs", "cacheScope"] {
                assert!(
                    result.get(field).is_none(),
                    "{method} sent a legacy peer a {field}: {result}"
                );
            }
            assert!(
                result
                    .get("_meta")
                    .and_then(|m| m.get(meta_keys::SERVER_INFO))
                    .is_none(),
                "{method} sent a legacy peer _meta.serverInfo: {result}"
            );
        }
    }

    /// What each transport hands `dispatch_request` as `stateless_peer`.
    /// `server/discover` did not exist before 2026-07-28, so a peer calling it
    /// is a 2026-07-28 peer whether or not it spelled the version out — and
    /// its result is required to carry the envelope.
    #[test]
    fn test_body_declares_stateless_reads_meta_and_the_discover_method() {
        let bare = |m: &str| JsonRpcRequest::new(1, m, None);
        let versioned = |v: &str| {
            JsonRpcRequest::new(
                1,
                "tools/list",
                Some(json!({"_meta": {meta_keys::PROTOCOL_VERSION: v}})),
            )
        };

        assert!(body_declares_stateless(&bare("server/discover")));
        assert!(body_declares_stateless(&versioned(
            crate::protocol::PROTOCOL_VERSION
        )));

        assert!(!body_declares_stateless(&bare("tools/list")));
        assert!(!body_declares_stateless(&bare("initialize")));
        assert!(!body_declares_stateless(&versioned(
            crate::protocol::PROTOCOL_VERSION_LEGACY
        )));
        assert!(!body_declares_stateless(&versioned("2024-11-05")));
        // A later date we do not speak must not buy 2026-07-28 semantics:
        // `is_stateless_version` is an ordering test, not a membership one.
        assert!(!body_declares_stateless(&versioned("2099-01-01")));
    }

    #[test]
    fn test_namespace_resource_contents_only_rewrites_the_uri_it_read() {
        let mut result = json!({
            "contents": [
                {"uri": "doc://1", "text": "a"},
                {"uri": "doc://other", "text": "b"},
                "not-an-object"
            ]
        });
        namespace_resource_contents(&mut result, "stub", "doc://1");
        assert_eq!(result["contents"][0]["uri"], "stub__doc://1");
        assert_eq!(result["contents"][1]["uri"], "doc://other");

        // An interim result has no `contents` at all — absence is normal.
        let mut interim = json!({"resultType": "input_required"});
        namespace_resource_contents(&mut interim, "stub", "doc://1");
        assert!(interim.get("contents").is_none());
    }

    /// A relayed continuation is still a privileged call. The audit entry has
    /// to say the request resumed an MRTR exchange, without ever recording
    /// the answers themselves.
    #[tokio::test]
    async fn test_mrtr_continuation_is_recorded_in_the_audit_entry() {
        let (url, _seen) = spawn_mrtr_backend().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let client = Arc::new(McpClient::connect_via_proxy(&url).await.unwrap());
        let mut server = ProxyServer::new(
            Arc::new(AuditLogger::Stream { sender: tx }),
            HashMap::new(),
            HashMap::new(),
            ToolCacheStore::new(Arc::new(crate::db::DbPool::disabled())),
        );
        server.install_client(
            "stub",
            client,
            &[Tool {
                name: "ask".to_string(),
                description: None,
                input_schema: None,
                annotations: None,
            }],
            &[],
            &[],
        );
        let proxy: SharedProxy = Arc::new(Mutex::new(server));
        let identity = AuthIdentity::anonymous();

        // A plain call is not a continuation and records nothing.
        dispatch_request(
            &proxy,
            JsonRpcRequest::new(1, "tools/call", Some(json!({"name": "stub__ask"}))),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        assert!(rx.recv().await.unwrap().arguments.is_none());

        // The retry is, and it must stay attributable as one.
        dispatch_request(
            &proxy,
            JsonRpcRequest::new(
                2,
                "tools/call",
                Some(json!({
                    "name": "stub__ask",
                    "inputResponses": {"confirm": {"secret": "hunter2"}},
                    "requestState": "opaque",
                })),
            ),
            &identity,
            &None,
            "test",
            true,
        )
        .await;
        let recorded = rx
            .recv()
            .await
            .unwrap()
            .arguments
            .expect("continuation must be recorded");
        assert_eq!(
            recorded,
            json!({"mrtrContinuation": ["inputResponses", "requestState"]})
        );
        // Never the payload itself — those answers routinely hold secrets.
        assert!(!recorded.to_string().contains("hunter2"));
    }
}
