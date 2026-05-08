use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::audit::{AuditEntry, AuditLogger};
use crate::client::McpClient;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::server_auth::{self, AclConfig, AuthIdentity};

use super::discovery::{connect_backend, discover_pending_backends, discover_single_backend};
use super::proxy::{
    infer_backend_name, ResolvedCall, ResolvedPromptGet, ResolvedResourceRead, SharedProxy,
    SEPARATOR,
};

/// Whether to discover all pending backends, a single one, or none.
enum DiscoveryAction {
    None,
    Single(String),
    All,
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
) -> JsonRpcResponse {
    let start = std::time::Instant::now();
    let method = req.method.clone();
    let id = req.id.clone();

    // Audit metadata captured outside the lock.
    let audit_logger: Arc<AuditLogger>;
    let mut tool_name_for_audit: Option<String> = None;
    let mut server_name_for_audit: Option<String> = None;
    let mut decision_for_audit: Option<server_auth::Decision> = None;

    let response = match req.method.as_str() {
        "initialize" => {
            let p = proxy.lock().await;
            audit_logger = Arc::clone(&p.audit);
            p.handle_initialize(id)
        }
        "tools/list" => {
            // Decide whether to trigger discovery, then drop the proxy lock
            // before doing any I/O. Discovery is serialized via the separate
            // discovery_lock inside discover_pending_backends.
            let needs_discovery = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                p.tools.is_empty() && p.has_undiscovered_backends()
            };
            if needs_discovery {
                discover_pending_backends(proxy).await;
            }
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
                    list_audit.log(AuditEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        source: source.to_string(),
                        method: "tools/list:filtered".to_string(),
                        tool_name: Some(t.name.clone()),
                        server_name: srv,
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
                        classification_kind: decision
                            .classification_kind
                            .map(|k| k.as_str().to_string()),
                        classification_source: decision
                            .classification_source
                            .map(|s| s.as_str().to_string()),
                        classification_confidence: decision.classification_confidence,
                    });
                }
            }
            let tools_snapshot = tools_allowed;
            JsonRpcResponse::success(id, json!({ "tools": tools_snapshot }))
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
            let resolved: std::result::Result<ResolvedCall, JsonRpcResponse> = {
                let mut p = proxy.lock().await;
                match p.resolve_tool_call(&id, req.params.clone(), identity, acl) {
                    Ok((server, orig, args, decision)) => {
                        let client = p.try_get_client(&server);
                        // Refine the audit entry now that we know the
                        // namespaced tool resolves to a real backend.
                        tool_name_for_audit = Some(format!("{server}{SEPARATOR}{orig}"));
                        server_name_for_audit = Some(server.clone());
                        // Fill the OTel span attributes now that resolution
                        // succeeded — Empty fields are no-ops when telemetry
                        // is off, so this is safe to do unconditionally.
                        let span = tracing::Span::current();
                        span.record("mcp.server", server.as_str());
                        span.record("mcp.tool", orig.as_str());
                        Ok((server, orig, args, client, decision))
                    }
                    Err((maybe_decision, resp)) => {
                        decision_for_audit = maybe_decision;
                        Err(resp)
                    }
                }
            };

            match resolved {
                Err(resp) => resp,
                Ok((server, original, args, maybe_client, acl_decision)) => {
                    decision_for_audit = Some(acl_decision);
                    // Phase 2: ensure connected (without holding the proxy
                    // lock during the connect itself).
                    let client_result: Result<Arc<McpClient>> = match maybe_client {
                        Some(c) => Ok(c),
                        None => connect_backend(proxy, &server).await,
                    };

                    match client_result {
                        Err(e) => JsonRpcResponse::error(
                            id,
                            -32603,
                            &format!("failed to connect to backend '{server}': {e:#}"),
                        ),
                        Ok(client) => {
                            // Phase 3: invoke the backend with NO proxy lock held.
                            match client.call_tool(&original, args).await {
                                Ok(result) => JsonRpcResponse::success(
                                    id,
                                    serde_json::to_value(&result).unwrap(),
                                ),
                                Err(e) => {
                                    JsonRpcResponse::error(id, -32603, &format!("[{server}] {e:#}"))
                                }
                            }
                        }
                    }
                }
            }
        }
        "resources/list" => {
            let needs_discovery = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                p.resources.is_empty() && p.has_undiscovered_backends()
            };
            if needs_discovery {
                discover_pending_backends(proxy).await;
            }
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
                    list_audit.log(AuditEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        source: source.to_string(),
                        method: "resources/list:filtered".to_string(),
                        tool_name: Some(r.uri.clone()),
                        server_name: srv,
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
                        classification_kind: None,
                        classification_source: None,
                        classification_confidence: None,
                    });
                }
            }
            JsonRpcResponse::success(id, json!({ "resources": resources_allowed }))
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
                        },
                        JsonRpcResponse::error(id, -32602, "missing required parameter: uri"),
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
                                -32603,
                                &format!(
                                    "access denied: resource '{}' on server '{}'",
                                    original_uri, server
                                ),
                            ))
                        } else {
                            let server = server.clone();
                            let original = original_uri.clone();
                            let client = p.try_get_client(&server);
                            server_name_for_audit = Some(server.clone());
                            Ok((server, original, client, decision))
                        }
                    }
                    None => Err(JsonRpcResponse::error(
                        id.clone(),
                        -32602,
                        &format!("unknown resource: {uri}"),
                    )),
                }
            };

            match resolved {
                Err(resp) => resp,
                Ok((server, original_uri, maybe_client, acl_decision)) => {
                    decision_for_audit = Some(acl_decision);
                    let client_result: Result<Arc<McpClient>> = match maybe_client {
                        Some(c) => Ok(c),
                        None => connect_backend(proxy, &server).await,
                    };
                    match client_result {
                        Err(e) => JsonRpcResponse::error(
                            id,
                            -32603,
                            &format!("failed to connect to backend '{server}': {e:#}"),
                        ),
                        Ok(client) => match client.read_resource(&original_uri).await {
                            Ok(mut result) => {
                                // Rewrite content URIs to namespaced form so the
                                // client sees the same URI it requested.
                                let namespaced_uri = format!("{server}{SEPARATOR}{original_uri}");
                                for content in &mut result.contents {
                                    if content.uri == original_uri {
                                        content.uri = namespaced_uri.clone();
                                    }
                                }
                                JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
                            }
                            Err(e) => {
                                JsonRpcResponse::error(id, -32603, &format!("[{server}] {e:#}"))
                            }
                        },
                    }
                }
            }
        }
        "prompts/list" => {
            let needs_discovery = {
                let p = proxy.lock().await;
                audit_logger = Arc::clone(&p.audit);
                p.prompts.is_empty() && p.has_undiscovered_backends()
            };
            if needs_discovery {
                discover_pending_backends(proxy).await;
            }
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
                    list_audit.log(AuditEntry {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        source: source.to_string(),
                        method: "prompts/list:filtered".to_string(),
                        tool_name: Some(pr.name.clone()),
                        server_name: srv,
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
                        classification_kind: None,
                        classification_source: None,
                        classification_confidence: None,
                    });
                }
            }
            JsonRpcResponse::success(id, json!({ "prompts": prompts_allowed }))
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
                        },
                        JsonRpcResponse::error(id, -32602, "missing required parameter: name"),
                    );
                }
            };

            let arguments = req
                .params
                .as_ref()
                .and_then(|v| v.get("arguments"))
                .cloned();

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
                                -32603,
                                &format!(
                                    "access denied: prompt '{}' on server '{}'",
                                    original_name, server
                                ),
                            ))
                        } else {
                            let server = server.clone();
                            let original = original_name.clone();
                            let client = p.try_get_client(&server);
                            server_name_for_audit = Some(server.clone());
                            Ok((server, original, arguments, client, decision))
                        }
                    }
                    None => Err(JsonRpcResponse::error(
                        id.clone(),
                        -32602,
                        &format!("unknown prompt: {prompt_name}"),
                    )),
                }
            };

            match resolved {
                Err(resp) => resp,
                Ok((server, original_name, args, maybe_client, acl_decision)) => {
                    decision_for_audit = Some(acl_decision);
                    let client_result: Result<Arc<McpClient>> = match maybe_client {
                        Some(c) => Ok(c),
                        None => connect_backend(proxy, &server).await,
                    };
                    match client_result {
                        Err(e) => JsonRpcResponse::error(
                            id,
                            -32603,
                            &format!("failed to connect to backend '{server}': {e:#}"),
                        ),
                        Ok(client) => match client.get_prompt(&original_name, args).await {
                            Ok(result) => {
                                JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap())
                            }
                            Err(e) => {
                                JsonRpcResponse::error(id, -32603, &format!("[{server}] {e:#}"))
                            }
                        },
                    }
                }
            }
        }
        _ => {
            let p = proxy.lock().await;
            audit_logger = Arc::clone(&p.audit);
            JsonRpcResponse::error(id, -32601, &format!("method not found: {}", req.method))
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
        },
        response,
    )
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
}

pub(crate) fn finish_audit(ctx: AuditCtx<'_>, response: JsonRpcResponse) -> JsonRpcResponse {
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
        if let Some(tool) = ctx.tool_name.as_ref() {
            labels.push(opentelemetry::KeyValue::new("mcp.tool", tool.clone()));
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
        arguments: None,
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
    /// through the production `dispatch_request` path.
    async fn dispatch(
        server: ProxyServer,
        req: JsonRpcRequest,
        identity: &AuthIdentity,
        acl: &Option<AclConfig>,
    ) -> JsonRpcResponse {
        let proxy: SharedProxy = Arc::new(Mutex::new(server));
        dispatch_request(&proxy, req, identity, acl, "test").await
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
        assert_eq!(crate::protocol::PROTOCOL_VERSION, "2025-11-25");
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
}
