//! OAuth 2.0 Authorization Server with Dynamic Client Registration
//! (RFC 7591) for `mcp serve`.
//!
//! Lets `mcp serve` be plugged directly into Claude.ai, ChatGPT, Cursor
//! and other AI clients that consume MCP authorization (spec 2025-06-18)
//! without an external OAuth provider in front.
//!
//! Public surface:
//! - [`OAuthAsConfig`] — JSON config under `serverAuth.oauthAs`.
//!
//! Module layout (built incrementally across the issue #90 tasks):
//! - `config` — [`OAuthAsConfig`] + boot-time validation.
//! - Other components (state, store, jwt, handlers, provider) land in
//!   their own files as the implementation tasks progress; declared
//!   here once they exist.

mod authorize;
mod cidr;
mod config;
mod jwt;
mod metadata;
mod provider;
mod redirect_uri;
mod register;
mod state;
mod store;
mod token;
mod types;

#[cfg(test)]
mod e2e_tests;

pub use config::OAuthAsConfig;
pub use provider::OAuthAsAuth;
pub use state::AsState;
pub use store::{load as load_state, save as save_state};

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};

/// Build the axum sub-router that exposes all OAuth AS endpoints.
/// Mounted under the root path of `mcp serve` so the well-known
/// discovery URLs land at `/.well-known/...` as RFC 8414 / RFC 9728
/// require.
pub fn router(config: Arc<OAuthAsConfig>, state: Arc<AsState>) -> Router {
    // The metadata handlers only need the config, so they get a
    // narrower state. The token / register / authorize handlers
    // need both, bundled in `register::AppCtx`.
    let app_ctx = Arc::new(register::AppCtx {
        config: config.clone(),
        state,
    });

    let metadata_router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server),
        )
        .with_state(config);

    let flow_router = Router::new()
        .route("/register", post(register::register))
        .route("/authorize", get(authorize::authorize))
        .route("/token", post(token::token))
        .with_state(app_ctx);

    metadata_router.merge(flow_router)
}
