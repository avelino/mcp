//! Persistent state shapes for the OAuth Authorization Server.
//!
//! These structs are what the AS persists across restarts (registered
//! clients, refresh tokens) plus what lives only in memory between
//! `/authorize` and `/token` (authorization codes). JWT access tokens
//! are stateless — they don't appear here.

use serde::{Deserialize, Serialize};

/// A client registered via `POST /register` (RFC 7591 Dynamic Client
/// Registration). Public clients only — no `client_secret` is issued
/// because PKCE replaces the need for one (and Claude.ai and other
/// MCP-aware clients are public clients anyway).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    /// Unix seconds when the registration happened. Useful for
    /// expiring stale clients in a future cleanup pass; for v1 it is
    /// purely informational.
    pub created_at_unix: u64,
}

/// One-shot authorization code emitted by `/authorize` and consumed
/// at `/token`. Lives only in memory (TTL ~60s) — it is intentionally
/// not part of the on-disk store, so a restart simply drops in-flight
/// authorizations rather than letting an attacker replay a captured
/// code post-restart.
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: Option<String>,
    pub subject: String,
    pub roles: Vec<String>,
    pub expires_at_unix: u64,
}

/// A long-lived refresh token. Persisted so refresh works across
/// restarts (Claude.ai will hold a refresh token for ~30 days).
/// Rotation: every successful refresh invalidates the previous token
/// and issues a new one, so capture-and-replay buys a single use at
/// most.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedRefreshToken {
    pub token: String,
    pub client_id: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub expires_at_unix: u64,
}

/// Claims serialized into the JWT access token. Names follow standard
/// JWT / OIDC conventions so existing tooling can introspect tokens
/// without custom logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer — must match the AS issuerUrl on verification.
    pub iss: String,
    /// Audience — the `client_id` the token was issued for. Single
    /// value; arrays are not supported in v1.
    pub aud: String,
    /// Subject — the authenticated user (from the trusted header at
    /// `/authorize` time).
    pub sub: String,
    /// Groups / roles. Becomes `AuthIdentity.roles` after validation.
    /// Empty vec serializes as `[]` rather than being omitted, so
    /// downstream consumers don't have to special-case "no roles".
    pub groups: Vec<String>,
    /// Expiry (unix seconds).
    pub exp: u64,
    /// Not-before (unix seconds).
    pub nbf: u64,
    /// Issued at (unix seconds).
    pub iat: u64,
    /// Unique token id — useful for audit trails and future revocation.
    pub jti: String,
}
