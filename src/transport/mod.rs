pub mod cli;
pub mod http;
pub mod stdio;

use anyhow::Result;
use async_trait::async_trait;

use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};

/// Transport trait — all methods take `&self` so a single transport instance
/// can be shared across many concurrent requests via `Arc`. Implementations
/// must use interior mutability (channels, atomics, mutexes) for any state
/// they need to mutate.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn request(&self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse>;
    async fn notify(&self, msg: &JsonRpcNotification) -> Result<()>;
    async fn close(&self) -> Result<()>;

    /// Send a request, mirroring `extra_headers` into whatever native header
    /// mechanism the transport has.
    ///
    /// This exists for the 2026-07-28 `x-mcp-header` feature, where annotated
    /// `tools/call` arguments become `Mcp-Param-{Name}` HTTP headers. The
    /// headers are computed by the client (only it has seen the tool's
    /// `inputSchema`) and handed down per request, so nothing about them is
    /// shared state between concurrent calls.
    ///
    /// Default: drop them and send the request as-is. Only Streamable HTTP has
    /// headers to mirror into, and the spec explicitly lets other transports
    /// ignore `x-mcp-header` annotations entirely.
    async fn request_with_headers(
        &self,
        msg: &JsonRpcRequest,
        extra_headers: &[(String, String)],
    ) -> Result<JsonRpcResponse> {
        let _ = extra_headers;
        self.request(msg).await
    }

    /// Tell the transport which protocol revision the client negotiated.
    ///
    /// Default no-op: only Streamable HTTP changes wire behavior across
    /// revisions (2026-07-28 removed `Mcp-Session-Id`). Until this is
    /// called — and forever, for stdio and cli — transports keep their
    /// pre-2026-07-28 behavior, which is what every current backend
    /// expects.
    fn set_protocol_version(&self, _version: &str) {}
}
