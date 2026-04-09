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
}
