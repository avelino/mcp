pub mod http;
pub mod stdio;

use anyhow::Result;
use async_trait::async_trait;

use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};

#[async_trait]
pub trait Transport: Send {
    async fn request(&mut self, msg: &JsonRpcRequest) -> Result<JsonRpcResponse>;
    async fn notify(&mut self, msg: &JsonRpcNotification) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}
