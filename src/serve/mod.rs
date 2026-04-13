mod discovery;
mod dispatch;
mod http;
pub(crate) mod proxy;
mod stdio;

use crate::config::Config;
use anyhow::Result;

pub use http::run_http;
pub use stdio::run_stdio;

pub async fn run(config: Config, http_addr: Option<&str>, insecure: bool) -> Result<()> {
    match http_addr {
        Some(addr) => run_http(config, addr, insecure).await,
        None => run_stdio(config).await,
    }
}
