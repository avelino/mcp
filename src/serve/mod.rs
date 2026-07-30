mod discovery;
mod dispatch;
/// End-to-end coverage of the 2026-07-28 wire contract the seam tests do not
/// reach: HTTP status codes, sentinel decoding, discovery shape.
#[cfg(test)]
mod e2e_conformance_tests;
/// End-to-end coverage of the client/serve seam: stateless negotiation, the
/// legacy path, MRTR relay.
#[cfg(test)]
mod e2e_tests;
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
