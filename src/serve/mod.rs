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
mod reload;
#[cfg(test)]
mod reload_tests;
mod stdio;
pub(crate) mod team;

use crate::config::Config;
use crate::instances::InstanceFilter;
use anyhow::Result;

pub use http::run_http;
pub use stdio::run_stdio;

/// `config` arrives already narrowed by `filter`; the filter travels alongside
/// it so a reload can re-apply the same narrowing to the config it re-reads.
pub async fn run(
    config: Config,
    http_addr: Option<&str>,
    insecure: bool,
    filter: InstanceFilter,
    management: bool,
    cookie_secure: bool,
) -> Result<()> {
    match http_addr {
        Some(addr) => run_http(config, addr, insecure, filter, management, cookie_secure).await,
        None => {
            if management {
                anyhow::bail!(
                    "--management needs `--http`: the UI is served over HTTP, not over the MCP stdio pipe"
                );
            }
            run_stdio(config, filter).await
        }
    }
}
