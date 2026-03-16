use anyhow::{bail, Context, Result};
use std::io::Write;

use super::store::{self, StoredTokens};

struct AuthHint {
    name: &'static str,
    token_url: &'static str,
    token_name: &'static str,
    instructions: &'static str,
}

const AUTH_HINTS: &[AuthHint] = &[
    AuthHint {
        name: "honeycomb",
        token_url: "https://ui.honeycomb.io/account",
        token_name: "Honeycomb API Key",
        instructions: "Go to Account → API Keys → Create API Key",
    },
    AuthHint {
        name: "github",
        token_url: "https://github.com/settings/tokens",
        token_name: "GitHub Personal Access Token",
        instructions: "Create a Fine-grained token with the scopes you need",
    },
    AuthHint {
        name: "sentry",
        token_url: "https://sentry.io/settings/account/api/auth-tokens/",
        token_name: "Sentry Auth Token",
        instructions: "Create a token with org:read, project:read scopes",
    },
    AuthHint {
        name: "linear",
        token_url: "https://linear.app/settings/api",
        token_name: "Linear API Key",
        instructions: "Settings → API → Personal API Keys → Create Key",
    },
    AuthHint {
        name: "notion",
        token_url: "https://www.notion.so/my-integrations",
        token_name: "Notion Integration Token",
        instructions: "Create an internal integration and copy the secret",
    },
    AuthHint {
        name: "slack",
        token_url: "https://api.slack.com/apps",
        token_name: "Slack Bot/User Token (xoxb-/xoxp-)",
        instructions: "Go to your app → OAuth & Permissions → Copy the token",
    },
    AuthHint {
        name: "grafana",
        token_url: "https://grafana.com/docs/grafana/latest/administration/service-accounts/",
        token_name: "Grafana Service Account Token",
        instructions: "Administration → Service Accounts → Add token",
    },
    AuthHint {
        name: "gitlab",
        token_url: "https://gitlab.com/-/user_settings/personal_access_tokens",
        token_name: "GitLab Personal Access Token",
        instructions: "Create a token with api scope",
    },
    AuthHint {
        name: "jira",
        token_url: "https://id.atlassian.com/manage-profile/security/api-tokens",
        token_name: "Atlassian API Token",
        instructions: "Create an API token (use email:token as Basic auth or token as Bearer)",
    },
    AuthHint {
        name: "cloudflare",
        token_url: "https://dash.cloudflare.com/profile/api-tokens",
        token_name: "Cloudflare API Token",
        instructions: "Create a custom token with the permissions you need",
    },
    AuthHint {
        name: "datadog",
        token_url: "https://app.datadoghq.com/organization-settings/api-keys",
        token_name: "Datadog API Key",
        instructions: "Organization Settings → API Keys → New Key",
    },
    AuthHint {
        name: "pagerduty",
        token_url: "https://support.pagerduty.com/main/docs/api-access-keys",
        token_name: "PagerDuty API Key",
        instructions: "User Settings → Create API User Token",
    },
];

fn find_auth_hint(server_url: &str) -> Option<&'static AuthHint> {
    let url_lower = server_url.to_lowercase();
    AUTH_HINTS
        .iter()
        .find(|h| url_lower.contains(h.name))
}

/// Prompt user for a token and store it.
pub fn prompt_for_token(server_url: &str) -> Result<String> {
    let key = store::server_key(server_url);

    if let Some(hint) = find_auth_hint(server_url) {
        eprintln!("This server requires a {}.", hint.token_name);
        eprintln!();
        eprintln!("  How: {}", hint.instructions);
        eprintln!("  URL: {}", hint.token_url);
        eprintln!();
    } else {
        eprintln!("This server requires a Bearer token for authentication.");
        eprintln!();
    }

    eprintln!("Enter access token for {key}:");
    eprint!("> ");
    std::io::stderr().flush().context("failed to flush stderr")?;

    let mut token = String::new();
    std::io::stdin()
        .read_line(&mut token)
        .context("failed to read token from stdin")?;
    let token = token.trim().to_string();

    if token.is_empty() {
        bail!("no token provided");
    }

    let mut auth_store = store::load_auth_store()?;
    auth_store.tokens.insert(
        key,
        StoredTokens {
            access_token: token.clone(),
            refresh_token: None,
            expires_at: None,
        },
    );
    store::save_auth_store(&auth_store)?;

    eprintln!("Token saved.");
    Ok(token)
}
