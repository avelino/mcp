//! Who is looking at the page.
//!
//! The local UI has exactly one viewer: the person who started it, with the
//! same authority as their shell. In team mode the proxy authenticates the
//! browser the same way it authenticates `/mcp` requests, and the viewer
//! decides three things: which tools are listed, whose audit entries are
//! visible, and whether writes are allowed.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::server_auth::AuthIdentity;

#[derive(Clone, Debug, Default)]
pub struct Viewer {
    /// `None` for the local UI: no identity was ever asserted.
    pub identity: Option<AuthIdentity>,
    /// True when the identity holds a role from `serverAuth.adminRoles`.
    pub admin: bool,
}

impl Viewer {
    /// The person who ran `mcp ui`. As powerful as their shell, and the UI
    /// says so.
    pub fn local() -> Self {
        Self {
            identity: None,
            admin: true,
        }
    }

    pub fn team(identity: AuthIdentity, admin: bool) -> Self {
        Self {
            identity: Some(identity),
            admin,
        }
    }

    pub fn is_local(&self) -> bool {
        self.identity.is_none()
    }

    pub fn subject(&self) -> &str {
        self.identity
            .as_ref()
            .map(|i| i.subject.as_str())
            .unwrap_or("local")
    }

    /// Whether this viewer may change the configuration file.
    pub fn can_write(&self) -> bool {
        self.admin
    }
}

/// Extractor that always yields a viewer.
///
/// The team guard inserts one into the request extensions; without it (the
/// local UI) the fallback is the local viewer. Keeping the fallback here means
/// the local routes need no middleware at all.
pub struct CurrentViewer(pub Viewer);

impl<S> FromRequestParts<S> for CurrentViewer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(CurrentViewer(
            parts
                .extensions
                .get::<Viewer>()
                .cloned()
                .unwrap_or_else(Viewer::local),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_viewer_can_write_and_has_no_identity() {
        let viewer = Viewer::local();
        assert!(viewer.is_local());
        assert!(viewer.can_write());
        assert_eq!(viewer.subject(), "local");
    }

    #[test]
    fn team_viewer_is_limited_by_admin_role() {
        let reader = Viewer::team(AuthIdentity::new("bob", vec!["dev".into()]), false);
        assert!(!reader.can_write());
        assert_eq!(reader.subject(), "bob");

        let admin = Viewer::team(AuthIdentity::new("alice", vec!["admin".into()]), true);
        assert!(admin.can_write());
    }

    #[test]
    fn anonymous_identity_is_still_an_identity() {
        let viewer = Viewer::team(AuthIdentity::anonymous(), false);
        assert!(!viewer.is_local());
        assert_eq!(viewer.subject(), "anonymous");
    }
}
