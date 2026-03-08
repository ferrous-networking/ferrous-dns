use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::instrument;

use ferrous_dns_domain::Config;

/// Returns authentication status info (no auth required to call).
///
/// Reads from the live `Config` so changes (e.g. password setup) are
/// visible immediately without server restart.
pub struct GetAuthStatusUseCase {
    config: Arc<RwLock<Config>>,
}

impl GetAuthStatusUseCase {
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        Self { config }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self) -> AuthStatus {
        let config = self.config.read().await;
        let password_configured = config
            .auth
            .admin
            .password_hash
            .as_ref()
            .map(|h| !h.is_empty())
            .unwrap_or(false);

        AuthStatus {
            auth_enabled: config.auth.enabled,
            password_configured,
        }
    }
}

/// Auth status returned to the frontend for login/setup flow.
#[derive(Debug, Clone)]
pub struct AuthStatus {
    /// Whether authentication is globally enabled.
    pub auth_enabled: bool,
    /// Whether the admin password has been set (first-run setup complete).
    pub password_configured: bool,
}
