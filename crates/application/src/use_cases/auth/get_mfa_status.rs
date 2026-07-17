use std::sync::Arc;

use tracing::instrument;

use crate::ports::MfaRepository;
use ferrous_dns_domain::DomainError;

/// A registered passkey, summarized for the settings UI.
pub struct PasskeySummary {
    pub id: i64,
    pub label: Option<String>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// A user's second-factor enrollment status.
pub struct MfaStatus {
    pub totp_enabled: bool,
    pub recovery_codes_remaining: usize,
    pub passkeys: Vec<PasskeySummary>,
}

/// Reports the current MFA enrollment for a user (for the security settings UI).
pub struct GetMfaStatusUseCase {
    mfa_repo: Arc<dyn MfaRepository>,
}

impl GetMfaStatusUseCase {
    pub fn new(mfa_repo: Arc<dyn MfaRepository>) -> Self {
        Self { mfa_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, username: &str) -> Result<MfaStatus, DomainError> {
        let totp_enabled = self
            .mfa_repo
            .get(username)
            .await?
            .map(|m| m.totp_enabled)
            .unwrap_or(false);

        let recovery_codes_remaining = self
            .mfa_repo
            .list_unused_recovery_codes(username)
            .await?
            .len();

        let passkeys = self
            .mfa_repo
            .list_credentials(username)
            .await?
            .into_iter()
            .map(|c| PasskeySummary {
                id: c.id.unwrap_or(0),
                label: c.label.map(|l| l.to_string()),
                created_at: c.created_at,
                last_used_at: c.last_used_at,
            })
            .collect();

        Ok(MfaStatus {
            totp_enabled,
            recovery_codes_remaining,
            passkeys,
        })
    }
}
