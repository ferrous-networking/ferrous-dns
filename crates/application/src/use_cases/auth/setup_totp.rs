use std::sync::Arc;

use tracing::{info, instrument};

use crate::ports::{MfaRepository, TotpService};
use ferrous_dns_domain::DomainError;

/// Data returned to the client to enroll a TOTP authenticator.
pub struct TotpSetup {
    /// base32 secret (shown for manual entry).
    pub secret: String,
    /// `otpauth://` provisioning URI.
    pub otpauth_uri: String,
    /// SVG QR code encoding the provisioning URI.
    pub qr_svg: String,
}

/// Begins TOTP enrollment: generates a secret (unconfirmed) and the QR data.
///
/// The secret is not active until [`super::ConfirmTotpUseCase`] verifies the
/// first code.
pub struct SetupTotpUseCase {
    mfa_repo: Arc<dyn MfaRepository>,
    totp: Arc<dyn TotpService>,
}

impl SetupTotpUseCase {
    pub fn new(mfa_repo: Arc<dyn MfaRepository>, totp: Arc<dyn TotpService>) -> Self {
        Self { mfa_repo, totp }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, username: &str) -> Result<TotpSetup, DomainError> {
        if let Some(existing) = self.mfa_repo.get(username).await? {
            if existing.totp_enabled {
                return Err(DomainError::MfaAlreadyEnabled);
            }
        }

        let secret = self.totp.generate_secret();
        self.mfa_repo.upsert_secret(username, &secret).await?;

        let otpauth_uri = self.totp.provisioning_uri(&secret, username)?;
        let qr_svg = self.totp.qr_svg(&otpauth_uri)?;

        info!(username = username, "TOTP enrollment started");
        Ok(TotpSetup {
            secret,
            otpauth_uri,
            qr_svg,
        })
    }
}
