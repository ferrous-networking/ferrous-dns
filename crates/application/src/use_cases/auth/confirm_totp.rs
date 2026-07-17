use std::fmt::Write;
use std::sync::Arc;

use ring::rand::SecureRandom;
use tracing::{info, instrument};

use crate::ports::{MfaRepository, PasswordHasher, TotpService};
use ferrous_dns_domain::DomainError;

/// Number of single-use recovery codes generated at enrollment.
const RECOVERY_CODE_COUNT: usize = 10;
/// Bytes of entropy per recovery code (rendered as hex).
const RECOVERY_CODE_BYTES: usize = 5;

/// Confirms TOTP enrollment by verifying the first code, then enables it and
/// issues single-use recovery codes.
///
/// The plaintext recovery codes are returned exactly once; only their Argon2id
/// hashes are stored.
pub struct ConfirmTotpUseCase {
    mfa_repo: Arc<dyn MfaRepository>,
    totp: Arc<dyn TotpService>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl ConfirmTotpUseCase {
    pub fn new(
        mfa_repo: Arc<dyn MfaRepository>,
        totp: Arc<dyn TotpService>,
        password_hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            mfa_repo,
            totp,
            password_hasher,
        }
    }

    /// Returns the plaintext recovery codes on success.
    #[instrument(skip(self, code))]
    pub async fn execute(&self, username: &str, code: &str) -> Result<Vec<String>, DomainError> {
        let mfa = self
            .mfa_repo
            .get(username)
            .await?
            .ok_or(DomainError::MfaNotConfigured)?;

        if mfa.totp_enabled {
            return Err(DomainError::MfaAlreadyEnabled);
        }

        if !self.totp.verify(&mfa.totp_secret, code)? {
            return Err(DomainError::InvalidMfaCode);
        }

        self.mfa_repo.enable(username).await?;

        let codes = generate_recovery_codes()?;
        let mut hashes = Vec::with_capacity(codes.len());
        for c in &codes {
            hashes.push(self.password_hasher.hash(c)?);
        }
        self.mfa_repo
            .replace_recovery_codes(username, &hashes)
            .await?;

        info!(username = username, "TOTP enabled");
        Ok(codes)
    }
}

/// Generates human-typeable recovery codes formatted `xxxxx-xxxxx`.
fn generate_recovery_codes() -> Result<Vec<String>, DomainError> {
    let rng = ring::rand::SystemRandom::new();
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut buf = [0u8; RECOVERY_CODE_BYTES];
        rng.fill(&mut buf)
            .map_err(|_| DomainError::IoError("CSPRNG fill failed".to_string()))?;
        let mut hex = String::with_capacity(RECOVERY_CODE_BYTES * 2 + 1);
        for (i, byte) in buf.iter().enumerate() {
            if i == RECOVERY_CODE_BYTES / 2 {
                hex.push('-');
            }
            let _ = write!(hex, "{byte:02x}");
        }
        codes.push(hex);
    }
    Ok(codes)
}
