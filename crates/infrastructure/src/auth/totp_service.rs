use qrcode::{render::svg, QrCode};
use totp_rs::{Algorithm, Secret, TOTP};

use ferrous_dns_application::ports::TotpService;
use ferrous_dns_domain::DomainError;

/// TOTP service backed by `totp-rs` (RFC 6238, SHA1/6-digit/30s — the profile
/// every authenticator app supports). QR codes are rendered as lightweight SVG
/// via the `qrcode` crate to avoid pulling a PNG image stack.
pub struct TotpRsService {
    issuer: String,
    /// Skew: number of ±30s steps tolerated (1 ≈ ±30s clock drift).
    skew: u8,
}

impl TotpRsService {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            skew: 1,
        }
    }

    fn build(&self, secret_base32: &str, account: &str) -> Result<TOTP, DomainError> {
        let bytes = Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .map_err(|e| DomainError::ConfigError(format!("invalid TOTP secret: {e:?}")))?;
        TOTP::new(
            Algorithm::SHA1,
            6,
            self.skew,
            30,
            bytes,
            Some(self.issuer.clone()),
            account.to_string(),
        )
        .map_err(|e| DomainError::ConfigError(format!("TOTP init failed: {e}")))
    }
}

impl TotpService for TotpRsService {
    fn generate_secret(&self) -> String {
        match Secret::generate_secret().to_encoded() {
            Secret::Encoded(s) => s,
            Secret::Raw(bytes) => data_encoding::BASE32_NOPAD.encode(&bytes),
        }
    }

    fn provisioning_uri(&self, secret: &str, account: &str) -> Result<String, DomainError> {
        Ok(self.build(secret, account)?.get_url())
    }

    fn qr_svg(&self, otpauth_uri: &str) -> Result<String, DomainError> {
        let code = QrCode::new(otpauth_uri.as_bytes())
            .map_err(|e| DomainError::ConfigError(format!("QR encode failed: {e}")))?;
        Ok(code
            .render::<svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .build())
    }

    fn verify(&self, secret: &str, code: &str) -> Result<bool, DomainError> {
        let totp = self.build(secret, "account")?;
        totp.check_current(code.trim())
            .map_err(|e| DomainError::ConfigError(format!("TOTP check failed: {e}")))
    }
}
