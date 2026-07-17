use ferrous_dns_domain::DomainError;

/// Port for TOTP secret generation and code verification (RFC 6238).
pub trait TotpService: Send + Sync {
    /// Generate a fresh random base32-encoded shared secret.
    fn generate_secret(&self) -> String;

    /// Build the `otpauth://` provisioning URI for the given account and secret,
    /// used to render the enrollment QR code.
    fn provisioning_uri(&self, secret: &str, account: &str) -> Result<String, DomainError>;

    /// Render an SVG QR code for a provisioning URI.
    fn qr_svg(&self, otpauth_uri: &str) -> Result<String, DomainError>;

    /// Verify a 6-digit code against the secret, tolerating small clock drift.
    fn verify(&self, secret: &str, code: &str) -> Result<bool, DomainError>;
}
