use ferrous_dns_domain::DomainError;

/// Status information about a TLS certificate and key pair.
pub struct TlsCertificateInfo {
    pub cert_exists: bool,
    pub key_exists: bool,
    pub cert_subject: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_valid: bool,
}

/// Port for TLS certificate management operations (status, upload, generation).
#[async_trait::async_trait]
pub trait TlsCertificatePort: Send + Sync {
    /// Reads and parses certificate files to determine their status.
    async fn get_status(&self, cert_path: &str, key_path: &str) -> TlsCertificateInfo;

    /// Validates PEM data and writes certificate + key to the configured paths.
    async fn save_certificates(
        &self,
        cert_data: &[u8],
        key_data: &[u8],
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), DomainError>;

    /// Generates a self-signed certificate and writes it to the configured paths.
    async fn generate_self_signed(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), DomainError>;
}
