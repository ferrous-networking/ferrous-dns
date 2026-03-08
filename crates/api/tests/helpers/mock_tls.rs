use ferrous_dns_application::ports::{TlsCertificateInfo, TlsCertificatePort};
use ferrous_dns_domain::DomainError;

pub struct MockTlsCertificateService;

#[async_trait::async_trait]
impl TlsCertificatePort for MockTlsCertificateService {
    async fn get_status(&self, _cert_path: &str, _key_path: &str) -> TlsCertificateInfo {
        TlsCertificateInfo {
            cert_exists: false,
            key_exists: false,
            cert_subject: None,
            cert_not_after: None,
            cert_valid: false,
        }
    }

    async fn save_certificates(
        &self,
        _cert_data: &[u8],
        _key_data: &[u8],
        _cert_path: &str,
        _key_path: &str,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn generate_self_signed(
        &self,
        _cert_path: &str,
        _key_path: &str,
    ) -> Result<(), DomainError> {
        Ok(())
    }
}
