use ferrous_dns_application::ports::{TlsCertificateInfo, TlsCertificatePort};
use ferrous_dns_domain::DomainError;
use std::io::BufReader;
use std::path::Path;
use tracing::warn;

const MAX_PEM_SIZE: usize = 64 * 1024;

pub struct TlsCertificateService;

#[async_trait::async_trait]
impl TlsCertificatePort for TlsCertificateService {
    async fn get_status(&self, cert_path: &str, key_path: &str) -> TlsCertificateInfo {
        let cert_exists = Path::new(cert_path).exists();
        let key_exists = Path::new(key_path).exists();

        let (cert_subject, cert_not_after, cert_valid) = if cert_exists {
            tokio::task::spawn_blocking({
                let path = cert_path.to_string();
                move || parse_cert_info(&path)
            })
            .await
            .unwrap_or((None, None, false))
        } else {
            (None, None, false)
        };

        TlsCertificateInfo {
            cert_exists,
            key_exists,
            cert_subject,
            cert_not_after,
            cert_valid,
        }
    }

    async fn save_certificates(
        &self,
        cert_data: &[u8],
        key_data: &[u8],
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), DomainError> {
        if cert_data.len() > MAX_PEM_SIZE {
            return Err(DomainError::InvalidInput(
                "Certificate file exceeds maximum size (64 KB)".into(),
            ));
        }
        if key_data.len() > MAX_PEM_SIZE {
            return Err(DomainError::InvalidInput(
                "Key file exceeds maximum size (64 KB)".into(),
            ));
        }

        validate_pem_cert(cert_data)?;
        validate_pem_key(key_data)?;

        ensure_parent_dir(cert_path).await?;
        tokio::fs::write(cert_path, cert_data)
            .await
            .map_err(|e| DomainError::IoError(format!("Failed to write certificate: {e}")))?;
        tokio::fs::write(key_path, key_data)
            .await
            .map_err(|e| DomainError::IoError(format!("Failed to write key: {e}")))?;

        Ok(())
    }

    async fn generate_self_signed(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), DomainError> {
        let (cert_pem, key_pem) = tokio::task::spawn_blocking(generate_self_signed_cert)
            .await
            .map_err(|e| DomainError::IoError(format!("Task join error: {e}")))?
            .map_err(|e| DomainError::IoError(format!("Certificate generation failed: {e}")))?;

        ensure_parent_dir(cert_path).await?;
        tokio::fs::write(cert_path, cert_pem.as_bytes())
            .await
            .map_err(|e| DomainError::IoError(format!("Failed to write certificate: {e}")))?;
        tokio::fs::write(key_path, key_pem.as_bytes())
            .await
            .map_err(|e| DomainError::IoError(format!("Failed to write key: {e}")))?;

        Ok(())
    }
}

fn generate_self_signed_cert() -> Result<(String, String), String> {
    let mut params = rcgen::CertificateParams::new(vec!["ferrous-dns".to_string()])
        .map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrous-dns");

    let now = std::time::SystemTime::now();
    let one_year = std::time::Duration::from_secs(365 * 24 * 3600);
    params.not_before = now.into();
    params.not_after = (now + one_year).into();

    params.subject_alt_names = vec![
        rcgen::SanType::DnsName(
            "ferrous-dns"
                .try_into()
                .map_err(|e: rcgen::Error| e.to_string())?,
        ),
        rcgen::SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e: rcgen::Error| e.to_string())?,
        ),
    ];

    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn parse_cert_info(cert_path: &str) -> (Option<String>, Option<String>, bool) {
    let Ok(data) = std::fs::read(cert_path) else {
        return (None, None, false);
    };

    let Ok(pems) = x509_parser::pem::Pem::iter_from_buffer(&data).collect::<Result<Vec<_>, _>>()
    else {
        warn!("Failed to parse PEM from {}", cert_path);
        return (None, None, false);
    };

    let Some(pem) = pems.first() else {
        return (None, None, false);
    };

    match x509_parser::parse_x509_certificate(&pem.contents) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let not_after = cert.validity().not_after.to_rfc2822().ok();
            let valid = cert.validity().is_valid();
            (Some(subject), not_after, valid)
        }
        Err(e) => {
            warn!(error = %e, "Failed to parse X.509 certificate");
            (None, None, false)
        }
    }
}

fn validate_pem_cert(data: &[u8]) -> Result<(), DomainError> {
    let mut reader = BufReader::new(data);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DomainError::InvalidInput(format!("Invalid certificate PEM: {e}")))?;
    if certs.is_empty() {
        return Err(DomainError::InvalidInput(
            "No certificates found in PEM data".into(),
        ));
    }
    Ok(())
}

fn validate_pem_key(data: &[u8]) -> Result<(), DomainError> {
    let mut reader = BufReader::new(data);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| DomainError::InvalidInput(format!("Invalid key PEM: {e}")))?
        .ok_or_else(|| DomainError::InvalidInput("No private key found in PEM data".into()))?;
    Ok(())
}

async fn ensure_parent_dir(path: &str) -> Result<(), DomainError> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.exists() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| DomainError::IoError(format!("Failed to create directory: {e}")))?;
        }
    }
    Ok(())
}
