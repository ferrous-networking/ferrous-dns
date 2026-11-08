use ferrous_dns_application::ports::{TlsCertificateInfo, TlsCertificatePort};
use ferrous_dns_domain::DomainError;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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

        write_pair(cert_path, cert_data, key_path, key_data).await
    }

    async fn generate_self_signed(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), DomainError> {
        let (cert_pem, key_pem) = tokio::task::spawn_blocking(generate_self_signed_cert)
            .await
            .map_err(|e| DomainError::IoError(format!("Task join error: {e}")))??;

        write_pair(cert_path, cert_pem.as_bytes(), key_path, key_pem.as_bytes()).await
    }
}

fn generate_self_signed_cert() -> Result<(String, String), DomainError> {
    let gen_err =
        |e: rcgen::Error| DomainError::IoError(format!("Certificate generation failed: {e}"));
    let mut params =
        rcgen::CertificateParams::new(vec!["ferrous-dns".to_string()]).map_err(gen_err)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrous-dns");

    let now = std::time::SystemTime::now();
    let one_year = std::time::Duration::from_secs(365 * 24 * 3600);
    params.not_before = now.into();
    params.not_after = (now + one_year).into();

    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("ferrous-dns".try_into().map_err(gen_err)?),
        rcgen::SanType::DnsName("localhost".try_into().map_err(gen_err)?),
    ];

    let key_pair = rcgen::KeyPair::generate().map_err(gen_err)?;
    let cert = params.self_signed(&key_pair).map_err(gen_err)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn parse_cert_info(cert_path: &str) -> (Option<String>, Option<String>, bool) {
    let Ok(data) = std::fs::read(cert_path) else {
        return (None, None, false);
    };

    with_first_certificate(cert_path, &data, |cert| {
        let subject = cert.subject().to_string();
        let not_after = cert.validity().not_after.to_rfc2822().ok();
        let valid = cert.validity().is_valid();
        (Some(subject), not_after, valid)
    })
    .unwrap_or((None, None, false))
}

/// The `notAfter` of the first certificate in the PEM file at `cert_path`, in
/// Unix seconds; `None` when the file is missing or holds no certificate.
pub fn certificate_not_after(cert_path: &str) -> Option<i64> {
    let data = std::fs::read(cert_path).ok()?;
    with_first_certificate(cert_path, &data, |cert| {
        cert.validity().not_after.timestamp()
    })
}

/// Reads the first certificate of a PEM chain: the server's own. Other blocks,
/// such as a private key bundled ahead of it, are skipped, as rustls does.
fn with_first_certificate<T>(
    cert_path: &str,
    data: &[u8],
    read: impl FnOnce(&x509_parser::certificate::X509Certificate) -> T,
) -> Option<T> {
    let Ok(pems) = x509_parser::pem::Pem::iter_from_buffer(data).collect::<Result<Vec<_>, _>>()
    else {
        warn!("Failed to parse PEM from {}", cert_path);
        return None;
    };

    let pem = pems.iter().find(|pem| pem.label == "CERTIFICATE")?;

    match x509_parser::parse_x509_certificate(&pem.contents) {
        Ok((_, cert)) => Some(read(&cert)),
        Err(e) => {
            warn!(error = %e, "Failed to parse X.509 certificate");
            None
        }
    }
}

fn validate_pem_cert(data: &[u8]) -> Result<(), DomainError> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(data)
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
    PrivateKeyDer::from_pem_slice(data)
        .map_err(|e| DomainError::InvalidInput(format!("Invalid key PEM: {e}")))?;
    Ok(())
}

async fn write_pair(
    cert_path: &str,
    cert: &[u8],
    key_path: &str,
    key: &[u8],
) -> Result<(), DomainError> {
    ensure_parent_dir(cert_path).await?;
    ensure_parent_dir(key_path).await?;
    tokio::fs::write(cert_path, cert)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to write certificate: {e}")))?;
    write_private(key_path, key)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to write key: {e}")))
}

/// Writes a private key readable by the owner only, tightening a pre-existing file before the secret lands in it.
async fn write_private(path: &str, data: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
    }
    file.write_all(data).await?;
    file.flush().await
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
