use ferrous_dns_application::ports::TlsCertificatePort;
use ferrous_dns_infrastructure::tls::{certificate_not_after, TlsCertificateService};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 temp path")
}

#[tokio::test]
async fn test_certificate_not_after_reads_a_generated_certificates_expiry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    TlsCertificateService
        .generate_self_signed(path_str(&cert), path_str(&key))
        .await
        .expect("generate pair");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64;

    let not_after = certificate_not_after(path_str(&cert)).expect("a certificate");

    let one_year = 365 * 24 * 3600;
    assert!(
        (not_after - (now + one_year)).abs() < 60,
        "not_after {not_after} is not a year after {now}"
    );
}

#[test]
fn test_certificate_not_after_is_none_without_a_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let garbage = dir.path().join("garbage.pem");
    std::fs::write(&garbage, b"not a certificate").expect("write");

    assert_eq!(certificate_not_after(path_str(&garbage)), None);
    assert_eq!(
        certificate_not_after(path_str(&dir.path().join("missing.pem"))),
        None
    );
}

#[tokio::test]
async fn test_generate_self_signed_creates_key_directory_separate_from_cert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("certs/server.crt");
    let key = dir.path().join("private/server.key");

    TlsCertificateService
        .generate_self_signed(path_str(&cert), path_str(&key))
        .await
        .expect("generate pair");

    assert!(cert.is_file());
    assert!(key.is_file());
}

#[tokio::test]
async fn test_save_certificates_creates_key_directory_separate_from_cert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (seed_cert, seed_key) = (dir.path().join("seed.crt"), dir.path().join("seed.key"));
    TlsCertificateService
        .generate_self_signed(path_str(&seed_cert), path_str(&seed_key))
        .await
        .expect("seed pair");
    let cert_pem = std::fs::read(&seed_cert).expect("read seed cert");
    let key_pem = std::fs::read(&seed_key).expect("read seed key");

    let cert = dir.path().join("certs/server.crt");
    let key = dir.path().join("private/server.key");
    TlsCertificateService
        .save_certificates(&cert_pem, &key_pem, path_str(&cert), path_str(&key))
        .await
        .expect("save pair");

    assert_eq!(std::fs::read(&cert).expect("cert"), cert_pem);
    assert_eq!(std::fs::read(&key).expect("key"), key_pem);
}

#[cfg(unix)]
#[tokio::test]
async fn test_private_key_is_owner_only_even_when_file_preexisted_world_readable() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    std::fs::write(&key, b"old").expect("pre-existing key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    TlsCertificateService
        .generate_self_signed(path_str(&cert), path_str(&key))
        .await
        .expect("generate pair");

    let mode = std::fs::metadata(&key)
        .expect("key metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
