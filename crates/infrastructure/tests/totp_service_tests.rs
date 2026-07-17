use ferrous_dns_application::ports::TotpService;
use ferrous_dns_infrastructure::auth::TotpRsService;
use totp_rs::{Algorithm, Secret, TOTP};

/// Builds the current 6-digit code for a base32 secret the same way the service
/// (SHA1/6/30) does, so the test can drive `verify`.
fn current_code(secret_base32: &str) -> String {
    let bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .expect("decode secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("Ferrous DNS".to_string()),
        "account".to_string(),
    )
    .expect("build totp");
    totp.generate_current().expect("generate code")
}

#[test]
fn generated_secret_verifies_current_code() {
    let svc = TotpRsService::new("Ferrous DNS");
    let secret = svc.generate_secret();
    assert!(!secret.is_empty());

    let code = current_code(&secret);
    assert!(
        svc.verify(&secret, &code).unwrap(),
        "current code must verify"
    );
    assert!(
        !svc.verify(&secret, "000000").unwrap() || code == "000000",
        "an unrelated code must fail"
    );
}

#[test]
fn provisioning_uri_and_qr_are_produced() {
    let svc = TotpRsService::new("Ferrous DNS");
    let secret = svc.generate_secret();

    let uri = svc.provisioning_uri(&secret, "admin").unwrap();
    assert!(uri.starts_with("otpauth://totp/"));
    assert!(
        uri.contains("Ferrous%20DNS") || uri.contains("Ferrous+DNS") || uri.contains("issuer=")
    );

    let svg = svc.qr_svg(&uri).unwrap();
    assert!(svg.contains("<svg"));
}

#[test]
fn invalid_secret_is_rejected() {
    let svc = TotpRsService::new("Ferrous DNS");
    // '1', '8', '0' are not valid base32 alphabet characters.
    assert!(svc.verify("1180", "123456").is_err());
}
