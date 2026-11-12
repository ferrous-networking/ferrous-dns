//! `/metrics` and `GET /config` against the real binary: the DNS listener
//! state, and the expiry of each certificate the TLS listeners loaded at start.

mod server_process;

use server_process::{free_port, write_certificate, TestConfig};
use std::time::{Duration, Instant};

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap()
}

async fn get(base: &str, path: &str) -> String {
    let response = client().get(format!("{base}{path}")).send().await.unwrap();
    assert!(response.status().is_success(), "GET {path}: {response:?}");
    response.text().await.unwrap()
}

/// The DNS listener comes up just after the web one, so wait for it.
async fn scrape_once_listening(base: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let body = get(base, "/metrics").await;
        if body.contains("\nferrousdns_dns_listening 1\n") || Instant::now() > deadline {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn web_certificate_expires_at(base: &str) -> serde_json::Value {
    let config: serde_json::Value =
        serde_json::from_str(&get(base, "/ferrous/api/v1/config").await).unwrap();
    config["web_certificate_expires_at"].clone()
}

#[tokio::test]
async fn test_metrics_report_the_listener_and_no_certificate_on_plain_http() {
    let config = TestConfig::with_extra("metrics_enabled = true");
    let _server = config.start();
    let base = format!("http://127.0.0.1:{}", config.web_port);

    let body = scrape_once_listening(&base).await;

    assert!(body.contains("\nferrousdns_dns_listening 1\n"), "{body}");
    assert!(
        !body.contains("ferrousdns_tls_cert_not_after_seconds{"),
        "{body}"
    );
    assert_eq!(
        web_certificate_expires_at(&base).await,
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn test_metrics_report_the_certificate_each_tls_listener_loaded() {
    let cert_dir = tempfile::tempdir().unwrap();
    let not_after = write_certificate(cert_dir.path());
    let (cert, key) = (
        cert_dir.path().join("cert.pem"),
        cert_dir.path().join("key.pem"),
    );
    let config = TestConfig::with_extra(&format!(
        "metrics_enabled = true\n\
         \n[server.web_tls]\nenabled = true\ntls_cert_path = \"{cert}\"\ntls_key_path = \"{key}\"\n\
         \n[server.encrypted_dns]\ndot_enabled = true\ndot_port = {dot_port}\n\
         tls_cert_path = \"{cert}\"\ntls_key_path = \"{key}\"",
        cert = cert.display(),
        key = key.display(),
        dot_port = free_port(),
    ));
    let _server = config.start();
    let base = format!("https://127.0.0.1:{}", config.web_port);

    let body = scrape_once_listening(&base).await;

    for line in [
        format!("ferrousdns_tls_cert_not_after_seconds{{listener=\"web\"}} {not_after}"),
        format!("ferrousdns_tls_cert_not_after_seconds{{listener=\"dot\"}} {not_after}"),
    ] {
        assert!(body.contains(&line), "missing `{line}` in:\n{body}");
    }
    assert!(!body.contains("listener=\"doq\""), "DoQ is off: {body}");
    assert_eq!(web_certificate_expires_at(&base).await, not_after);
}
