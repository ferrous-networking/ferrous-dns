//! `GET /health` and `ferrous-dns --healthcheck` against the real binary. Docker's
//! HEALTHCHECK runs the flag, which reads the endpoint, so both must tell a server
//! whose DNS listener never came up from a healthy one.
#![cfg(unix)]

mod server_process;

use server_process::{wait_for_exit, TestConfig};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

/// A plain HTTP/1.1 GET on the loopback: the status code and the body.
fn http_get(port: u16, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // One write: the TLS port's redirect reads a single segment, then closes.
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP response: {response}"));
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

fn health(config: &TestConfig) -> (u16, serde_json::Value) {
    let (status, body) = http_get(config.web_port, "/ferrous/api/v1/health");
    let json = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("/health answered {status} with a non-JSON body {body:?}: {e}"));
    (status, json)
}

/// Runs `--healthcheck` with the same config; a hang fails the test after 15 s.
fn run_healthcheck(config: &TestConfig) -> ExitStatus {
    run_healthcheck_with_env(config, &[])
}

fn run_healthcheck_with_env(config: &TestConfig, env: &[(&str, &str)]) -> ExitStatus {
    let mut child = config
        .command()
        .arg("--healthcheck")
        .envs(env.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_exit(&mut child, Duration::from_secs(15)).unwrap_or_else(|| {
        child.kill().unwrap();
        panic!("--healthcheck still running after 15 s");
    })
}

/// Holds the DNS port with a socket that does not set SO_REUSEPORT, so the
/// server's own bind fails.
fn take_dns_port(config: &TestConfig) -> UdpSocket {
    UdpSocket::bind(("127.0.0.1", config.dns_port)).unwrap()
}

#[test]
fn test_health_reports_ok_and_the_version_while_dns_listens() {
    let config = TestConfig::new();
    let _server = config.start();

    let (status, json) = health(&config);

    assert_eq!(status, 200, "{json}");
    assert_eq!(
        json,
        serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") })
    );
}

#[test]
fn test_health_answers_503_while_the_dns_port_is_taken() {
    let config = TestConfig::new();
    let _held = take_dns_port(&config);
    let _server = config.start();

    let (status, json) = health(&config);

    assert_eq!(status, 503, "{json}");
    assert_eq!(json["status"], "unavailable");
}

#[test]
fn test_healthcheck_exits_0_against_a_healthy_server() {
    let config = TestConfig::new();
    let _server = config.start();

    assert_eq!(run_healthcheck(&config).code(), Some(0));
}

/// Docker copies the client's proxy settings into every container's environment.
#[test]
fn test_healthcheck_ignores_a_proxy_set_in_the_environment() {
    let config = TestConfig::new();
    let _server = config.start();
    let dead_proxy = "http://127.0.0.1:1";

    let status = run_healthcheck_with_env(
        &config,
        &[("HTTP_PROXY", dead_proxy), ("http_proxy", dead_proxy)],
    );

    assert_eq!(status.code(), Some(0));
}

#[test]
fn test_healthcheck_exits_1_while_the_dns_port_is_taken() {
    let config = TestConfig::new();
    let _held = take_dns_port(&config);
    let _server = config.start();

    assert_eq!(run_healthcheck(&config).code(), Some(1));
}

#[test]
fn test_healthcheck_exits_1_when_no_server_answers() {
    let config = TestConfig::new();

    assert_eq!(run_healthcheck(&config).code(), Some(1));
}

#[test]
fn test_healthcheck_follows_the_redirect_to_a_self_signed_https_server() {
    let cert_dir = tempfile::tempdir().unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let cert_path = cert_dir.path().join("cert.pem");
    let key_path = cert_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    let config = TestConfig::with_extra(&format!(
        "\n[server.web_tls]\nenabled = true\ntls_cert_path = \"{}\"\ntls_key_path = \"{}\"",
        cert_path.display(),
        key_path.display()
    ));
    let _server = config.start();

    // Plain HTTP on the TLS port is only a redirect.
    assert_eq!(http_get(config.web_port, "/ferrous/api/v1/health").0, 301);
    assert_eq!(run_healthcheck(&config).code(), Some(0));
}
