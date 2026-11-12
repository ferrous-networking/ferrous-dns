//! The real binary on a kernel without IPv6 (#386). A seccomp filter fails
//! `socket(AF_INET6, …)` with `EAFNOSUPPORT`, which is what a kernel booted
//! with `ipv6.disable=1` returns, so every listener has to make do with
//! AF_INET.
#![cfg(target_os = "linux")]

mod common;
mod server_process;

use common::SkipServerVerification;
use hickory_proto::op::Message;
use rustls::pki_types::ServerName;
use server_process::{
    accepts_within, framed, free_port, http_get, http_status, private_ptr_query, server_log,
    skip_without_seccomp, tcp_answers, udp_answers, wait_for_exit, write_certificate, TestConfig,
    FALLBACK_LINE, NO_IPV6, NO_IPV6_ERROR, PTR_QUERY_ID,
};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const HEALTH: &str = "/ferrous/api/v1/health";

fn assert_serves_dns_and_web(config: &TestConfig) {
    let log = || server_log(config.dir.path());
    let dns = SocketAddr::new(V4, config.dns_port);
    assert!(
        accepts_within(dns, Duration::from_secs(10)),
        "DNS listener on {dns}:\n{}",
        log()
    );
    assert!(udp_answers(dns), "DNS over UDP on {dns}:\n{}", log());
    assert!(tcp_answers(dns), "DNS over TCP on {dns}:\n{}", log());
    assert_eq!(
        http_status(SocketAddr::new(V4, config.web_port), HEALTH),
        200,
        "{}",
        log()
    );
}

fn log_contains_within(dir: &Path, needle: &str, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while !server_log(dir).contains(needle) {
        if Instant::now() > deadline {
            return false;
        }
        sleep(Duration::from_millis(50));
    }
    true
}

/// `query`'s result, or a failure naming `what` when the server never answers.
async fn within<T>(what: &str, query: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), query)
        .await
        .unwrap_or_else(|_| panic!("{what}: no answer within 10 s"))
}

fn client_tls(alpn: &[u8]) -> rustls::ClientConfig {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls
}

async fn dot_reply_id(server: SocketAddr) -> u16 {
    let stream = tokio::net::TcpStream::connect(server).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"dot")))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    tls.write_all(&framed(&private_ptr_query())).await.unwrap();
    let mut len = [0u8; 2];
    tls.read_exact(&mut len).await.unwrap();
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
    tls.read_exact(&mut reply).await.unwrap();
    Message::from_vec(&reply).unwrap().id
}

async fn doq_reply_id(server: SocketAddr) -> u16 {
    let quic =
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls(b"doq"))).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let connection = endpoint
        .connect(server, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&framed(&private_ptr_query())).await.unwrap();
    send.finish().unwrap();
    let reply = recv.read_to_end(4096).await.unwrap();
    Message::from_vec(&reply[2..]).unwrap().id
}

async fn doh_reply_id(server: SocketAddr) -> u16 {
    let reply = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("http://{server}/dns-query"))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(private_ptr_query())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    Message::from_vec(&reply).unwrap().id
}

#[test]
fn test_auto_falls_back_to_ipv4_without_kernel_ipv6() {
    if skip_without_seccomp("test_auto_falls_back_to_ipv4_without_kernel_ipv6") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("auto"), "", "enabled = false");
    let _server = config.start_without_ipv6();

    assert_serves_dns_and_web(&config);
    let log = server_log(config.dir.path());
    assert!(log.contains(FALLBACK_LINE), "{log}");
    // Only the listeners fall back: the stored config keeps saying "auto".
    let (status, body) = http_get(
        SocketAddr::new(V4, config.web_port),
        "/ferrous/api/v1/config",
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(r#""bind_address":"auto""#), "{body}");
}

#[tokio::test]
async fn test_auto_fallback_covers_dot_doq_and_doh_without_kernel_ipv6() {
    if skip_without_seccomp("test_auto_fallback_covers_dot_doq_and_doh_without_kernel_ipv6") {
        return;
    }
    ferrous_dns::install_crypto_provider();
    let certs = tempfile::tempdir().unwrap();
    write_certificate(certs.path());
    let (dot_port, doq_port, doh_port) = (free_port(), free_port(), free_port());
    let config = TestConfig::with_bind_address(
        Some("auto"),
        &format!(
            "\n[server.encrypted_dns]\n\
             dot_enabled = true\ndot_port = {dot_port}\n\
             doq_enabled = true\ndoq_port = {doq_port}\n\
             doh_enabled = true\ndoh_port = {doh_port}\n\
             tls_cert_path = \"{cert}\"\ntls_key_path = \"{key}\"",
            cert = certs.path().join("cert.pem").display(),
            key = certs.path().join("key.pem").display(),
        ),
        "enabled = false",
    );
    let _server = config.start_without_ipv6();
    let log = || server_log(config.dir.path());

    assert!(log().contains(FALLBACK_LINE), "{}", log());
    let dot = SocketAddr::new(V4, dot_port);
    let doh = SocketAddr::new(V4, doh_port);
    assert!(
        accepts_within(dot, Duration::from_secs(10)),
        "DoT:\n{}",
        log()
    );
    assert!(
        accepts_within(doh, Duration::from_secs(10)),
        "DoH:\n{}",
        log()
    );
    assert_eq!(
        within("DoT", dot_reply_id(dot)).await,
        PTR_QUERY_ID,
        "DoT:\n{}",
        log()
    );
    assert_eq!(
        within("DoQ", doq_reply_id(SocketAddr::new(V4, doq_port))).await,
        PTR_QUERY_ID,
        "DoQ:\n{}",
        log()
    );
    assert_eq!(
        within("DoH", doh_reply_id(doh)).await,
        PTR_QUERY_ID,
        "DoH:\n{}",
        log()
    );
}

#[test]
fn test_ipv4_bind_serves_dns_without_kernel_ipv6() {
    if skip_without_seccomp("test_ipv4_bind_serves_dns_without_kernel_ipv6") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("0.0.0.0"), "", "enabled = false");
    let _server = config.start_without_ipv6();

    assert_serves_dns_and_web(&config);
}

#[test]
fn test_explicit_ipv6_bind_names_the_missing_ipv6_without_kernel_ipv6() {
    if skip_without_seccomp("test_explicit_ipv6_bind_names_the_missing_ipv6_without_kernel_ipv6") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("[::]"), "", "enabled = false");
    let mut child = config.spawn_logged(config.command_without_ipv6(NO_IPV6));
    let status = wait_for_exit(&mut child, Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();
    let log = server_log(config.dir.path());

    // The web listener cannot bind, so the server stops and says why.
    assert!(status.is_some_and(|status| !status.success()), "{log}");
    assert!(
        log.contains(&format!("[::]:{} {NO_IPV6_ERROR}", config.web_port)),
        "{log}"
    );
    // An explicit address never falls back.
    assert!(!log.contains(FALLBACK_LINE), "{log}");
}

#[test]
fn test_explicit_ipv6_dns_bind_is_reported_while_the_web_stays_up() {
    if skip_without_seccomp("test_explicit_ipv6_dns_bind_is_reported_while_the_web_stays_up") {
        return;
    }
    let config = TestConfig::with_bind_address(
        Some("[::]"),
        "web_bind_address = \"127.0.0.1\"",
        "enabled = false",
    );
    let _server = config.start_without_ipv6();

    let message = format!("[::]:{} {NO_IPV6_ERROR}", config.dns_port);
    assert!(
        log_contains_within(config.dir.path(), &message, Duration::from_secs(10)),
        "{}",
        server_log(config.dir.path())
    );
    assert_eq!(
        http_status(SocketAddr::new(V4, config.web_port), HEALTH),
        503
    );
    let log = server_log(config.dir.path());
    assert!(!log.contains(FALLBACK_LINE), "{log}");
}

#[test]
fn test_auto_keeps_ipv6_when_af_inet6_is_denied_for_another_reason() {
    if skip_without_seccomp("test_auto_keeps_ipv6_when_af_inet6_is_denied_for_another_reason") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("auto"), "", "enabled = false");
    let mut child = config.spawn_logged(config.command_without_ipv6(libc::EACCES));
    let status = wait_for_exit(&mut child, Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();
    let log = server_log(config.dir.path());

    // Only EAFNOSUPPORT means "no IPv6"; anything else is reported as it is.
    assert!(status.is_some_and(|status| !status.success()), "{log}");
    assert!(log.contains("Permission denied"), "{log}");
    assert!(!log.contains(NO_IPV6_ERROR), "{log}");
    assert!(!log.contains(FALLBACK_LINE), "{log}");
}

#[test]
fn test_healthcheck_passes_on_the_ipv4_fallback() {
    if skip_without_seccomp("test_healthcheck_passes_on_the_ipv4_fallback") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("auto"), "", "enabled = false");
    let _server = config.start_without_ipv6();
    assert!(accepts_within(
        SocketAddr::new(V4, config.dns_port),
        Duration::from_secs(10)
    ));
    let log = server_log(config.dir.path());
    assert!(log.contains(FALLBACK_LINE), "{log}");

    let probe = config
        .command_without_ipv6(NO_IPV6)
        .arg("--healthcheck")
        .output()
        .unwrap();
    assert!(
        probe.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&probe.stderr),
        server_log(config.dir.path())
    );
}
