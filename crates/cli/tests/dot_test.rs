//! DNS-over-TLS (DoT) server listener (RFC 7858) end-to-end tests.
//!
//! Binds the real `serve_dot` accept loop against a self-signed test
//! certificate and drives it with a real `tokio-rustls` client over the
//! RFC 7858 two-byte length-prefixed framing.
//!
//! Also covers the dual-stack peer path: on a `[::]` bind the kernel reports
//! IPv4 peers as `::ffff:a.b.c.d`, and the accept loop must normalise that
//! back to plain IPv4 before the per-IP connection limiter (and everything
//! else client-facing) sees it.

mod common;

use common::{
    build_a_query, dual_stack_loopback_available, handler_with_canned_addresses,
    SkipServerVerification,
};
use ferrous_dns::server::{
    bind_dot_listener, load_server_tls_config, serve_dot, ConnectionLimiter,
};
use ferrous_dns_application::ports::TlsCertificatePort;
use ferrous_dns_infrastructure::tls::TlsCertificateService;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use rustls::pki_types::ServerName;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Starts a DoT listener on `bind` with a fresh self-signed cert and the given
/// connection limiter. The listener is bound synchronously before this
/// returns, so callers can connect immediately with no bind race — the
/// resolved `SocketAddr` (actual port) is returned.
async fn start_test_dot_server_on(bind: &str, conn_limiter: ConnectionLimiter) -> SocketAddr {
    ferrous_dns::install_crypto_provider();

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    TlsCertificateService
        .generate_self_signed(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
        .await
        .unwrap();

    let tls_config = load_server_tls_config(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        "dot_test",
        &[],
    )
    .unwrap()
    .unwrap();

    let listener = Arc::new(bind_dot_listener(bind).unwrap());
    let addr = common::unmap_addr(listener.local_addr().unwrap());
    let handler =
        handler_with_canned_addresses(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], 300);
    // `tls_config` already holds the parsed cert and key, so the temp dir can
    // go away once we get here.
    tokio::spawn(serve_dot(
        listener,
        tls_config,
        handler,
        1,
        false,
        conn_limiter,
    ));
    addr
}

/// Builds a TLS client that trusts any server certificate — the test server
/// uses a throwaway self-signed cert, so there's nothing to chain to a root.
fn build_test_tls_connector() -> TlsConnector {
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    TlsConnector::from(Arc::new(tls_config))
}

#[tokio::test]
async fn round_trip_returns_expected_answer() {
    let addr = start_test_dot_server_on("127.0.0.1:0", ConnectionLimiter::new(0)).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = build_test_tls_connector()
        .connect(server_name, stream)
        .await
        .unwrap();

    let query = build_a_query("example.com");
    let query_id = u16::from_be_bytes([query[0], query[1]]);

    // RFC 7858 framing: a two-byte big-endian length prefix per message.
    tls_stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    tls_stream.write_all(&query).await.unwrap();

    let mut len_buf = [0u8; 2];
    tls_stream.read_exact(&mut len_buf).await.unwrap();
    let mut response = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    tls_stream.read_exact(&mut response).await.unwrap();

    let msg = Message::from_vec(&response).unwrap();
    assert_eq!(msg.id, query_id);
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn ipv4_client_on_a_dual_stack_bind_is_keyed_as_plain_ipv4() {
    // Needs a `[::]` socket that actually receives IPv4 — the whole point of
    // the test is the v4-mapped peer address a dual-stack bind produces.
    if !dual_stack_loopback_available() {
        eprintln!(
            "skipping ipv4_client_on_a_dual_stack_bind_is_keyed_as_plain_ipv4: \
             no dual-stack loopback available"
        );
        return;
    }

    let limiter = ConnectionLimiter::new(1);
    let bound = start_test_dot_server_on("[::]:0", limiter.clone()).await;

    // Take the single slot for plain 127.0.0.1. An IPv4 client reaching the
    // dual-stack listener arrives at the socket as ::ffff:127.0.0.1: unless
    // the accept loop unmaps it, the limiter keys it separately and lets the
    // connection through instead of dropping it.
    let _held = limiter
        .try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect("the single slot for 127.0.0.1 should be free");

    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port());
    let mut stream = TcpStream::connect(target).await.unwrap();

    // On the rejected path the accept loop drops the stream before the TLS
    // handshake, so the read must end promptly with EOF or a reset. If it
    // hangs, the server accepted the connection and is waiting for a
    // ClientHello — i.e. the peer was keyed as ::ffff:127.0.0.1 and the per-IP
    // limit never applied.
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(0)) => { /* EOF: the connection was dropped, as expected */ }
        Ok(Err(_reset)) => { /* connection reset: also the rejected path */ }
        Ok(Ok(n)) => panic!(
            "the server sent {n} byte(s) instead of dropping the connection, \
             so the IPv4 client was keyed as ::ffff:127.0.0.1 rather than 127.0.0.1"
        ),
        Err(_elapsed) => panic!(
            "the server kept the connection open waiting for a ClientHello, \
             so the IPv4 client was keyed as ::ffff:127.0.0.1 instead of 127.0.0.1 \
             and the per-IP limit did not apply"
        ),
    }
}
