//! DNS-over-QUIC (DoQ) server listener (RFC 9250) end-to-end tests.
//!
//! Starts the real `start_doq_server` accept loop against a self-signed test
//! certificate and drives it with a real `quinn` client, mirroring the
//! upstream DoQ client setup in
//! `ferrous_dns_infrastructure::dns::transport::quic`.

use async_trait::async_trait;
use ferrous_dns::server::{
    bind_doq_endpoint, load_server_tls_config, serve_doq, ConnectionLimiter,
};
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, CacheStats, DnsResolution, DnsResolver, FilterDecision,
    PagedQueryResult, QueryLogRepository, TimeGranularity, TimelineBucket, TlsCertificatePort,
};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, DnsQuery, DnssecStats, DomainError, QueryLog, QueryLogFilter, QueryStats,
};
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use ferrous_dns_infrastructure::tls::TlsCertificateService;
use hickory_proto::op::{Message, MessageType, OpCode, Query as WireQuery};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

// ── Minimal port doubles (hand-rolled per crate test-placement convention —
// application crate mocks aren't reachable from the cli crate's test binary) ──

/// Resolver whose cache always hits with a fixed set of addresses, regardless
/// of the query's domain/type.
struct CannedAddressResolver {
    addresses: Vec<IpAddr>,
    ttl: u32,
}

#[async_trait]
impl DnsResolver for CannedAddressResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        unimplemented!("cache hit only")
    }

    fn try_cache(&self, _query: &DnsQuery) -> Option<DnsResolution> {
        let mut res = DnsResolution::new(self.addresses.clone(), true);
        res.min_ttl = Some(self.ttl);
        Some(res)
    }
}

/// Allows every domain; assigns the default group.
struct AllowAllFilter;

#[async_trait]
impl BlockFilterEnginePort for AllowAllFilter {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        0
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
    fn is_blocking_enabled(&self) -> bool {
        false
    }
    fn set_blocking_enabled(&self, _enabled: bool) {}
}

/// Drops every logged query.
struct NoopQueryLog;

#[async_trait]
impl QueryLogRepository for NoopQueryLog {
    async fn log_query(&self, _query: &QueryLog) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_recent(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        unimplemented!()
    }
    async fn get_recent_paged(
        &self,
        _limit: u32,
        _offset: u32,
        _period_hours: f32,
        _cursor: Option<i64>,
        _filter: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError> {
        unimplemented!()
    }
    async fn get_stats(&self, _period_hours: f32) -> Result<QueryStats, DomainError> {
        unimplemented!()
    }
    async fn get_dnssec_stats(&self, _period_hours: f32) -> Result<DnssecStats, DomainError> {
        unimplemented!()
    }
    async fn get_timeline(
        &self,
        _period_hours: u32,
        _granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        unimplemented!()
    }
    async fn count_queries_since(&self, _seconds_ago: i64) -> Result<u64, DomainError> {
        unimplemented!()
    }
    async fn get_cache_stats(&self, _period_hours: f32) -> Result<CacheStats, DomainError> {
        unimplemented!()
    }
    async fn get_top_blocked_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_top_allowed_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_distinct_recent_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_top_clients(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        unimplemented!()
    }
    async fn delete_older_than(&self, _days: u32) -> Result<u64, DomainError> {
        unimplemented!()
    }
}

/// Builds a handler that always resolves to `addresses` with the given TTL.
fn handler_with_canned_addresses(addresses: Vec<IpAddr>, ttl: u32) -> Arc<DnsServerHandler> {
    let resolver: Arc<dyn DnsResolver> = Arc::new(CannedAddressResolver { addresses, ttl });
    let use_case = Arc::new(HandleDnsQueryUseCase::new(
        resolver,
        Arc::new(AllowAllFilter),
        Arc::new(NoopQueryLog),
    ));
    Arc::new(DnsServerHandler::new(
        use_case,
        BlockPolicy {
            mode: BlockResponseMode::NullIp,
            ttl: 60,
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
        },
    ))
}

/// Builds a valid wire-format A-record query for `name`.
fn build_a_query(name: &str) -> Vec<u8> {
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let mut query = WireQuery::new();
    query.set_name(Name::from_str(&fqdn).unwrap());
    query.set_query_type(HickoryRecordType::A);
    query.set_query_class(DNSClass::IN);

    let mut message = Message::new(fastrand::u16(..), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(query);

    let mut buf = Vec::with_capacity(64);
    let mut encoder = BinEncoder::new(&mut buf);
    message.emit(&mut encoder).unwrap();
    buf
}

/// Starts a DoQ listener on an ephemeral loopback port with a fresh
/// self-signed cert and the given connection limiter. The endpoint is bound
/// synchronously before this returns, so callers can connect immediately with
/// no bind race — the resolved `SocketAddr` (actual port) is returned.
async fn start_test_doq_server(conn_limiter: ConnectionLimiter) -> SocketAddr {
    start_test_doq_server_on("127.0.0.1:0", conn_limiter).await
}

async fn start_test_doq_server_on(bind: &str, conn_limiter: ConnectionLimiter) -> SocketAddr {
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
        "doq_test",
        &[b"doq"],
    )
    .unwrap()
    .unwrap();

    let endpoint = bind_doq_endpoint(bind, tls_config).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let handler =
        handler_with_canned_addresses(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], 300);
    tokio::spawn(serve_doq(endpoint, handler, conn_limiter));
    addr
}

/// Dummy certificate verifier that accepts any certificate — the test server
/// uses a throwaway self-signed cert, so there's nothing to chain to a root.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Builds a `quinn` client endpoint configured for DoQ (ALPN `doq`) that
/// trusts any server certificate — mirrors
/// `ferrous_dns_infrastructure::dns::transport::quic`'s client setup, minus
/// the pooling and with a permissive verifier for the test's self-signed cert.
fn build_test_client_endpoint() -> quinn::Endpoint {
    build_client_endpoint("127.0.0.1:0", vec![b"doq".to_vec()])
}

/// Builds a `quinn` client endpoint bound to `local`, offering the given ALPN
/// protocol list. Trusts any server certificate (self-signed test cert).
fn build_client_endpoint(local: &str, alpn: Vec<Vec<u8>>) -> quinn::Endpoint {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    tls_config.alpn_protocols = alpn;

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .expect("valid QUIC TLS config");
    let client_config = quinn::ClientConfig::new(Arc::new(quic_config));

    let mut endpoint =
        quinn::Endpoint::client(local.parse().unwrap()).expect("QUIC client endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Opens a bi-stream on `connection`, sends `query_bytes` length-prefixed,
/// and reads back a length-prefixed response.
async fn send_query_on(connection: &quinn::Connection, query_bytes: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&(query_bytes.len() as u16).to_be_bytes())
        .await
        .unwrap();
    send.write_all(query_bytes).await.unwrap();
    send.finish().unwrap();

    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    recv.read_exact(&mut resp).await.unwrap();
    resp
}

#[tokio::test]
async fn round_trip_returns_expected_answer() {
    let addr = start_test_doq_server(ConnectionLimiter::new(0)).await;

    let endpoint = build_test_client_endpoint();
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    let query = build_a_query("example.com");
    let query_id = u16::from_be_bytes([query[0], query[1]]);

    let response = send_query_on(&connection, &query).await;
    let msg = Message::from_vec(&response).unwrap();

    assert_eq!(msg.id, query_id);
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn multiple_streams_on_one_connection_each_get_a_response() {
    let addr = start_test_doq_server(ConnectionLimiter::new(0)).await;

    let endpoint = build_test_client_endpoint();
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    let queries: Vec<Vec<u8>> = vec![
        build_a_query("one.example.com"),
        build_a_query("two.example.com"),
        build_a_query("three.example.com"),
    ];
    let query_ids: Vec<u16> = queries
        .iter()
        .map(|q| u16::from_be_bytes([q[0], q[1]]))
        .collect();

    let futures = queries.iter().map(|q| send_query_on(&connection, q));
    let responses = futures::future::join_all(futures).await;

    for (response, expected_id) in responses.iter().zip(query_ids.iter()) {
        let msg = Message::from_vec(response).unwrap();
        assert_eq!(msg.id, *expected_id);
        assert_eq!(msg.answers.len(), 1);
    }
}

#[tokio::test]
async fn per_ip_connection_limit_is_enforced() {
    let addr = start_test_doq_server(ConnectionLimiter::new(1)).await;

    let first_endpoint = build_test_client_endpoint();
    let first_connection = first_endpoint
        .connect(addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // First connection stays open, occupying the one allowed slot. The second
    // must be actively refused (incoming.refuse()) — which resolves promptly to
    // a ConnectionError — NOT left hanging. A timeout here is a failure, not a
    // pass: it would mean the server stalled instead of rejecting.
    let second_endpoint = build_test_client_endpoint();
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        second_endpoint.connect(addr, "localhost").unwrap(),
    )
    .await;

    match outcome {
        Ok(Ok(_conn)) => {
            panic!("second connection should have been refused by the per-IP limit")
        }
        Ok(Err(_refused)) => { /* refused as expected */ }
        Err(_elapsed) => {
            panic!("refused connection should resolve promptly, not hang past the timeout")
        }
    }

    drop(first_connection);
}

#[tokio::test]
async fn wrong_alpn_is_rejected() {
    let addr = start_test_doq_server(ConnectionLimiter::new(0)).await;

    // A client offering only a non-`doq` ALPN must fail the QUIC/TLS handshake:
    // the server advertises `doq` alone, so there is no protocol overlap.
    let endpoint = build_client_endpoint("127.0.0.1:0", vec![b"h3".to_vec()]);
    let result = endpoint.connect(addr, "localhost").unwrap().await;

    assert!(
        result.is_err(),
        "handshake with a non-doq ALPN must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn malformed_streams_do_not_break_the_connection() {
    let addr = start_test_doq_server(ConnectionLimiter::new(0)).await;

    let endpoint = build_test_client_endpoint();
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    // (a) Zero-length prefix: the server reads the 2-byte length, sees 0, and
    // drops the stream without dispatching anything.
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    send.write_all(&0u16.to_be_bytes()).await.unwrap();
    send.finish().unwrap();

    // (b) Length prefix that overstates the body, then EOF: the body read hits
    // an unexpected EOF and the stream is dropped — no response, no hang.
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    send.write_all(&100u16.to_be_bytes()).await.unwrap();
    send.write_all(b"short").await.unwrap();
    send.finish().unwrap();

    // (c) Well-framed but not a valid DNS message: the handler parses nothing
    // and returns no response, so the client reads back zero bytes.
    let garbage = b"\xff\xff not a dns message";
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&(garbage.len() as u16).to_be_bytes())
        .await
        .unwrap();
    send.write_all(garbage).await.unwrap();
    send.finish().unwrap();
    let leftover = recv.read_to_end(512).await.unwrap_or_default();
    assert!(
        leftover.is_empty(),
        "a malformed query must not produce a response"
    );

    // The connection survived all three malformed streams: a valid query on a
    // fresh stream still round-trips correctly.
    let query = build_a_query("example.com");
    let response = send_query_on(&connection, &query).await;
    let msg = Message::from_vec(&response).unwrap();
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[tokio::test]
async fn round_trip_over_ipv6() {
    // Some CI sandboxes have no IPv6 loopback — skip rather than fail there.
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("skipping round_trip_over_ipv6: no IPv6 loopback available");
        return;
    }

    let addr = start_test_doq_server_on("[::1]:0", ConnectionLimiter::new(2)).await;

    let endpoint = build_client_endpoint("[::1]:0", vec![b"doq".to_vec()]);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    // Exercises the IPv6 peer path: the per-connection client_ip is a v6 address
    // and the limiter is keyed on it.
    let query = build_a_query("example.com");
    let response = send_query_on(&connection, &query).await;
    let msg = Message::from_vec(&response).unwrap();
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("expected an A record, got {other:?}"),
    }
}
