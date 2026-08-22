//! Test doubles and helpers shared by the encrypted-DNS listener tests
//! (`doq_test.rs`, `dot_test.rs`).
//!
//! This module is compiled into every integration-test binary that declares
//! `mod common;`, so items only one binary uses would otherwise trip
//! dead-code warnings under `-D warnings`.
#![allow(dead_code)]

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, CacheStats, DnsResolution, DnsResolver, FilterDecision,
    PagedQueryResult, QueryLogRepository, TimeGranularity, TimelineBucket,
};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, DnsQuery, DnssecStats, DomainError, QueryLog, QueryLogFilter, QueryStats,
};
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use hickory_proto::op::{Message, MessageType, OpCode, Query as WireQuery};
use hickory_proto::rr::{DNSClass, Name, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

// ── Minimal port doubles (hand-rolled per crate test-placement convention —
// application crate mocks aren't reachable from the cli crate's test binary) ──

/// Resolver whose cache always hits with a fixed set of addresses, regardless
/// of the query's domain/type.
pub struct CannedAddressResolver {
    pub addresses: Vec<IpAddr>,
    pub ttl: u32,
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
pub struct AllowAllFilter;

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
pub struct NoopQueryLog;

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
pub fn handler_with_canned_addresses(addresses: Vec<IpAddr>, ttl: u32) -> Arc<DnsServerHandler> {
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
pub fn build_a_query(name: &str) -> Vec<u8> {
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

/// Dummy certificate verifier that accepts any certificate — the test server
/// uses a throwaway self-signed cert, so there's nothing to chain to a root.
#[derive(Debug)]
pub struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
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

/// True when a `[::]` socket also receives IPv4 traffic. Guards the dual-stack
/// tests: a host with `net.ipv6.bindv6only=1`, or no IPv6 at all, cannot
/// exercise the v4-mapped peer path.
pub fn dual_stack_loopback_available() -> bool {
    let Ok(server) = std::net::UdpSocket::bind("[::]:0") else {
        return false;
    };
    let Ok(local) = server.local_addr() else {
        return false;
    };
    if server
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
    {
        return false;
    }
    let Ok(client) = std::net::UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    if client
        .send_to(b"probe", ("127.0.0.1", local.port()))
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 8];
    server.recv_from(&mut buf).is_ok()
}
