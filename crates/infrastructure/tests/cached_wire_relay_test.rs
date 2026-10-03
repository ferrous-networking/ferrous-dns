//! The cached-wire fast path end to end, over a real `DnsCache` and
//! `CachedResolver`: a client gets its own cookie back and DNSSEC records
//! only when it set DO, and a hit the fast path cannot answer is logged once,
//! by the slow path that answers it.

#[path = "support/ports.rs"]
mod ports;

use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{
    CacheStats, DnsResolution, DnsResolver, PagedQueryResult, QueryLogRepository, TimeGranularity,
    TimelineBucket,
};
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, ClientProtocol, DnsCookiesConfig, DnsQuery, DnssecStats, DomainError,
    QueryLog, QueryLogFilter, QueryStats, RecordType,
};
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::fast_path::parse_query;
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use ferrous_dns_infrastructure::dns::{CachedData, DnsCache, DnsCacheConfig, EvictionStrategy};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::{MX, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType as WireType};
use hickory_proto::serialize::binary::BinEncodable;
use ports::{AllowAllFilter, NoopQueryLog};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const ID: u16 = 0x5a5a;
const CLIENT_COOKIE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
/// What the upstream echoed of the cookie we sent it.
const UPSTREAM_ECHO: [u8; 24] = [9; 24];

/// Every probe is served from the cache.
struct NoUpstream;

#[async_trait]
impl DnsResolver for NoUpstream {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::QueryTimeout)
    }
}

/// Counts the queries the use case logs.
#[derive(Default)]
struct CountingQueryLog(AtomicUsize);

#[async_trait]
impl QueryLogRepository for CountingQueryLog {
    async fn log_query(&self, _query: &QueryLog) -> Result<(), DomainError> {
        unimplemented!()
    }
    fn log_query_sync(&self, _query: &QueryLog) -> Result<(), DomainError> {
        self.0.fetch_add(1, Ordering::Relaxed);
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
        _page: ferrous_dns_application::ports::PageAt,
        _period_hours: f32,
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
        _period_hours: f32,
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

struct Server {
    handler: DnsServerHandler,
    /// Our server cookie for `CLIENT_COOKIE` from `CLIENT`.
    server_cookie: [u8; 8],
}

impl Server {
    /// A handler with DNS Cookies on, logging to `log`, whose cache holds
    /// `answers`.
    fn caching(answers: &[(&str, RecordType, Vec<u8>)], log: Arc<dyn QueryLogRepository>) -> Self {
        let cache = Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: 100,
            eviction_strategy: EvictionStrategy::HitRate,
            refresh_threshold: 0.75,
            batch_eviction_percentage: 0.1,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: 0,
            max_ttl: 86_400,
        }));
        for (name, record_type, wire) in answers {
            let data = CachedData::WireData(Bytes::from(wire.clone()));
            cache.insert(name, *record_type, data, 300, None);
        }
        let resolver = Arc::new(CachedResolver::new(Arc::new(NoUpstream), cache, 300, 4));
        let cookies = DnsCookiesConfig {
            require_valid_cookie: false,
            ..DnsCookiesConfig::default()
        };
        let use_case = HandleDnsQueryUseCase::new(resolver, Arc::new(AllowAllFilter), log)
            .with_dns_cookies(DnsCookieGuard::from_config(&cookies, [7; 32]));
        let server_cookie = use_case
            .cookie_guard()
            .expect("cookies are enabled")
            .generate_server_cookie(CLIENT, &CLIENT_COOKIE);
        let policy = BlockPolicy {
            mode: BlockResponseMode::NullIp,
            ttl: 60,
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
        };
        Self {
            handler: DnsServerHandler::new(Arc::new(use_case), policy),
            server_cookie,
        }
    }

    /// What the UDP worker's cached-wire fast path sends for `query`.
    fn fast(&self, query: &[u8]) -> Option<Message> {
        let parsed = parse_query(query).expect("a fast-path query");
        let reply = self
            .handler
            .try_fast_path_wire(&parsed, query, CLIENT, ClientProtocol::Udp)?;
        Some(Message::from_vec(&reply).expect("the reply decodes"))
    }

    /// What the slow path sends for `query`.
    async fn slow(&self, query: &[u8]) -> Message {
        let reply = self
            .handler
            .handle_raw_udp_fallback(query, CLIENT, ClientProtocol::Udp)
            .await
            .expect("answered");
        Message::from_vec(&reply).expect("the reply decodes")
    }
}

fn name(owner: &str) -> Name {
    Name::from_ascii(owner).unwrap()
}

/// An upstream answer to a `qtype` query for `owner` holding `answer`, then
/// an RRSIG over it when `signed`, then an OPT with `extended_rcode`, DO as
/// `dnssec_ok`, and the upstream's echo of our cookie.
fn upstream(
    owner: &str,
    qtype: WireType,
    answer: RData,
    signed: bool,
    dnssec_ok: bool,
    extended_rcode: u8,
) -> Vec<u8> {
    let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.add_query(Query::query(name(owner), qtype));
    msg.add_answer(Record::from_rdata(name(owner), 300, answer));
    let mut wire = msg.to_bytes().unwrap();
    if signed {
        let mut rdata = u16::from(qtype).to_be_bytes().to_vec();
        rdata.extend_from_slice(&[
            13, 3, 0, 0, 1, 0x2C, 0x70, 0, 0, 0, 0x60, 0, 0, 0, 0x12, 0x34,
        ]);
        rdata.extend_from_slice(b"\x07example\x03com\x00");
        rdata.extend_from_slice(&[0xAB; 64]);
        wire.extend_from_slice(&[0xC0, 0x0C, 0, 46, 0, 1, 0, 0, 1, 0x2C]);
        wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        wire.extend_from_slice(&rdata);
        wire[7] += 1;
    }
    wire.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, extended_rcode, 0]);
    wire.extend_from_slice(&[u8::from(dnssec_ok) << 7, 0, 0, 4 + 24, 0, 10, 0, 24]);
    wire.extend_from_slice(&UPSTREAM_ECHO);
    wire[11] += 1;
    wire
}

fn mx() -> RData {
    RData::MX(MX::new(10, name("mx1.example.com.")))
}

fn txt(text: &str) -> RData {
    RData::TXT(TXT::new(vec![text.to_string()]))
}

/// A query for `owner`, with an OPT carrying `cookie` when `edns` is
/// `Some(dnssec_ok)`.
fn query(owner: &str, qtype: WireType, edns: Option<bool>, cookie: Option<&[u8]>) -> Vec<u8> {
    let mut msg = Message::new(ID, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name(owner), qtype));
    if let Some(dnssec_ok) = edns {
        let mut opt = Edns::new();
        opt.set_max_payload(1232).set_dnssec_ok(dnssec_ok);
        if let Some(cookie) = cookie {
            opt.options_mut()
                .insert(EdnsOption::Unknown(10, cookie.to_vec()));
        }
        msg.set_edns(opt);
    }
    msg.to_bytes().unwrap()
}

fn cookie_of(reply: &Message) -> Option<Vec<u8>> {
    let opt = reply.edns.as_ref()?;
    opt.options().as_ref().iter().find_map(|(_, o)| match o {
        EdnsOption::Unknown(10, data) => Some(data.clone()),
        _ => None,
    })
}

fn types(records: &[Record]) -> Vec<WireType> {
    records.iter().map(Record::record_type).collect()
}

/// RFC 7873 §5.3: a client discards a reply that does not carry its own
/// cookie, so a cached answer must echo it beside our server cookie rather
/// than hand over the upstream's echo of the cookie we sent upstream.
#[test]
fn cached_answers_echo_the_client_cookie_beside_our_server_cookie() {
    let answers = [
        ("mail.example.com", RecordType::MX, WireType::MX, mx()),
        (
            "example.com",
            RecordType::TXT,
            WireType::TXT,
            txt("v=spf1 -all"),
        ),
    ];
    let server = Server::caching(
        &answers.clone().map(|(owner, record_type, qtype, answer)| {
            (
                owner,
                record_type,
                upstream(owner, qtype, answer, false, true, 0),
            )
        }),
        Arc::new(NoopQueryLog),
    );
    let ours = [&CLIENT_COOKIE[..], &server.server_cookie].concat();
    // A bare client cookie, and one returning an earlier server cookie.
    let stale = [&CLIENT_COOKIE[..], &[0xEE; 16]].concat();

    for (owner, _, qtype, answer) in answers {
        for sent in [&CLIENT_COOKIE[..], &stale] {
            let reply = server
                .fast(&query(owner, qtype, Some(false), Some(sent)))
                .expect("served on the fast path");
            assert_eq!(reply.metadata.id, ID);
            assert_eq!(reply.answers[0].data, answer, "{owner}");
            assert_eq!(cookie_of(&reply), Some(ours.clone()), "{owner}");
        }
        let reply = server
            .fast(&query(owner, qtype, Some(false), None))
            .expect("served on the fast path");
        assert!(reply.edns.is_some());
        assert_eq!(
            cookie_of(&reply),
            None,
            "{owner}: no cookie sent, none back"
        );
    }
}

/// RFC 3225 §3 / RFC 4035 §3.2.1: an answer cached from a DO=1 upstream
/// reaches a client that did not set DO with DO clear and without its
/// RRSIGs, and one that did set DO with both.
#[tokio::test]
async fn cached_dnssec_records_reach_only_clients_that_set_do() {
    let signed = upstream("mail.example.com", WireType::MX, mx(), true, true, 0);
    let unsigned = upstream("example.com", WireType::MX, mx(), false, true, 0);
    let server = Server::caching(
        &[
            ("mail.example.com", RecordType::MX, signed),
            ("example.com", RecordType::MX, unsigned),
        ],
        Arc::new(NoopQueryLog),
    );

    for owner in ["mail.example.com", "example.com"] {
        let edns = server
            .fast(&query(owner, WireType::MX, Some(false), None))
            .expect("served on the fast path");
        assert_eq!(types(&edns.answers), [WireType::MX], "{owner}");
        assert!(!edns.edns.expect("OPT echoed").flags().dnssec_ok, "{owner}");

        let cookie = server
            .fast(&query(
                owner,
                WireType::MX,
                Some(false),
                Some(&CLIENT_COOKIE),
            ))
            .expect("served on the fast path");
        assert_eq!(types(&cookie.answers), [WireType::MX], "{owner}");

        let plain = server
            .fast(&query(owner, WireType::MX, None, None))
            .expect("served on the fast path");
        assert_eq!(types(&plain.answers), [WireType::MX], "{owner}");
        assert!(plain.edns.is_none(), "{owner}");
    }

    let validating = server
        .slow(&query("mail.example.com", WireType::MX, Some(true), None))
        .await;
    assert_eq!(types(&validating.answers), [WireType::MX, WireType::RRSIG]);
    assert!(validating.edns.expect("OPT echoed").flags().dnssec_ok);
}

/// A hit the fast path declines (too big for the client's buffer, or an
/// extended RCODE a client without OPT cannot receive) is answered, and
/// logged, by the slow path alone.
#[tokio::test]
async fn a_hit_the_fast_path_declines_is_logged_once() {
    let big = RData::TXT(TXT::new(vec!["x".repeat(250), "y".repeat(250)]));
    let big = upstream("big.example.com", WireType::TXT, big, false, true, 0);
    let extended = upstream("odd.example.com", WireType::TXT, txt("v"), false, true, 1);
    let log = Arc::new(CountingQueryLog::default());
    let server = Server::caching(
        &[
            ("big.example.com", RecordType::TXT, big),
            ("odd.example.com", RecordType::TXT, extended),
        ],
        log.clone(),
    );
    let logged = || log.0.load(Ordering::Relaxed);

    let q = query("big.example.com", WireType::TXT, None, None);
    assert!(server.fast(&q).is_none(), "too big for 512 bytes");
    assert_eq!(logged(), 0);
    let reply = server.slow(&q).await;
    assert!(reply.metadata.truncation);
    assert_eq!(logged(), 1);

    let q = query("odd.example.com", WireType::TXT, None, None);
    assert!(server.fast(&q).is_none(), "no OPT to carry the RCODE");
    assert_eq!(logged(), 1);
    let reply = server.slow(&q).await;
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(logged(), 2);
}

/// RFC 1035 §3.2.1, RFC 2181 §8: a cached answer's TTLs count down its
/// time in the cache, on every record and on either path, never past what
/// the entry has left.
#[tokio::test]
async fn cached_answers_count_down_every_ttl() {
    let exchange = name("mx1.example.com.");
    let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name("mail.example.com."), WireType::MX));
    msg.add_answer(Record::from_rdata(name("mail.example.com."), 300, mx()));
    msg.add_authority(Record::from_rdata(
        name("example.com."),
        3600,
        RData::NS(hickory_proto::rr::rdata::NS(exchange.clone())),
    ));
    msg.add_additional(Record::from_rdata(
        exchange,
        120,
        RData::A(Ipv4Addr::new(192, 0, 2, 25).into()),
    ));
    msg.set_edns(Edns::new());
    coarse_clock::tick();
    let server = Server::caching(
        &[("mail.example.com", RecordType::MX, msg.to_bytes().unwrap())],
        Arc::new(NoopQueryLog),
    );
    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let ttls = |reply: &Message| -> Vec<u32> {
        [&reply.answers, &reply.authorities, &reply.additionals]
            .into_iter()
            .flatten()
            .map(|r| r.ttl)
            .collect()
    };
    let replies = [
        server.fast(&query("mail.example.com", WireType::MX, Some(false), None)),
        server.fast(&query("mail.example.com", WireType::MX, None, None)),
        server.fast(&query(
            "mail.example.com",
            WireType::MX,
            Some(false),
            Some(&CLIENT_COOKIE),
        )),
        Some(
            server
                .slow(&query("mail.example.com", WireType::MX, Some(true), None))
                .await,
        ),
    ];
    for reply in replies {
        let reply = reply.expect("served on the fast path");
        let got = ttls(&reply);
        let age = 300 - got[0];
        assert!(age >= 1, "counted down: {got:?}");
        // The NS may not outlive the entry; the glue has its own countdown.
        assert_eq!(got, [300 - age, 300 - age, 120 - age]);
    }
}

/// A resolver that sends 0x20-randomized names drops an answer whose
/// question is not spelled as it asked; the cache holds one spelling for every
/// client. A different name, as a Safe Search rewrite answers with, stays.
#[tokio::test]
async fn cached_answers_echo_the_question_as_the_client_spelled_it() {
    let rewritten = upstream("safe.example.net", WireType::MX, mx(), false, true, 0);
    let server = Server::caching(
        &[
            (
                "mail.example.com",
                RecordType::MX,
                upstream("mail.example.com", WireType::MX, mx(), false, true, 0),
            ),
            ("www.example.com", RecordType::MX, rewritten),
        ],
        Arc::new(NoopQueryLog),
    );
    let spelled = |reply: &Message| {
        (
            reply.queries[0].name().to_string(),
            reply.answers[0].name.to_string(),
        )
    };
    let cookie = Some(&CLIENT_COOKIE[..]);

    for (owner, echoed) in [
        ("MaIl.ExAmPlE.cOm.", "MaIl.ExAmPlE.cOm."),
        ("wWw.ExAmPlE.cOm.", "safe.example.net."),
    ] {
        let mut replies = Vec::new();
        for (edns, cookie) in [(None, None), (Some(false), None), (Some(false), cookie)] {
            replies.push(
                server
                    .fast(&query(owner, WireType::MX, edns, cookie))
                    .expect("hit"),
            );
        }
        for (edns, cookie) in [(Some(true), None), (Some(true), cookie)] {
            replies.push(server.slow(&query(owner, WireType::MX, edns, cookie)).await);
        }
        for reply in replies {
            assert_eq!(spelled(&reply), (echoed.into(), echoed.into()), "{owner}");
        }
    }
}
