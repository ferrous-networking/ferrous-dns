//! End-to-end validation against an in-process signed hierarchy.
//!
//! A fake upstream serves `.` → `test.` → `example.test.`, all Ed25519-signed,
//! plus `insecure.test.` (an unsigned delegation that `test.` proves with a
//! signed NSEC) and `stripped.test.` (whose DS denial an attacker removed). The
//! validator is anchored on the fake root key, so every verdict comes from real
//! signature math and the real chain walk; only the network is simulated.

use data_encoding::BASE64;
use ferrous_dns_domain::{DnssecStatus, RecordType as FRecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::trust_anchor::TrustAnchorStore;
use ferrous_dns_infrastructure::dns::dnssec::{DnssecCache, DnssecValidator};
use ferrous_dns_infrastructure::dns::PoolManager;
use hickory_proto::dnssec::crypto::Ed25519SigningKey;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, NSEC, RRSIG};
use hickory_proto::dnssec::{
    Algorithm, DigestType, DnssecSigner, PublicKey, PublicKeyBuf, SigningKey,
};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::UdpSocket;

const TTL: u32 = 300;

fn n(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

struct Zone {
    apex: Name,
    dnskey: DNSKEY,
    signer: DnssecSigner,
}

impl Zone {
    fn new(apex: &str) -> Self {
        let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
        let key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
        let public = key.to_public_key().unwrap();
        let dnskey = DNSKEY::with_flags(
            257,
            PublicKeyBuf::new(public.public_bytes().to_vec(), Algorithm::ED25519),
        );
        let apex = n(apex);
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            apex.clone(),
            Duration::from_secs(86_400),
        );
        Self {
            apex,
            dnskey,
            signer,
        }
    }

    /// `records` plus the RRSIG this zone makes over them (one RRset).
    fn signed(&self, records: Vec<Record>) -> Vec<Record> {
        let owner = records[0].name.clone();
        let mut rrset = RecordSet::new(owner.clone(), records[0].record_type(), 0);
        for record in &records {
            rrset.insert(record.clone(), 0);
        }
        let inception = OffsetDateTime::now_utc() - time::Duration::minutes(5);
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &self.signer).unwrap();
        let mut out = records;
        out.push(Record::from_rdata(
            owner,
            TTL,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        ));
        out
    }

    fn dnskey_rrset(&self) -> Vec<Record> {
        self.signed(vec![Record::from_rdata(
            self.apex.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )])
    }

    fn ds_record(&self) -> Record {
        let ds = DS::from_key(self.dnskey.public_key(), &self.apex, DigestType::SHA256).unwrap();
        Record::from_rdata(self.apex.clone(), TTL, RData::DNSSEC(DNSSECRData::DS(ds)))
    }

    fn nsec(&self, owner: &str, next: &str, types: &[RecordType]) -> Vec<Record> {
        self.signed(vec![Record::from_rdata(
            n(owner),
            TTL,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(n(next), types.iter().copied()))),
        )])
    }

    fn soa(&self) -> Vec<Record> {
        let soa = SOA::new(
            self.apex.clone(),
            self.apex.clone(),
            1,
            3600,
            600,
            86_400,
            TTL,
        );
        self.signed(vec![Record::from_rdata(
            self.apex.clone(),
            TTL,
            RData::SOA(soa),
        )])
    }

    /// SOA plus the given NSEC proof, as a negative answer's authority section.
    fn denial(&self, nsecs: Vec<Record>) -> Vec<Record> {
        let mut authority = self.soa();
        authority.extend(nsecs);
        authority
    }

    fn anchor(&self) -> TrustAnchorStore {
        format!(
            ". 3600 IN DNSKEY 257 3 15 {}",
            BASE64.encode(self.dnskey.public_key().public_bytes())
        )
        .parse()
        .unwrap()
    }
}

struct Reply {
    rcode: ResponseCode,
    answers: Vec<Record>,
    authorities: Vec<Record>,
}

fn reply(answers: Vec<Record>, authorities: Vec<Record>) -> Reply {
    Reply {
        rcode: ResponseCode::NoError,
        answers,
        authorities,
    }
}

type Key = (String, RecordType);

fn key(name: &str, rtype: RecordType) -> Key {
    (n(name).to_lowercase().to_string(), rtype)
}

struct Hierarchy {
    test: Zone,
    example: Zone,
    upstream: Arc<HashMap<Key, Reply>>,
    /// Queries the fake upstream has answered.
    queries: Arc<AtomicUsize>,
    anchor: TrustAnchorStore,
}

fn hierarchy() -> Hierarchy {
    use RecordType::*;
    let root = Zone::new(".");
    let test = Zone::new("test.");
    let example = Zone::new("example.test.");

    let mut up = HashMap::new();
    up.insert(key(".", DNSKEY), reply(root.dnskey_rrset(), vec![]));
    up.insert(
        key("test.", DS),
        reply(root.signed(vec![test.ds_record()]), vec![]),
    );
    up.insert(key("test.", DNSKEY), reply(test.dnskey_rrset(), vec![]));
    up.insert(
        key("example.test.", DS),
        reply(test.signed(vec![example.ds_record()]), vec![]),
    );
    up.insert(
        key("example.test.", DNSKEY),
        reply(example.dnskey_rrset(), vec![]),
    );
    // A real delegation (NS bit) with no DS: provably unsigned.
    up.insert(
        key("insecure.test.", DS),
        reply(
            vec![],
            test.denial(test.nsec("insecure.test.", "stripped.test.", &[NS, RRSIG, NSEC])),
        ),
    );
    // The attacker's empty DS answer, denial proof removed.
    up.insert(key("stripped.test.", DS), reply(vec![], vec![]));
    // Plain hosts inside example.test.: no DS, and no NS bit, so not zone cuts.
    up.insert(
        key("www.example.test.", DS),
        reply(
            vec![],
            example.denial(example.nsec("www.example.test.", "example.test.", &[A, RRSIG, NSEC])),
        ),
    );
    up.insert(
        key("alias.example.test.", DS),
        reply(
            vec![],
            example.denial(example.nsec(
                "alias.example.test.",
                "www.example.test.",
                &[CNAME, RRSIG, NSEC],
            )),
        ),
    );
    up.insert(
        key("nope.example.test.", DS),
        Reply {
            rcode: ResponseCode::NXDomain,
            answers: vec![],
            authorities: example.denial(nxdomain_proof(&example)),
        },
    );

    Hierarchy {
        anchor: root.anchor(),
        test,
        example,
        upstream: Arc::new(up),
        queries: Arc::new(AtomicUsize::new(0)),
    }
}

/// NSECs proving `nope.example.test.` and `*.example.test.` absent.
fn nxdomain_proof(example: &Zone) -> Vec<Record> {
    use RecordType::*;
    let mut proof = example.nsec(
        "alias.example.test.",
        "www.example.test.",
        &[CNAME, RRSIG, NSEC],
    );
    proof.extend(example.nsec(
        "example.test.",
        "alias.example.test.",
        &[SOA, NS, DNSKEY, RRSIG, NSEC],
    ));
    proof
}

async fn serve(socket: UdpSocket, upstream: Arc<HashMap<Key, Reply>>, queries: Arc<AtomicUsize>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Ok(query) = Message::from_vec(&buf[..len]) else {
            continue;
        };
        let Some(question) = query.queries.first().cloned() else {
            continue;
        };
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        queries.fetch_add(1, Ordering::Relaxed);
        let k = (
            question.name().to_lowercase().to_string(),
            question.query_type(),
        );
        response.add_query(question);
        if let Some(r) = upstream.get(&k) {
            response.metadata.response_code = r.rcode;
            response.add_answers(r.answers.iter().cloned());
            response.add_authorities(r.authorities.iter().cloned());
        }
        let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
    }
}

async fn validator(h: &Hierarchy) -> DnssecValidator {
    validator_with_cache(h, Arc::new(DnssecCache::new())).await
}

async fn validator_with_cache(h: &Hierarchy, cache: Arc<DnssecCache>) -> DnssecValidator {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(serve(
        socket,
        Arc::clone(&h.upstream),
        Arc::clone(&h.queries),
    ));
    let pool = UpstreamPool {
        name: "fake".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![format!("udp://{addr}")],
        weight: None,
    };
    let pm = Arc::new(PoolManager::new(vec![pool], None).await.unwrap());
    DnssecValidator::new(pm, h.anchor.clone(), cache, 2_000)
}

fn message(rcode: ResponseCode, answers: Vec<Record>, authorities: Vec<Record>) -> Message {
    let mut m = Message::new(0, MessageType::Response, OpCode::Query);
    m.metadata.response_code = rcode;
    m.add_answers(answers);
    m.add_authorities(authorities);
    m
}

fn a(owner: &str) -> Record {
    Record::from_rdata(n(owner), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))))
}

async fn verdict(h: &Hierarchy, qname: &str, qtype: FRecordType, m: Message) -> DnssecStatus {
    validator(h)
        .await
        .validate_with_message(qname, qtype, &m)
        .await
}

#[tokio::test]
async fn signed_answer_is_secure() {
    let h = hierarchy();
    let m = message(
        ResponseCode::NoError,
        h.example.signed(vec![a("www.example.test.")]),
        vec![],
    );
    assert_eq!(
        verdict(&h, "www.example.test", FRecordType::A, m).await,
        DnssecStatus::Secure
    );
}

#[tokio::test]
async fn signed_answer_stays_secure_once_the_chain_is_cached() {
    let h = hierarchy();
    let mut v = validator(&h).await;
    for round in 0..2 {
        let m = message(
            ResponseCode::NoError,
            h.example.signed(vec![a("www.example.test.")]),
            vec![],
        );
        assert_eq!(
            v.validate_with_message("www.example.test", FRecordType::A, &m)
                .await,
            DnssecStatus::Secure,
            "round {round}"
        );
    }
}

#[tokio::test]
async fn verdicts_hold_when_ds_denials_come_from_the_cache() {
    let h = hierarchy();
    let cache = Arc::new(DnssecCache::new());
    let mut v = validator_with_cache(&h, Arc::clone(&cache)).await;
    for round in 0..2 {
        let stripped = message(ResponseCode::NoError, vec![a("www.example.test.")], vec![]);
        assert_eq!(
            v.validate_with_message("www.example.test", FRecordType::A, &stripped)
                .await,
            DnssecStatus::Bogus,
            "round {round}: a cached not-a-zone-cut proof must not read as insecure"
        );
        let unsigned = message(
            ResponseCode::NoError,
            vec![a("host.insecure.test.")],
            vec![],
        );
        assert_eq!(
            v.validate_with_message("host.insecure.test", FRecordType::A, &unsigned)
                .await,
            DnssecStatus::Insecure,
            "round {round}"
        );
    }
    assert!(
        cache.stats().total_ds_hits > 0,
        "the second round must have walked through cached DS answers"
    );
}

#[tokio::test]
async fn parent_delegation_nsec_cannot_deny_names_in_the_child_zone() {
    // RFC 6840 §4.1: test.'s NSEC at the example.test. cut covers every name
    // below it in canonical order, but those names live in the child zone.
    let h = hierarchy();
    use RecordType::*;
    let forged = h.test.denial(h.test.nsec(
        "example.test.",
        "insecure.test.",
        &[NS, DS, RRSIG, NSEC],
    ));
    let m = message(ResponseCode::NXDomain, vec![], forged);
    assert_eq!(
        verdict(&h, "nope.example.test", FRecordType::A, m).await,
        DnssecStatus::Bogus
    );
}

#[tokio::test]
async fn stripped_rrsig_inside_a_signed_zone_is_bogus() {
    let h = hierarchy();
    let m = message(ResponseCode::NoError, vec![a("www.example.test.")], vec![]);
    assert_eq!(
        verdict(&h, "www.example.test", FRecordType::A, m).await,
        DnssecStatus::Bogus,
        "an unsigned answer from a provably signed zone is a downgrade, not Insecure"
    );
}

#[tokio::test]
async fn unsigned_answer_below_a_proven_insecure_delegation_is_insecure() {
    let h = hierarchy();
    let m = message(
        ResponseCode::NoError,
        vec![a("host.insecure.test.")],
        vec![],
    );
    assert_eq!(
        verdict(&h, "host.insecure.test", FRecordType::A, m).await,
        DnssecStatus::Insecure
    );
}

#[tokio::test]
async fn missing_ds_denial_is_bogus() {
    let h = hierarchy();
    let m = message(
        ResponseCode::NoError,
        vec![a("host.stripped.test.")],
        vec![],
    );
    assert_eq!(
        verdict(&h, "host.stripped.test", FRecordType::A, m).await,
        DnssecStatus::Bogus,
        "an empty DS answer without the parent's signed denial proves nothing"
    );
}

#[tokio::test]
async fn unsigned_nxdomain_inside_a_signed_zone_is_bogus() {
    let h = hierarchy();
    let m = message(ResponseCode::NXDomain, vec![], vec![]);
    assert_eq!(
        verdict(&h, "nope.example.test", FRecordType::A, m).await,
        DnssecStatus::Bogus
    );
}

#[tokio::test]
async fn unsigned_nxdomain_below_an_insecure_delegation_is_insecure() {
    let h = hierarchy();
    let m = message(ResponseCode::NXDomain, vec![], vec![]);
    assert_eq!(
        verdict(&h, "nope.insecure.test", FRecordType::A, m).await,
        DnssecStatus::Insecure
    );
}

#[tokio::test]
async fn signed_nxdomain_is_secure() {
    let h = hierarchy();
    let m = message(ResponseCode::NXDomain, vec![], nxdomain_proof(&h.example));
    assert_eq!(
        verdict(&h, "nope.example.test", FRecordType::A, m).await,
        DnssecStatus::Secure
    );
}

#[tokio::test]
async fn signed_cname_into_an_insecure_zone_is_insecure() {
    let h = hierarchy();
    let mut answers = h.example.signed(vec![Record::from_rdata(
        n("alias.example.test."),
        TTL,
        RData::CNAME(CNAME(n("cdn.insecure.test."))),
    )]);
    answers.push(a("cdn.insecure.test."));
    let m = message(ResponseCode::NoError, answers, vec![]);
    assert_eq!(
        verdict(&h, "alias.example.test", FRecordType::A, m).await,
        DnssecStatus::Insecure,
        "the unsigned target sits under a proven-insecure cut; only the CNAME is signed"
    );
}

#[tokio::test]
async fn stripped_cname_target_inside_a_signed_zone_is_bogus() {
    let h = hierarchy();
    let mut answers = h.example.signed(vec![Record::from_rdata(
        n("alias.example.test."),
        TTL,
        RData::CNAME(CNAME(n("www.example.test."))),
    )]);
    answers.push(a("www.example.test."));
    let m = message(ResponseCode::NoError, answers, vec![]);
    assert_eq!(
        verdict(&h, "alias.example.test", FRecordType::A, m).await,
        DnssecStatus::Bogus
    );
}

#[tokio::test]
async fn warm_walks_send_no_upstream_queries() {
    // Once the chain is cached, validating again must not touch the upstream —
    // in particular no DNSKEY lookup for a zone proven unsigned, whose missing
    // keys can never be cached.
    let h = hierarchy();
    let mut v = validator(&h).await;
    let cases = [
        (
            "www.example.test",
            message(
                ResponseCode::NoError,
                h.example.signed(vec![a("www.example.test.")]),
                vec![],
            ),
        ),
        (
            "host.insecure.test",
            message(
                ResponseCode::NoError,
                vec![a("host.insecure.test.")],
                vec![],
            ),
        ),
        (
            "nope.insecure.test",
            message(ResponseCode::NXDomain, vec![], vec![]),
        ),
    ];
    for (qname, m) in &cases {
        v.validate_with_message(qname, FRecordType::A, m).await;
    }
    let cold = h.queries.load(Ordering::Relaxed);
    for (qname, m) in &cases {
        v.validate_with_message(qname, FRecordType::A, m).await;
    }
    assert_eq!(h.queries.load(Ordering::Relaxed), cold);
}
