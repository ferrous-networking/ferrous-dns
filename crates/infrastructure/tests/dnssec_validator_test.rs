use ferrous_dns_domain::{DnssecStatus, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::trust_anchor::TrustAnchorStore;
use ferrous_dns_infrastructure::dns::dnssec::validation::authority::rrset_is_authentic;
use ferrous_dns_infrastructure::dns::dnssec::{DnskeyRecord, DnssecCache, DnssecValidatorPool};
use ferrous_dns_infrastructure::dns::PoolManager;
use hickory_proto::dnssec::crypto::Ed25519SigningKey;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
use hickory_proto::dnssec::{Algorithm, DnssecSigner, PublicKey, PublicKeyBuf, SigningKey};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType as HRT};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn make_pool_manager(server: String) -> Arc<PoolManager> {
    let pool = UpstreamPool {
        name: "test".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![server],
        weight: None,
    };
    Arc::new(PoolManager::new(vec![pool], None).await.unwrap())
}

fn make_a_record(name: &str, ip: Ipv4Addr) -> Record {
    let name = Name::from_str(name).unwrap();
    Record::from_rdata(name, 300, RData::A(A(ip)))
}

/// An A record at `owner`, its RRSIG made by a fresh Ed25519 key in the name of
/// `signer`, and that key.
fn signed_a(owner: &str, signer: &str) -> (Record, Record, DnskeyRecord) {
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let pub_bytes = signing_key.to_public_key().unwrap().public_bytes().to_vec();
    let key = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: pub_bytes.clone(),
    };
    let signer = DnssecSigner::new(
        HickoryDNSKEY::with_flags(256, PublicKeyBuf::new(pub_bytes, Algorithm::ED25519)),
        Box::new(signing_key),
        Name::from_str(signer).unwrap(),
        Duration::from_secs(7200),
    );

    let owner = Name::from_str(owner).unwrap();
    let a_record = make_a_record(&owner.to_string(), Ipv4Addr::new(192, 0, 2, 1));
    let mut rrset = RecordSet::new(owner.clone(), HRT::A, 0);
    rrset.insert(a_record.clone(), 0);
    let inception = OffsetDateTime::now_utc() - time::Duration::minutes(5);
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
    let rrsig_record = Record::from_rdata(owner, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));
    (a_record, rrsig_record, key)
}

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn authentic(a_record: &Record, sigs: &[Record], zone: &str, keys: Vec<DnskeyRecord>) -> bool {
    let keys: Arc<[DnskeyRecord]> = Arc::from(keys);
    let zone = Name::from_str(zone).unwrap();
    rrset_is_authentic(
        &a_record.name,
        HRT::A,
        std::slice::from_ref(a_record),
        sigs,
        now(),
        &|signer| (signer == &zone).then(|| Arc::clone(&keys)),
    )
}

#[test]
fn rrset_signed_by_an_established_zone_key_is_authentic() {
    let (a, sig, key) = signed_a("example.com.", "example.com.");
    assert!(authentic(&a, &[sig], "example.com.", vec![key]));
}

#[test]
fn rrset_whose_signer_has_no_established_keys_is_not_authentic() {
    let (a, sig, _) = signed_a("example.com.", "example.com.");
    assert!(!authentic(&a, &[sig], "unrelated.test.", vec![]));
}

#[test]
fn rrset_signed_with_a_key_the_zone_does_not_hold_is_not_authentic() {
    let (a, sig, _) = signed_a("example.com.", "example.com.");
    let wrong_key = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: vec![0u8; 32],
    };
    assert!(!authentic(&a, &[sig], "example.com.", vec![wrong_key]));
}

#[test]
fn rrset_signed_by_a_zone_that_does_not_enclose_it_is_not_authentic() {
    // Cross-zone forgery (RFC 4035 §5.3.1): an attacker who holds a real,
    // validly-chained zone signs a record for an unrelated victim name with
    // their own key. The signature verifies, but the signer does not enclose
    // the owner.
    let (a, sig, attacker_key) = signed_a("victim.bank.com.", "evil.example.");
    assert!(!authentic(&a, &[sig], "evil.example.", vec![attacker_key]));
}

/// A positive answer naming more distinct owners than the validator will walk
/// chains for: refused as Bogus before any upstream query.
fn answer_needing_too_many_walks() -> Message {
    let mut m = Message::new(0, MessageType::Response, OpCode::Query);
    for i in 0..9 {
        m.add_answer(make_a_record(
            &format!("host{i}.example."),
            Ipv4Addr::LOCALHOST,
        ));
    }
    m
}

async fn observe_query(
    upstream: &UdpSocket,
    validation: impl std::future::Future,
    expected_name: &str,
) {
    let mut wire = [0; 4096];
    let len = timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = validation => panic!("validation completed before querying the upstream"),
            result = upstream.recv_from(&mut wire) => result.unwrap().0,
        }
    })
    .await
    .expect("admitted validation must query the upstream");
    let query = Message::from_vec(&wire[..len]).unwrap();
    assert_eq!(
        query.queries[0].name().to_string().to_ascii_lowercase(),
        expected_name,
    );
}

#[tokio::test]
async fn next_free_validator_serves_the_oldest_waiter() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let manager = make_pool_manager(format!("udp://{}", upstream.local_addr().unwrap())).await;
    let pool = DnssecValidatorPool::new(
        manager,
        60_000,
        NonZeroUsize::new(2).unwrap(),
        TrustAnchorStore::new(),
        Arc::new(DnssecCache::new()),
    );
    let mut first = Box::pin(pool.validate_query("first.example.", RecordType::A));
    observe_query(&upstream, &mut first, "first.example.").await;

    let mut positive = Message::new(0, MessageType::Response, OpCode::Query);
    positive.add_answer(make_a_record("second.example.", Ipv4Addr::LOCALHOST));
    let mut second =
        Box::pin(pool.validate_with_message("second.example.", RecordType::A, &positive));
    // The second validator is suspended while bootstrapping the root keys.
    observe_query(&upstream, &mut second, ".").await;

    let instant = answer_needing_too_many_walks();
    let mut oldest =
        Box::pin(pool.validate_with_message("oldest.example.", RecordType::A, &instant));
    let mut younger = Box::pin(pool.validate_query("younger.example.", RecordType::A));
    assert!(futures::poll!(&mut oldest).is_pending());
    assert!(futures::poll!(&mut younger).is_pending());

    drop(second);
    // Even polling the younger waiter first cannot steal the returned validator.
    assert!(futures::poll!(&mut younger).is_pending());
    let result = timeout(Duration::from_secs(5), oldest)
        .await
        .expect("the oldest waiter must not wait for the still-busy first validator")
        .unwrap();
    assert_eq!(result, DnssecStatus::Bogus);
    observe_query(&upstream, &mut younger, "younger.example.").await;
}

#[tokio::test]
async fn cancelled_validation_and_waiters_restore_pool_capacity() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let manager = make_pool_manager(format!("udp://{}", upstream.local_addr().unwrap())).await;
    let pool = DnssecValidatorPool::new(
        manager,
        60_000,
        NonZeroUsize::MIN,
        TrustAnchorStore::empty(),
        Arc::new(DnssecCache::new()),
    );
    let mut active = Box::pin(pool.validate_query("active.example.", RecordType::A));
    observe_query(&upstream, &mut active, "active.example.").await;

    let instant = answer_needing_too_many_walks();
    let mut cancelled =
        Box::pin(pool.validate_with_message("cancelled.example.", RecordType::A, &instant));
    let mut admitted =
        Box::pin(pool.validate_with_message("admitted.example.", RecordType::A, &instant));
    let mut survivor =
        Box::pin(pool.validate_with_message("survivor.example.", RecordType::A, &instant));
    assert!(futures::poll!(&mut cancelled).is_pending());
    assert!(futures::poll!(&mut admitted).is_pending());
    assert!(futures::poll!(&mut survivor).is_pending());

    drop(cancelled);
    drop(active);
    // Cancel after capacity was assigned but before the waiter resumed.
    drop(admitted);
    let result = timeout(Duration::from_secs(5), survivor)
        .await
        .expect("cancellation must return both the validator and its capacity")
        .unwrap();
    assert_eq!(result, DnssecStatus::Bogus);
}
