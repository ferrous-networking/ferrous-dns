use ferrous_dns_domain::{RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::trust_anchor::TrustAnchorStore;
use ferrous_dns_infrastructure::dns::dnssec::{
    DnskeyRecord, DnssecValidator, DnssecValidatorPool, ValidationResult,
};
use ferrous_dns_infrastructure::dns::PoolManager;
use ferrous_dns_infrastructure::dns::QueryEventEmitter;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;

use std::time::Duration;
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
    Arc::new(
        PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled())
            .await
            .unwrap(),
    )
}

fn make_validator() -> DnssecValidator {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pm = rt.block_on(make_pool_manager("udp://127.0.0.1:5353".into()));
    DnssecValidator::with_trust_store(pm, TrustAnchorStore::empty())
}

fn make_a_record(name: &str, ip: Ipv4Addr) -> Record {
    let name = Name::from_str(name).unwrap();
    Record::from_rdata(name, 300, RData::A(A(ip)))
}

#[test]
fn test_verify_rrset_empty_records_returns_indeterminate() {
    // Empty answers (NXDOMAIN / NODATA) are routed to authenticated denial of
    // existence before reaching the RRset verifier; a stray empty RRset here is
    // undecided rather than blindly authentic.
    let validator = make_validator();
    assert_eq!(
        validator.verify_rrset_signatures("example.com.", &[]),
        ValidationResult::Indeterminate
    );
}

#[test]
fn test_verify_rrset_a_records_only_no_rrsig_returns_bogus() {
    let validator = make_validator();
    let a = make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(
        validator.verify_rrset_signatures("example.com.", &[a]),
        ValidationResult::Bogus
    );
}

#[test]
fn test_verify_rrset_multiple_a_records_no_rrsig_returns_bogus() {
    let validator = make_validator();
    let records: Vec<Record> = [
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(5, 6, 7, 8),
        Ipv4Addr::new(9, 10, 11, 12),
    ]
    .iter()
    .map(|ip| make_a_record("example.com.", *ip))
    .collect();
    assert_eq!(
        validator.verify_rrset_signatures("example.com.", &records),
        ValidationResult::Bogus
    );
}

#[test]
fn test_verify_rrset_rrsig_present_no_zone_keys_returns_bogus() {
    use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
    use hickory_proto::dnssec::{
        crypto::Ed25519SigningKey, Algorithm, DnssecSigner, PublicKey, PublicKeyBuf, SigningKey,
    };
    use hickory_proto::rr::{DNSClass, RecordSet, RecordType as HRT};
    use time::{Duration as TD, OffsetDateTime};

    let validator = make_validator();

    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let pub_key_buf = signing_key.to_public_key().unwrap();
    let pub_bytes = pub_key_buf.public_bytes().to_vec();

    let h_pub = PublicKeyBuf::new(pub_bytes, Algorithm::ED25519);
    let h_dnskey = HickoryDNSKEY::with_flags(256, h_pub);
    let signer_name = Name::from_str("example.com.").unwrap();
    let sig_duration = std::time::Duration::from_secs(7200);
    let signer = DnssecSigner::new(
        h_dnskey,
        Box::new(signing_key),
        signer_name.clone(),
        sig_duration,
    );

    let record_name = Name::from_str("example.com.").unwrap();
    let a_record = make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4));
    let mut rrset = RecordSet::new(record_name.clone(), HRT::A, 0);
    rrset.insert(a_record.clone(), 0);

    let inception = OffsetDateTime::now_utc() - TD::minutes(5);
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
    let rrsig_record =
        Record::from_rdata(record_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));

    let answers = vec![a_record, rrsig_record];
    assert_eq!(
        validator.verify_rrset_signatures("example.com.", &answers),
        ValidationResult::Bogus
    );
}

#[test]
fn test_verify_rrset_valid_ed25519_rrsig_returns_secure() {
    use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
    use hickory_proto::dnssec::{
        crypto::Ed25519SigningKey, Algorithm, DnssecSigner, PublicKey, PublicKeyBuf, SigningKey,
    };
    use hickory_proto::rr::{DNSClass, RecordSet, RecordType as HRT};
    use time::{Duration as TD, OffsetDateTime};

    let mut validator = make_validator();

    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let pub_key_buf = signing_key.to_public_key().unwrap();
    let pub_bytes = pub_key_buf.public_bytes().to_vec();

    let our_dnskey = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: pub_bytes.clone(),
    };

    let h_pub = PublicKeyBuf::new(pub_bytes, Algorithm::ED25519);
    let h_dnskey = HickoryDNSKEY::with_flags(256, h_pub);
    let signer_name = Name::from_str("example.com.").unwrap();
    let sig_duration = std::time::Duration::from_secs(7200);
    let signer = DnssecSigner::new(
        h_dnskey,
        Box::new(signing_key),
        signer_name.clone(),
        sig_duration,
    );

    let record_name = Name::from_str("example.com.").unwrap();
    let a_record = make_a_record("example.com.", Ipv4Addr::new(93, 184, 216, 34));
    let mut rrset = RecordSet::new(record_name.clone(), HRT::A, 0);
    rrset.insert(a_record.clone(), 0);

    let inception = OffsetDateTime::now_utc() - TD::minutes(5);
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
    let rrsig_record =
        Record::from_rdata(record_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));

    validator.insert_zone_keys_for_test("example.com.", vec![our_dnskey]);

    let answers = vec![a_record, rrsig_record];
    assert_eq!(
        validator.verify_rrset_signatures("example.com.", &answers),
        ValidationResult::Secure
    );
}

#[test]
fn test_verify_rrset_wrong_zone_key_returns_bogus() {
    use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
    use hickory_proto::dnssec::{
        crypto::Ed25519SigningKey, Algorithm, DnssecSigner, PublicKeyBuf, SigningKey,
    };
    use hickory_proto::rr::{DNSClass, RecordSet, RecordType as HRT};
    use time::{Duration as TD, OffsetDateTime};

    let mut validator = make_validator();

    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let pub_key_buf = signing_key.to_public_key().unwrap();
    let pub_bytes: Vec<u8> = {
        use hickory_proto::dnssec::PublicKey;
        pub_key_buf.public_bytes().to_vec()
    };

    let h_pub = PublicKeyBuf::new(pub_bytes, Algorithm::ED25519);
    let h_dnskey = HickoryDNSKEY::with_flags(256, h_pub);
    let signer_name = Name::from_str("example.com.").unwrap();
    let sig_duration = std::time::Duration::from_secs(7200);
    let signer = DnssecSigner::new(
        h_dnskey,
        Box::new(signing_key),
        signer_name.clone(),
        sig_duration,
    );

    let record_name = Name::from_str("example.com.").unwrap();
    let a_record = make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4));
    let mut rrset = RecordSet::new(record_name.clone(), HRT::A, 0);
    rrset.insert(a_record.clone(), 0);

    let inception = OffsetDateTime::now_utc() - TD::minutes(5);
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
    let rrsig_record =
        Record::from_rdata(record_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));

    let wrong_key = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: vec![0u8; 32],
    };
    validator.insert_zone_keys_for_test("example.com.", vec![wrong_key]);

    let answers = vec![a_record, rrsig_record];
    assert_eq!(
        validator.verify_rrset_signatures("example.com.", &answers),
        ValidationResult::Bogus
    );
}

#[test]
fn test_verify_rrset_signer_not_enclosing_owner_returns_bogus() {
    // Cross-zone forgery (RFC 4035 §5.3.1). An attacker controls a real,
    // validly-chained zone (evil.example) and signs an A record for an unrelated
    // victim name (victim.bank.com) with their own key, labelling the RRSIG with
    // their own signer name. The signature verifies against the attacker key, and
    // `extract_signer_zones` would have populated validated_keys["evil.example."]
    // by walking that genuinely-signed zone — so without the signer-encloses-owner
    // check this answer would be accepted as Secure (AD=1) despite being entirely
    // forged. The signer name does NOT enclose the owner, so it must be Bogus.
    use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY as HickoryDNSKEY, RRSIG};
    use hickory_proto::dnssec::{
        crypto::Ed25519SigningKey, Algorithm, DnssecSigner, PublicKey, PublicKeyBuf, SigningKey,
    };
    use hickory_proto::rr::{DNSClass, RecordSet, RecordType as HRT};
    use time::{Duration as TD, OffsetDateTime};

    let mut validator = make_validator();

    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let pub_key_buf = signing_key.to_public_key().unwrap();
    let pub_bytes = pub_key_buf.public_bytes().to_vec();

    let attacker_dnskey = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: pub_bytes.clone(),
    };

    let h_pub = PublicKeyBuf::new(pub_bytes, Algorithm::ED25519);
    let h_dnskey = HickoryDNSKEY::with_flags(256, h_pub);
    // The attacker signs with THEIR own zone as the signer name...
    let signer_name = Name::from_str("evil.example.").unwrap();
    let sig_duration = std::time::Duration::from_secs(7200);
    let signer = DnssecSigner::new(
        h_dnskey,
        Box::new(signing_key),
        signer_name.clone(),
        sig_duration,
    );

    // ...over a forged RRset owned by an unrelated victim name.
    let record_name = Name::from_str("victim.bank.com.").unwrap();
    let a_record = make_a_record("victim.bank.com.", Ipv4Addr::new(6, 6, 6, 6));
    let mut rrset = RecordSet::new(record_name.clone(), HRT::A, 0);
    rrset.insert(a_record.clone(), 0);

    let inception = OffsetDateTime::now_utc() - TD::minutes(5);
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
    let rrsig_record =
        Record::from_rdata(record_name, 300, RData::DNSSEC(DNSSECRData::RRSIG(rrsig)));

    // The attacker's zone keys are trusted (their real zone chains to the root).
    validator.insert_zone_keys_for_test("evil.example.", vec![attacker_dnskey]);

    let answers = vec![a_record, rrsig_record];
    assert_eq!(
        validator.verify_rrset_signatures("victim.bank.com.", &answers),
        ValidationResult::Bogus
    );
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
    );
    let mut first = Box::pin(pool.validate_query("first.example.", RecordType::A));
    observe_query(&upstream, &mut first, "first.example.").await;

    let mut positive = Message::new(0, MessageType::Response, OpCode::Query);
    positive.add_answer(make_a_record("second.example.", Ipv4Addr::LOCALHOST));
    let mut second =
        Box::pin(pool.validate_with_message("second.example.", RecordType::A, &positive));
    // The second validator is suspended while bootstrapping the root keys.
    observe_query(&upstream, &mut second, ".").await;

    let negative = Message::new(0, MessageType::Response, OpCode::Query);
    let mut oldest =
        Box::pin(pool.validate_with_message("oldest.example.", RecordType::A, &negative));
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
    assert_eq!(result.validation_status, ValidationResult::Insecure);
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
    );
    let mut active = Box::pin(pool.validate_query("active.example.", RecordType::A));
    observe_query(&upstream, &mut active, "active.example.").await;

    let negative = Message::new(0, MessageType::Response, OpCode::Query);
    let mut cancelled =
        Box::pin(pool.validate_with_message("cancelled.example.", RecordType::A, &negative));
    let mut admitted =
        Box::pin(pool.validate_with_message("admitted.example.", RecordType::A, &negative));
    let mut survivor =
        Box::pin(pool.validate_with_message("survivor.example.", RecordType::A, &negative));
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
    assert_eq!(result.validation_status, ValidationResult::Insecure);
}
