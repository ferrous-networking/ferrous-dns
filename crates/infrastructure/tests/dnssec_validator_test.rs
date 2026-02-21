use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::trust_anchor::TrustAnchorStore;
use ferrous_dns_infrastructure::dns::dnssec::{DnskeyRecord, DnssecValidator, ValidationResult};
use ferrous_dns_infrastructure::dns::PoolManager;
use ferrous_dns_infrastructure::dns::QueryEventEmitter;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

fn make_validator() -> DnssecValidator {
    let pool = UpstreamPool {
        name: "test".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://127.0.0.1:5353".into()],
        weight: None,
    };
    let pm =
        Arc::new(PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled()).unwrap());
    DnssecValidator::with_trust_store(pm, TrustAnchorStore::empty())
}

fn make_a_record(name: &str, ip: Ipv4Addr) -> Record {
    let name = Name::from_str(name).unwrap();
    Record::from_rdata(name, 300, RData::A(A(ip)))
}

#[test]
fn test_verify_rrset_empty_records_returns_secure() {
    let validator = make_validator();
    assert_eq!(
        validator.verify_rrset_signatures("example.com.", &[]),
        ValidationResult::Secure
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
        crypto::Ed25519SigningKey, Algorithm, PublicKey, PublicKeyBuf, SigSigner, SigningKey,
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
    let signer = SigSigner::dnssec(
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
        crypto::Ed25519SigningKey, Algorithm, PublicKey, PublicKeyBuf, SigSigner, SigningKey,
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
    let signer = SigSigner::dnssec(
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
        crypto::Ed25519SigningKey, Algorithm, PublicKeyBuf, SigSigner, SigningKey,
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
    let signer = SigSigner::dnssec(
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
