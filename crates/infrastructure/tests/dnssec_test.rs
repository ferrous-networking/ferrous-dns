use ferrous_dns_infrastructure::dns::dnssec::{
    crypto, DnskeyRecord, DnssecCache, DsDenial, DsLookup, DsRecord,
};
use hickory_proto::dnssec::crypto::Ed25519SigningKey;
use hickory_proto::dnssec::rdata::{DNSKEY, RRSIG};
use hickory_proto::dnssec::{Algorithm, DnssecSigner, PublicKey, PublicKeyBuf, SigningKey};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType as HRT};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

#[test]
fn cache_serves_unexpired_sets_and_drops_expired_ones() {
    let cache = DnssecCache::new();
    let key = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };

    cache.cache_dnskey("fresh.example.", vec![key.clone()].into(), 300);
    cache.cache_dnskey("expired.example.", vec![key].into(), 0);
    cache.cache_ds(
        "expired.example.",
        DsLookup::Absent(DsDenial::InsecureDelegation),
        0,
    );

    assert_eq!(cache.get_dnskey("fresh.example.").unwrap().len(), 1);
    assert!(cache.get_dnskey("expired.example.").is_none());
    assert!(cache.get_ds("expired.example.").is_none());

    let stats = cache.stats();
    assert_eq!(stats.total_dnskey_hits, 1);
    assert_eq!(stats.total_dnskey_misses, 1);
    assert_eq!(stats.total_ds_misses, 1);
    assert_eq!(
        stats.dnskey_entries, 1,
        "expired entry is removed on lookup"
    );
    assert_eq!(stats.ds_entries, 0);
}

#[test]
fn key_tag_of_an_oversized_key_does_not_overflow() {
    // Trust anchor files are not RDLENGTH-bounded, so the sum must not overflow.
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![0xFF; 140_000],
    };

    let _ = dnskey.calculate_key_tag();
}

#[test]
fn test_verify_ds_key_tag_mismatch() {
    let ds = DsRecord {
        key_tag: 9999,
        algorithm: 8,
        digest_type: 2,
        digest: vec![0u8; 32],
    };

    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };

    // Different key_tag → must return false without computing digest
    let result = crypto::verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result);
}

#[test]
fn test_verify_ds_algorithm_mismatch() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };
    let key_tag = dnskey.calculate_key_tag();

    let ds = DsRecord {
        key_tag,
        algorithm: 13, // Different algorithm than dnskey.algorithm (8)
        digest_type: 2,
        digest: vec![0u8; 32],
    };

    let result = crypto::verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result);
}

#[test]
fn test_verify_ds_wrong_digest() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1, 0xAB, 0xCD],
    };
    let key_tag = dnskey.calculate_key_tag();

    let ds = DsRecord {
        key_tag,
        algorithm: 8,
        digest_type: 2,
        digest: vec![0u8; 32], // Wrong digest (all zeros)
    };

    let result = crypto::verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result, "Wrong digest should not match");
}

#[test]
fn test_verify_ds_unsupported_digest_type() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };
    let key_tag = dnskey.calculate_key_tag();

    let ds = DsRecord {
        key_tag,
        algorithm: 8,
        digest_type: 99, // Unsupported
        digest: vec![0u8; 20],
    };

    let result = crypto::verify_ds(&ds, &dnskey, "example.com.");
    assert!(
        result.is_err(),
        "Unsupported digest type should return error"
    );
}

#[test]
fn test_is_supported_algorithm_matches_dispatch_arms() {
    // The RFC 6840 §5.2 "insecure, not bogus" decision in `validate_delegation`
    // keys off this predicate, so it MUST stay in lockstep with the algorithms
    // `verify_rrsig_with_name` can actually dispatch. Supported today: RSA/SHA-1
    // (5,7), RSA/SHA-256 (8), RSA/SHA-512 (10), ECDSA P-256/P-384 (13,14),
    // Ed25519 (15). Notably Ed448 (16) is NOT implemented.
    for alg in [5, 7, 8, 10, 13, 14, 15] {
        assert!(
            crypto::is_supported_algorithm(alg),
            "algorithm {alg} should be reported as supported"
        );
    }
    for alg in [0, 1, 3, 6, 12, 16, 17, 252, 253, 254] {
        assert!(
            !crypto::is_supported_algorithm(alg),
            "algorithm {alg} should be reported as unsupported"
        );
    }
}

/// An A RRset at `example.com.`, an RRSIG over it whose validity window opens
/// `inception_ago` before now and lasts `lifetime`, and the signing key.
fn signed_rrset(
    inception_ago: time::Duration,
    lifetime: std::time::Duration,
) -> (Record, RRSIG, DnskeyRecord) {
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().unwrap();
    let signing_key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let public = signing_key.to_public_key().unwrap().public_bytes().to_vec();
    let key = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: public.clone(),
    };
    let owner = Name::from_str("example.com.").unwrap();
    let signer = DnssecSigner::new(
        DNSKEY::with_flags(256, PublicKeyBuf::new(public, Algorithm::ED25519)),
        Box::new(signing_key),
        owner.clone(),
        lifetime,
    );
    let record = Record::from_rdata(owner.clone(), 300, RData::A(A::new(192, 0, 2, 1)));
    let mut rrset = RecordSet::new(owner, HRT::A, 0);
    rrset.insert(record.clone(), 0);
    let inception = time::OffsetDateTime::now_utc() - inception_ago;
    let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &signer).unwrap();
    (record, rrsig, key)
}

fn verifies(record: &Record, rrsig: &RRSIG, keys: &[DnskeyRecord]) -> bool {
    crypto::rrsig_verifies(
        rrsig,
        keys,
        &record.name,
        std::iter::once(record),
        now_secs(),
    )
    .unwrap()
}

#[test]
fn rrsig_verifies_only_inside_its_validity_window() {
    let day = std::time::Duration::from_secs(86_400);
    let (record, current, key) = signed_rrset(time::Duration::minutes(5), day);
    assert!(verifies(&record, &current, &[key]));

    let (record, expired, key) = signed_rrset(time::Duration::days(3), day);
    assert!(
        !verifies(&record, &expired, &[key]),
        "expired signature accepted"
    );
}

#[test]
fn rrsig_needs_the_signing_key_among_the_candidates() {
    let day = std::time::Duration::from_secs(86_400);
    let (record, rrsig, key) = signed_rrset(time::Duration::minutes(5), day);
    let (_, _, other) = signed_rrset(time::Duration::minutes(5), day);
    assert!(!verifies(&record, &rrsig, std::slice::from_ref(&other)));
    assert!(verifies(&record, &rrsig, &[other, key]));
}
