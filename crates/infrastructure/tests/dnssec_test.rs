use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::{
    cache::{DnskeyEntry, DsEntry, ValidationEntry},
    ChainVerifier, DnskeyRecord, DnssecCache, DsRecord, SignatureVerifier, TrustAnchorStore,
    ValidationResult,
};
use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_validation_entry_creation() {
    let entry = ValidationEntry::new(ValidationResult::Secure, 300);
    assert!(!entry.is_expired());
}

#[test]
fn test_validation_entry_secure() {
    let entry = ValidationEntry::new(ValidationResult::Secure, 300);

    assert!(!entry.is_expired());
}

#[test]
fn test_validation_entry_insecure() {
    let entry = ValidationEntry::new(ValidationResult::Insecure, 300);
    assert!(!entry.is_expired());
}

#[test]
fn test_validation_entry_bogus() {
    let entry = ValidationEntry::new(ValidationResult::Bogus, 300);
    assert!(!entry.is_expired());
}

#[test]
fn test_validation_entry_indeterminate() {
    let entry = ValidationEntry::new(ValidationResult::Indeterminate, 300);
    assert!(!entry.is_expired());
}

#[test]
fn test_validation_entry_expiration() {
    let entry = ValidationEntry::new(ValidationResult::Secure, 1);
    assert!(!entry.is_expired());

    thread::sleep(Duration::from_secs(2));
    assert!(entry.is_expired());
}

#[test]
fn test_validation_entry_short_ttl() {
    let entry = ValidationEntry::new(ValidationResult::Secure, 0);

    thread::sleep(Duration::from_millis(100));

    let _ = entry.is_expired();
}

#[test]
fn test_validation_entry_long_ttl() {
    let entry = ValidationEntry::new(ValidationResult::Secure, 86400);
    assert!(!entry.is_expired());
}

#[test]
fn test_dnskey_entry_empty() {
    let entry = DnskeyEntry::new(vec![], 300);
    assert!(!entry.is_expired());
    assert_eq!(entry.keys().len(), 0);
}

#[test]
fn test_dnskey_entry_with_keys() {
    let keys = vec![];
    let entry = DnskeyEntry::new(keys, 300);
    assert!(!entry.is_expired());
    assert_eq!(entry.keys().len(), 0);
}

#[test]
fn test_dnskey_entry_expiration() {
    let entry = DnskeyEntry::new(vec![], 1);
    assert!(!entry.is_expired());

    thread::sleep(Duration::from_secs(2));
    assert!(entry.is_expired());
}

#[test]
fn test_dnskey_entry_ttl_variations() {
    let ttls = vec![0, 1, 60, 300, 3600, 86400];

    for ttl in ttls {
        let entry = DnskeyEntry::new(vec![], ttl);

        let _ = entry.is_expired();
    }
}

#[test]
fn test_ds_entry_empty() {
    let entry = DsEntry::new(vec![], 300);
    assert!(!entry.is_expired());
    assert_eq!(entry.records().len(), 0);
}

#[test]
fn test_ds_entry_with_records() {
    let records = vec![];
    let entry = DsEntry::new(records, 300);
    assert!(!entry.is_expired());
    assert_eq!(entry.records().len(), 0);
}

#[test]
fn test_ds_entry_expiration() {
    let entry = DsEntry::new(vec![], 1);
    assert!(!entry.is_expired());

    thread::sleep(Duration::from_secs(2));
    assert!(entry.is_expired());
}

#[test]
fn test_ds_entry_various_ttls() {
    let short = DsEntry::new(vec![], 1);
    let medium = DsEntry::new(vec![], 300);
    let long = DsEntry::new(vec![], 86400);

    assert!(!short.is_expired());
    assert!(!medium.is_expired());
    assert!(!long.is_expired());
}

#[test]
fn test_all_entry_types_implement_expiration() {
    let validation = ValidationEntry::new(ValidationResult::Secure, 300);
    let dnskey = DnskeyEntry::new(vec![], 300);
    let ds = DsEntry::new(vec![], 300);

    assert!(!validation.is_expired());
    assert!(!dnskey.is_expired());
    assert!(!ds.is_expired());
}

#[test]
fn test_entry_types_expire_independently() {
    let short = ValidationEntry::new(ValidationResult::Secure, 1);
    let medium = DnskeyEntry::new(vec![], 5);
    let long = DsEntry::new(vec![], 10);

    assert!(!short.is_expired());
    assert!(!medium.is_expired());
    assert!(!long.is_expired());

    thread::sleep(Duration::from_secs(2));
    assert!(short.is_expired());
    assert!(!medium.is_expired());
    assert!(!long.is_expired());
}

#[test]
fn test_validation_results_all_states() {
    let results = vec![
        ValidationResult::Secure,
        ValidationResult::Insecure,
        ValidationResult::Bogus,
        ValidationResult::Indeterminate,
    ];

    for result in results {
        let entry = ValidationEntry::new(result, 300);
        assert!(!entry.is_expired());
    }
}

#[test]
fn test_validation_result_edge_cases() {
    let zero_ttl = ValidationEntry::new(ValidationResult::Secure, 0);
    let _ = zero_ttl.is_expired();

    let max_ttl = ValidationEntry::new(ValidationResult::Secure, u32::MAX);
    assert!(!max_ttl.is_expired());
}

#[test]
fn test_cache_entry_lifecycle() {
    let entry = DnskeyEntry::new(vec![], 2);
    assert!(!entry.is_expired());

    thread::sleep(Duration::from_secs(1));
    assert!(!entry.is_expired());

    thread::sleep(Duration::from_secs(2));
    assert!(entry.is_expired());
}

#[test]
fn test_multiple_entries_different_expiry() {
    let entries = vec![
        DsEntry::new(vec![], 1),
        DsEntry::new(vec![], 2),
        DsEntry::new(vec![], 3),
    ];

    for entry in &entries {
        assert!(!entry.is_expired());
    }

    thread::sleep(Duration::from_millis(1500));
    assert!(entries[0].is_expired());
    assert!(!entries[1].is_expired());
    assert!(!entries[2].is_expired());
}

// ============================================================================
// DnskeyRecord tests
// ============================================================================

#[test]
fn test_dnskey_record_construction() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![1, 2, 3, 4],
    };

    assert!(dnskey.is_ksk());
    assert!(!dnskey.is_zsk());
    assert_eq!(dnskey.algorithm_name(), "RSA/SHA-256");
}

#[test]
fn test_dnskey_zsk_flags() {
    let zsk = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 13,
        public_key: vec![0u8; 64],
    };

    assert!(!zsk.is_ksk());
    assert!(zsk.is_zsk());
    assert_eq!(zsk.algorithm_name(), "ECDSA P-256/SHA-256");
}

#[test]
fn test_dnskey_calculate_key_tag_deterministic() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1, 0xAB, 0xCD, 0xEF],
    };

    // Key tag must be deterministic (same result every call)
    let tag1 = dnskey.calculate_key_tag();
    let tag2 = dnskey.calculate_key_tag();
    assert_eq!(tag1, tag2);
}

// ============================================================================
// DsRecord tests
// ============================================================================

#[test]
fn test_ds_record_construction() {
    let ds = DsRecord {
        key_tag: 12345,
        algorithm: 8,
        digest_type: 2,
        digest: vec![0u8; 32],
    };

    assert_eq!(ds.key_tag, 12345);
    assert_eq!(ds.digest_type_name(), "SHA-256");
    assert_eq!(ds.algorithm_name(), "RSA/SHA-256");
}

// ============================================================================
// verify_ds tests
// ============================================================================

#[test]
fn test_verify_ds_key_tag_mismatch() {
    let verifier = SignatureVerifier;

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
    let result = verifier.verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result);
}

#[test]
fn test_verify_ds_algorithm_mismatch() {
    let verifier = SignatureVerifier;

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

    let result = verifier.verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result);
}

#[test]
fn test_verify_ds_wrong_digest() {
    let verifier = SignatureVerifier;

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

    let result = verifier.verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result, "Wrong digest should not match");
}

#[test]
fn test_verify_ds_unsupported_digest_type() {
    let verifier = SignatureVerifier;

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

    let result = verifier.verify_ds(&ds, &dnskey, "example.com.");
    assert!(
        result.is_err(),
        "Unsupported digest type should return error"
    );
}

// ============================================================================
// verify_rrsig basic checks (time/key_tag/algorithm)
// ============================================================================

#[test]
fn test_verify_rrsig_expired_signature() {
    use ferrous_dns_domain::RecordType;
    use ferrous_dns_infrastructure::dns::dnssec::RrsigRecord;
    use std::time::{SystemTime, UNIX_EPOCH};

    let verifier = SignatureVerifier;

    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1, 0xAB],
    };
    let key_tag = dnskey.calculate_key_tag();

    let rrsig = RrsigRecord {
        type_covered: RecordType::A,
        algorithm: 8,
        labels: 2,
        original_ttl: 300,
        signature_expiration: 1000,
        signature_inception: 1,
        key_tag,
        signer_name: "example.com.".to_string(),
        signature: vec![0u8; 64],
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let result = verifier
        .verify_rrsig(&rrsig, &dnskey, "example.com.", &[], now_secs)
        .unwrap();
    assert!(!result, "Expired RRSIG should return false");
}

#[test]
fn test_verify_rrsig_key_tag_mismatch() {
    use ferrous_dns_domain::RecordType;
    use ferrous_dns_infrastructure::dns::dnssec::RrsigRecord;
    use std::time::{SystemTime, UNIX_EPOCH};

    let verifier = SignatureVerifier;

    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1, 0xAB],
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let rrsig = RrsigRecord {
        type_covered: RecordType::A,
        algorithm: 8,
        labels: 2,
        original_ttl: 300,
        signature_expiration: now + 3600,
        signature_inception: now - 60,
        key_tag: 9999, // Deliberately wrong key_tag
        signer_name: "example.com.".to_string(),
        signature: vec![0u8; 64],
    };

    let result = verifier
        .verify_rrsig(&rrsig, &dnskey, "example.com.", &[], now)
        .unwrap();
    assert!(!result, "Key tag mismatch should return false");
}

// ============================================================================
// ChainVerifier::get_zone_keys — public API tests
// ============================================================================

fn make_chain_verifier_for_test() -> ChainVerifier {
    let pool = UpstreamPool {
        name: "test".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://127.0.0.1:5353".into()],
        weight: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pm = Arc::new(
        rt.block_on(PoolManager::new(
            vec![pool],
            None,
            QueryEventEmitter::new_disabled(),
        ))
        .unwrap(),
    );
    ChainVerifier::new(pm, TrustAnchorStore::empty(), Arc::new(DnssecCache::new()))
}

#[test]
fn test_chain_verifier_get_zone_keys_returns_none_initially() {
    let verifier = make_chain_verifier_for_test();
    assert!(verifier.get_zone_keys("example.com.").is_none());
    assert!(verifier.get_zone_keys(".").is_none());
    assert!(verifier.get_zone_keys("com.").is_none());
}

// ============================================================================
// ValidationResult::as_str — all variants
// ============================================================================

#[test]
fn test_validation_result_as_str_secure() {
    assert_eq!(ValidationResult::Secure.as_str(), "Secure");
}

#[test]
fn test_validation_result_as_str_insecure() {
    assert_eq!(ValidationResult::Insecure.as_str(), "Insecure");
}

#[test]
fn test_validation_result_as_str_bogus() {
    assert_eq!(ValidationResult::Bogus.as_str(), "Bogus");
}

#[test]
fn test_validation_result_as_str_indeterminate() {
    assert_eq!(ValidationResult::Indeterminate.as_str(), "Indeterminate");
}
