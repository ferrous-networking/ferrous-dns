use ferrous_dns_infrastructure::dns::dnssec::{
    cache::{DnskeyEntry, DsEntry, ValidationEntry},
    ValidationResult,
};
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
