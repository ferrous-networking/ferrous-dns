//! The cache key's hash decides the bloom filter's bits and the DashMap shard
//! of every entry. Keys in the view every client shares must hash exactly as
//! they did before per-group views existed, so the bloom and the shards behave
//! as before for everyone who routes nothing per group.

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::{BorrowedKey, CacheKey};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const NAMES: [&str; 8] = [
    "example.com",
    "a",
    "localhost",
    "1.10.in-addr.arpa",
    "_dmarc.example.org",
    "xn--e1afmkfd.xn--p1ai",
    "bücher.example",
    "a-very-long-label-for-a-name-that-is-close-to-the-length-limit.example.com",
];

const TYPES: [RecordType; 5] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::MX,
    RecordType::PTR,
    RecordType::HTTPS,
];

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// The key hash before per-group views: the name, then the type.
fn reference_hash(domain: &str, record_type: RecordType) -> u64 {
    let mut hasher = DefaultHasher::new();
    domain.hash(&mut hasher);
    std::mem::discriminant(&record_type).hash(&mut hasher);
    hasher.finish()
}

#[test]
fn test_shared_view_key_hashes_as_before() {
    for name in NAMES {
        for record_type in TYPES {
            let expected = reference_hash(name, record_type);
            assert_eq!(
                hash_of(&CacheKey::new(name, record_type)),
                expected,
                "{name} {record_type}"
            );
            assert_eq!(
                hash_of(&BorrowedKey::new(name, record_type)),
                expected,
                "{name} {record_type}"
            );
        }
    }
}

#[test]
fn test_uppercase_name_hashes_as_its_lowercase_form() {
    assert_eq!(
        hash_of(&CacheKey::new("WWW.Example.COM", RecordType::A)),
        reference_hash("www.example.com", RecordType::A)
    );
}

#[test]
fn test_group_view_key_hashes_alike_borrowed_and_owned() {
    for name in NAMES {
        for record_type in TYPES {
            for view in [1, 3, u32::MAX] {
                let owned = CacheKey::new(name, record_type).in_view(view);
                let borrowed = BorrowedKey::new(name, record_type).in_view(view);
                assert_eq!(
                    hash_of(&owned),
                    hash_of(&borrowed),
                    "{name} {record_type} view {view}: the bloom would miss this entry"
                );
            }
        }
    }
}

#[test]
fn test_views_of_one_name_are_distinct_keys() {
    let shared = CacheKey::new("corp.example", RecordType::A);
    let group_a = CacheKey::new("corp.example", RecordType::A).in_view(3);
    let group_b = CacheKey::new("corp.example", RecordType::A).in_view(4);
    assert_ne!(shared, group_a);
    assert_ne!(group_a, group_b);
    assert_ne!(hash_of(&shared), hash_of(&group_a));
    assert_ne!(hash_of(&group_a), hash_of(&group_b));
    assert_eq!(
        group_a,
        CacheKey::new("CORP.example", RecordType::A).in_view(3)
    );
}
