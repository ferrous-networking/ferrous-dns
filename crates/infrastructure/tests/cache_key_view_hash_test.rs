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
