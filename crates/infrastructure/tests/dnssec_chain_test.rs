use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::trust_anchor::TrustAnchorStore;
use ferrous_dns_infrastructure::dns::dnssec::{ChainVerifier, DnskeyRecord, DnssecCache};
use ferrous_dns_infrastructure::dns::PoolManager;
use ferrous_dns_infrastructure::dns::QueryEventEmitter;
use std::sync::Arc;

fn make_chain_verifier() -> ChainVerifier {
    let pool = UpstreamPool {
        name: "test".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://127.0.0.1:5353".into()],
        weight: None,
    };
    let pm =
        Arc::new(PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled()).unwrap());
    ChainVerifier::new(pm, TrustAnchorStore::empty(), Arc::new(DnssecCache::new()))
}

#[test]
fn test_get_zone_keys_returns_none_on_empty_chain() {
    let verifier = make_chain_verifier();
    assert!(verifier.get_zone_keys("example.com.").is_none());
    assert!(verifier.get_zone_keys(".").is_none());
    assert!(verifier.get_zone_keys("com.").is_none());
}

#[test]
fn test_get_zone_keys_returns_inserted_keys() {
    let mut verifier = make_chain_verifier();
    let key = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: vec![0u8; 32],
    };
    verifier.insert_zone_keys_for_test("example.com.", vec![key.clone()]);

    let stored = verifier.get_zone_keys("example.com.").unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0], key);
}

#[test]
fn test_get_zone_keys_returns_ksk_and_zsk_after_rrsig_verification() {
    let mut verifier = make_chain_verifier();
    let ksk = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![1, 2, 3, 4],
    };
    let zsk = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 8,
        public_key: vec![5, 6, 7, 8],
    };
    verifier.insert_zone_keys_for_test("example.com.", vec![ksk.clone(), zsk.clone()]);

    let stored = verifier.get_zone_keys("example.com.").unwrap();
    assert_eq!(stored.len(), 2);
    assert!(
        stored.iter().any(|k| k.flags == 257),
        "KSK should be stored"
    );
    assert!(
        stored.iter().any(|k| k.flags == 256),
        "ZSK should be stored"
    );
}

#[test]
fn test_get_zone_keys_multiple_zones_are_independent() {
    let mut verifier = make_chain_verifier();
    let key_a = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![1],
    };
    let key_b = DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: vec![0u8; 32],
    };
    verifier.insert_zone_keys_for_test("com.", vec![key_a]);
    verifier.insert_zone_keys_for_test("example.com.", vec![key_b]);

    assert_eq!(verifier.get_zone_keys("com.").unwrap().len(), 1);
    assert_eq!(verifier.get_zone_keys("example.com.").unwrap().len(), 1);
    assert!(verifier.get_zone_keys("net.").is_none());
}

#[test]
fn test_split_domain_root_is_empty() {
    assert!(ChainVerifier::split_domain(".").is_empty());
    assert!(ChainVerifier::split_domain("").is_empty());
}

#[test]
fn test_split_domain_tld_gives_single_label() {
    assert_eq!(ChainVerifier::split_domain("com"), vec!["com"]);
    assert_eq!(ChainVerifier::split_domain("com."), vec!["com"]);
}

#[test]
fn test_split_domain_two_labels_reversed() {
    let labels = ChainVerifier::split_domain("example.com.");
    assert_eq!(labels, vec!["com", "example"]);
}

#[test]
fn test_split_domain_three_labels_reversed() {
    let labels = ChainVerifier::split_domain("www.example.com.");
    assert_eq!(labels, vec!["com", "example", "www"]);
}
