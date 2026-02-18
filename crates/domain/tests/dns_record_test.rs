use ferrous_dns_domain::{DnsRecord, RecordCategory, RecordType};
use std::net::IpAddr;
use std::str::FromStr;

mod helpers;
use helpers::DnsRecordBuilder;

#[test]
fn test_dns_record_creation() {
    let record = DnsRecord::new(
        "example.com".to_string(),
        RecordType::A,
        IpAddr::from_str("192.0.2.1").unwrap(),
        300,
    );

    assert_eq!(record.domain, "example.com");
    assert_eq!(record.record_type, RecordType::A);
    assert_eq!(record.ttl, 300);
}

#[test]
fn test_record_expiration() {
    let record = DnsRecord::new(
        "example.com".to_string(),
        RecordType::A,
        IpAddr::from_str("192.0.2.1").unwrap(),
        300,
    );

    assert!(!record.is_expired(100));
    assert!(!record.is_expired(299));
    assert!(record.is_expired(300));
    assert!(record.is_expired(500));
}

#[test]
fn test_remaining_ttl() {
    let record = DnsRecord::new(
        "example.com".to_string(),
        RecordType::A,
        IpAddr::from_str("192.0.2.1").unwrap(),
        300,
    );

    assert_eq!(record.remaining_ttl(0), 300);
    assert_eq!(record.remaining_ttl(100), 200);
    assert_eq!(record.remaining_ttl(300), 0);
    assert_eq!(record.remaining_ttl(500), 0);
}

#[test]
fn test_dns_record_builder() {
    let record = DnsRecordBuilder::new()
        .domain("test.com")
        .address("10.0.0.1")
        .ttl(600)
        .build();

    assert_eq!(record.domain, "test.com");
    assert_eq!(record.ttl, 600);
    assert_eq!(record.address, IpAddr::from_str("10.0.0.1").unwrap());
}

#[test]
fn test_dns_record_with_ipv6() {
    let record = DnsRecordBuilder::new()
        .record_type(RecordType::AAAA)
        .address("2001:4860:4860::8888")
        .build();

    assert_eq!(record.record_type, RecordType::AAAA);
    assert!(matches!(record.address, IpAddr::V6(_)));
}

#[test]
fn test_category_as_str() {
    assert_eq!(RecordCategory::Basic.as_str(), "basic");
    assert_eq!(RecordCategory::Dnssec.as_str(), "dnssec");
    assert_eq!(RecordCategory::Security.as_str(), "security");
}

#[test]
fn test_category_label() {
    assert_eq!(RecordCategory::Basic.label(), "Basic DNS Records");
    assert_eq!(RecordCategory::Security.label(), "Security & Cryptography");
    assert_eq!(RecordCategory::Dnssec.label(), "DNSSEC Records");
}

#[test]
fn test_category_all() {
    let all = RecordCategory::all();
    assert_eq!(all.len(), 7);
    assert!(all.contains(&RecordCategory::Basic));
    assert!(all.contains(&RecordCategory::Dnssec));
    assert!(all.contains(&RecordCategory::Security));
    assert!(all.contains(&RecordCategory::Advanced));
}

#[test]
fn test_category_display() {
    assert_eq!(format!("{}", RecordCategory::Basic), "basic");
    assert_eq!(format!("{}", RecordCategory::Dnssec), "dnssec");
}

#[test]
fn test_record_type_category() {
    assert_eq!(RecordType::A.category(), RecordCategory::Basic);
    assert_eq!(RecordType::AAAA.category(), RecordCategory::Basic);
    assert_eq!(RecordType::MX.category(), RecordCategory::Basic);

    assert_eq!(RecordType::DNSKEY.category(), RecordCategory::Dnssec);
    assert_eq!(RecordType::RRSIG.category(), RecordCategory::Dnssec);
    assert_eq!(RecordType::DS.category(), RecordCategory::Dnssec);

    assert_eq!(RecordType::CAA.category(), RecordCategory::Security);
    assert_eq!(RecordType::TLSA.category(), RecordCategory::Security);
}

#[test]
fn test_record_category_consistency() {
    let categories = RecordCategory::all();
    let mut strings: Vec<&str> = categories.iter().map(|c| c.as_str()).collect();
    strings.sort();
    strings.dedup();
    assert_eq!(strings.len(), categories.len());
}
