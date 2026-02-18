use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::forwarding::MessageBuilder;

mod fixtures;

#[test]
fn test_build_a_query() {
    let bytes = MessageBuilder::build_query("google.com", &RecordType::A);
    assert!(bytes.is_ok());

    let bytes = bytes.unwrap();
    
    assert!(
        bytes.len() >= 12,
        "DNS message too short: {} bytes",
        bytes.len()
    );

    assert_eq!(bytes[2] & 0x01, 0x01, "RD flag should be set");
}

#[test]
fn test_build_aaaa_query() {
    let bytes = MessageBuilder::build_query("example.com", &RecordType::AAAA);
    assert!(bytes.is_ok());

    let bytes = bytes.unwrap();
    assert!(bytes.len() >= 12);
}

#[test]
fn test_build_mx_query() {
    let bytes = MessageBuilder::build_query("example.com", &RecordType::MX);
    assert!(bytes.is_ok());

    let bytes = bytes.unwrap();
    assert!(bytes.len() >= 12);
}

#[test]
fn test_build_txt_query() {
    let bytes = MessageBuilder::build_query("example.com", &RecordType::TXT);
    assert!(bytes.is_ok());

    let bytes = bytes.unwrap();
    assert!(bytes.len() >= 12);
}

#[test]
fn test_build_query_with_id() {
    let result = MessageBuilder::build_query_with_id("test.com", &RecordType::A);
    assert!(result.is_ok());

    let (id, bytes) = result.unwrap();
    
    let wire_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    assert_eq!(wire_id, id, "Wire ID should match returned ID");
}

#[test]
fn test_query_id_uniqueness() {
    let mut ids = std::collections::HashSet::new();

    for _ in 0..100 {
        let (id, _) = MessageBuilder::build_query_with_id("test.com", &RecordType::A).unwrap();
        ids.insert(id);
    }

    assert!(ids.len() > 50, "Should generate varied IDs");
}

#[test]
fn test_query_with_id_different_domains() {
    let domains = vec!["google.com", "cloudflare.com", "example.com"];

    for domain in domains {
        let result = MessageBuilder::build_query_with_id(domain, &RecordType::A);
        assert!(result.is_ok(), "Failed for domain: {}", domain);

        let (id, bytes) = result.unwrap();
        let wire_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(wire_id, id);
    }
}

#[test]
fn test_invalid_domain_empty() {
    let result = MessageBuilder::build_query("", &RecordType::A);
    
    let _ = result;
}

#[test]
fn test_valid_fqdn() {
    let result = MessageBuilder::build_query("www.example.com", &RecordType::A);
    assert!(result.is_ok());
}

#[test]
fn test_domain_with_hyphen() {
    let result = MessageBuilder::build_query("my-domain.com", &RecordType::A);
    assert!(result.is_ok());
}

#[test]
fn test_long_domain() {
    let long_domain = "subdomain.very-long-domain-name-for-testing.example.com";
    let result = MessageBuilder::build_query(long_domain, &RecordType::A);
    assert!(result.is_ok());
}

#[test]
fn test_single_label_domain() {
    
    let result = MessageBuilder::build_query("localhost", &RecordType::A);
    let _ = result; 
}

#[test]
fn test_all_record_types_build() {
    let types = vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::MX,
        RecordType::TXT,
        RecordType::SOA,
        RecordType::NS,
        RecordType::CNAME,
    ];

    for rt in types {
        let result = MessageBuilder::build_query("example.com", &rt);
        assert!(result.is_ok(), "Failed to build query for {:?}", rt);
    }
}

#[test]
fn test_dnssec_record_types() {
    let dnssec_types = vec![
        RecordType::DNSKEY,
        RecordType::DS,
        RecordType::RRSIG,
        RecordType::NSEC,
    ];

    for rt in dnssec_types {
        let result = MessageBuilder::build_query("example.com", &rt);
        assert!(result.is_ok(), "Failed to build DNSSEC query for {:?}", rt);
    }
}

#[test]
fn test_advanced_record_types() {
    let advanced_types = vec![RecordType::SRV, RecordType::CAA, RecordType::PTR];

    for rt in advanced_types {
        let result = MessageBuilder::build_query("example.com", &rt);
        assert!(result.is_ok(), "Failed to build query for {:?}", rt);
    }
}

#[test]
fn test_dns_header_structure() {
    let bytes = MessageBuilder::build_query("test.com", &RecordType::A).unwrap();

    assert!(bytes.len() >= 12);

    assert_eq!(bytes[2] & 0x01, 0x01);

    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    assert_eq!(qdcount, 1, "Should have 1 question");

    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    assert_eq!(ancount, 0, "Query should have 0 answers");
}

#[test]
fn test_message_size_reasonable() {
    let bytes = MessageBuilder::build_query("example.com", &RecordType::A).unwrap();

    assert!(bytes.len() < 512, "Query should be under 512 bytes");
    assert!(bytes.len() >= 12, "Query should have at least header");
}

#[test]
fn test_different_domains_different_sizes() {
    let short = MessageBuilder::build_query("a.co", &RecordType::A).unwrap();
    let long =
        MessageBuilder::build_query("very.long.subdomain.example.com", &RecordType::A).unwrap();

    assert!(
        long.len() > short.len(),
        "Longer domain should produce longer message"
    );
}

#[test]
fn test_build_queries_from_fixtures() {
    let fixtures = fixtures::load_dns_fixtures();

    for (name, fixture) in fixtures.iter() {
        
        let record_type = match fixture.record_type.as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            "MX" => RecordType::MX,
            "TXT" => RecordType::TXT,
            _ => continue,
        };

        let result = MessageBuilder::build_query(&fixture.domain, &record_type);
        assert!(
            result.is_ok(),
            "Failed to build query for fixture: {}",
            name
        );
    }
}

#[test]
fn test_multiple_queries_sequential() {
    
    for i in 0..10 {
        let domain = format!("test{}.com", i);
        let result = MessageBuilder::build_query(&domain, &RecordType::A);
        assert!(result.is_ok());
    }
}

#[test]
fn test_query_with_numbers_in_domain() {
    let result = MessageBuilder::build_query("server123.example.com", &RecordType::A);
    assert!(result.is_ok());
}

#[test]
fn test_query_with_underscores() {
    
    let result = MessageBuilder::build_query("_service._tcp.example.com", &RecordType::SRV);
    assert!(result.is_ok());
}
