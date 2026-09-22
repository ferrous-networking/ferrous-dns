use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::dns::fast_path;
use ferrous_dns_infrastructure::dns::forwarding::ResponseParser;
#[cfg(feature = "dns-over-h3")]
use ferrous_dns_infrastructure::dns::transport::h3::H3Transport;
#[cfg(feature = "dns-over-quic")]
use ferrous_dns_infrastructure::dns::transport::quic::QuicTransport;
use ferrous_dns_infrastructure::dns::transport::DnsTransport;
use ferrous_dns_infrastructure::dns::transport::{
    https::HttpsTransport, tcp::TcpTransport, tls::TlsTransport, udp::UdpTransport,
};
use ferrous_dns_infrastructure::dns::wire_response;
use std::net::IpAddr;

mod helpers;
use helpers::DnsServerBuilder;

#[test]
fn test_all_protocols_have_unique_names() {
    let udp = UdpTransport::new(DnsServerBuilder::google_dns());
    let tcp = TcpTransport::new(DnsServerBuilder::google_dns());
    let (tls_addr, tls_host) = DnsServerBuilder::cloudflare_tls();
    let tls = TlsTransport::new(tls_addr, tls_host.into());
    let https = HttpsTransport::new(
        DnsServerBuilder::cloudflare_https(),
        "1.1.1.1".to_string(),
        vec![],
    );

    let mut names = vec![
        udp.protocol_name(),
        tcp.protocol_name(),
        tls.protocol_name(),
        https.protocol_name(),
    ];

    #[cfg(feature = "dns-over-h3")]
    {
        let h3 = H3Transport::new(DnsServerBuilder::cloudflare_h3(), vec![]);
        names.push(h3.protocol_name());
    }

    #[cfg(feature = "dns-over-quic")]
    {
        let (quic_addr, quic_host) = DnsServerBuilder::cloudflare_doq();
        let quic = QuicTransport::new(quic_addr, quic_host.into());
        names.push(quic.protocol_name());
    }

    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "Protocol names should be unique");
}

// ── RFC 6891: OPT record in fast-path responses ───────────────────────────────

fn build_edns_query() -> Vec<u8> {
    vec![
        0x00, 0x01, // ID
        0x00, 0x00, // FLAGS (plain query, no flags)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x01, // ARCOUNT = 1 (one OPT record)
        // QNAME: google.com.
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        // QTYPE A, QCLASS IN
        0x00, 0x01, 0x00, 0x01, // OPT RR
        0x00, // NAME = root
        0x00, 0x29, // TYPE = OPT (41)
        0x10, 0x00, // CLASS = 4096 (client UDP payload size)
        0x00, 0x00, 0x00, 0x00, // TTL: extended RCODE=0, version=0, DO=0, Z=0
        0x00, 0x00, // RDLENGTH = 0
    ]
}

/// Models a real `dig +dnssec` query: EDNS OPT with the DO bit set and a
/// COOKIE option in the RDATA (as dig 9.18+ sends).
fn build_edns_do_query() -> Vec<u8> {
    vec![
        0x00, 0x01, // ID
        0x01, 0x20, // FLAGS: RD + AD
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x01, // ARCOUNT = 1 (one OPT record)
        // QNAME: google.com.
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        // QTYPE A, QCLASS IN
        0x00, 0x01, 0x00, 0x01, // OPT RR
        0x00, // NAME = root
        0x00, 0x29, // TYPE = OPT (41)
        0x04, 0xd0, // CLASS = 1232 (client UDP payload size)
        0x00, 0x00, 0x80, 0x00, // TTL: ext RCODE=0, version=0, DO=1, Z=0
        0x00, 0x0c, // RDLENGTH = 12
        0x00, 0x0a, // OPTION-CODE = COOKIE (10)
        0x00, 0x08, // OPTION-LENGTH = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 8-byte client cookie
    ]
}

#[test]
fn test_fast_path_detects_do_bit() {
    let with_do = fast_path::parse_query(&build_edns_do_query())
        .expect("EDNS+DO query should be fast-path parseable");
    assert!(
        with_do.wants_dnssec,
        "wants_dnssec must be true when the client set the EDNS DO bit"
    );

    let without_do = fast_path::parse_query(&build_edns_query())
        .expect("EDNS query should be fast-path parseable");
    assert!(
        !without_do.wants_dnssec,
        "wants_dnssec must be false when the DO bit is clear"
    );
}

#[test]
fn test_fast_path_response_includes_opt_when_client_sent_edns() {
    let query_bytes = build_edns_query();

    let fast_query = fast_path::parse_query(&query_bytes)
        .expect("Minimal EDNS query should be fast-path parseable");

    assert!(
        fast_query.has_edns,
        "FastPathQuery.has_edns must be true when query contains OPT record"
    );

    let addresses: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];

    let (wire, wire_len) =
        wire_response::build_cache_hit_response(&fast_query, &query_bytes, &addresses, 300)
            .expect("build_cache_hit_response should succeed");

    let arcount = u16::from_be_bytes([wire[10], wire[11]]);
    assert_eq!(
        arcount, 1,
        "ARCOUNT must be 1 when OPT record is included (RFC 6891 §6.1.1)"
    );

    let opt_start = wire_len - 11;
    assert_eq!(wire[opt_start], 0x00, "OPT NAME must be root (0x00)");
    assert_eq!(
        u16::from_be_bytes([wire[opt_start + 1], wire[opt_start + 2]]),
        41,
        "OPT TYPE must be 41"
    );
}

// Transport errors determine which failures can trigger upstream failover.

#[test]
fn test_transport_error_classification_typed_variants() {
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportTimeout {
            server: "8.8.8.8:53".into()
        }
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportConnectionRefused {
            server: "1.1.1.1:53".into()
        }
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportConnectionReset {
            server: "9.9.9.9:53".into()
        }
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportNoHealthyServers
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportAllServersUnreachable
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::SpoofedResponse {
            server: "8.8.8.8:53".into(),
            reason: "cookie mismatch".into()
        }
    ));

    assert!(!ResponseParser::is_transport_error(&DomainError::NxDomain));
    assert!(!ResponseParser::is_transport_error(&DomainError::Blocked));
}

#[test]
fn test_fast_path_response_no_opt_when_client_has_no_edns() {
    let mut query_bytes: Vec<u8> = vec![
        0x00, 0x01, // ID
        0x00, 0x00, // FLAGS (standard query)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0 (no OPT)
        // QNAME: google.com.
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        // QTYPE A, QCLASS IN
        0x00, 0x01, 0x00, 0x01,
    ];
    query_bytes.resize(query_bytes.len(), 0);

    let fast_query =
        fast_path::parse_query(&query_bytes).expect("Minimal query should be fast-path parseable");

    assert!(
        !fast_query.has_edns,
        "FastPathQuery.has_edns must be false when no OPT record is present"
    );

    let addresses: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
    let (wire, _wire_len) =
        wire_response::build_cache_hit_response(&fast_query, &query_bytes, &addresses, 300)
            .expect("build_cache_hit_response should succeed");

    let arcount = u16::from_be_bytes([wire[10], wire[11]]);
    assert_eq!(arcount, 0, "ARCOUNT must be 0 when client did not send OPT");
}
