use ferrous_dns_domain::{DomainError, UpstreamAddr};
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
use std::sync::Arc;

mod helpers;
use helpers::{DnsServerBuilder, UdpPoolBuilder};

#[test]
fn test_udp_transport_creation() {
    let transport = UdpTransport::new(DnsServerBuilder::google_dns());

    assert_eq!(transport.protocol_name(), "UDP");
}

#[test]
fn test_udp_transport_with_pool() {
    let addr = DnsServerBuilder::google_dns();
    let pool = UdpPoolBuilder::medium();
    let _transport = UdpTransport::with_pool(addr, pool);
}

#[test]
fn test_udp_transport_ipv6() {
    let addr = DnsServerBuilder::google_dns_ipv6();
    let _transport = UdpTransport::new(addr);
}

#[test]
fn test_udp_transport_different_providers() {
    let google = UdpTransport::new(DnsServerBuilder::google_dns());
    assert_eq!(google.protocol_name(), "UDP");

    let cloudflare = UdpTransport::new(DnsServerBuilder::cloudflare_dns());
    assert_eq!(cloudflare.protocol_name(), "UDP");
}

#[test]
fn test_udp_pool_creation() {
    let small = UdpPoolBuilder::small();
    assert!(Arc::strong_count(&small) == 1);

    let medium = UdpPoolBuilder::medium();
    assert!(Arc::strong_count(&medium) == 1);

    let large = UdpPoolBuilder::large();
    assert!(Arc::strong_count(&large) == 1);
}

#[test]
fn test_udp_pool_custom() {
    let custom = UdpPoolBuilder::custom(10, 150);
    assert!(Arc::strong_count(&custom) == 1);
}

#[test]
fn test_tcp_transport_creation() {
    let addr = DnsServerBuilder::google_dns();
    let transport = TcpTransport::new(addr);

    assert_eq!(transport.protocol_name(), "TCP");
}

#[test]
fn test_tcp_transport_ipv6() {
    let addr = DnsServerBuilder::cloudflare_dns_ipv6();
    let transport = TcpTransport::new(addr);

    assert_eq!(transport.protocol_name(), "TCP");
}

#[test]
fn test_length_prefix_encoding() {
    let len: u16 = 300;
    let bytes = len.to_be_bytes();
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1], 44);
    assert_eq!(u16::from_be_bytes(bytes), 300);
}

#[test]
fn test_tcp_length_prefix_various_sizes() {
    let sizes = vec![0u16, 1, 255, 256, 512, 1024, 4096, u16::MAX];

    for size in sizes {
        let bytes = size.to_be_bytes();
        let reconstructed = u16::from_be_bytes(bytes);
        assert_eq!(reconstructed, size, "Failed for size {}", size);
    }
}

#[test]
fn test_tls_transport_creation() {
    let (addr, hostname) = DnsServerBuilder::cloudflare_tls();
    let transport = TlsTransport::new(addr, hostname.clone());

    assert_eq!(transport.protocol_name(), "TLS");
}

#[test]
fn test_tls_transport_google() {
    let (addr, hostname) = DnsServerBuilder::google_tls();
    let transport = TlsTransport::new(addr, hostname.clone());

    assert_eq!(transport.protocol_name(), "TLS");
}

#[test]
fn test_tls_transport_different_hostnames() {
    let _cloudflare = TlsTransport::new(
        UpstreamAddr::Resolved("1.1.1.1:853".parse().unwrap()),
        "cloudflare-dns.com".to_string(),
    );

    let _google = TlsTransport::new(
        UpstreamAddr::Resolved("8.8.8.8:853".parse().unwrap()),
        "dns.google".to_string(),
    );
}

#[test]
fn test_https_transport_creation() {
    let url = DnsServerBuilder::cloudflare_https();
    let transport = HttpsTransport::new(url.clone(), "1.1.1.1".to_string(), vec![]);

    assert_eq!(transport.protocol_name(), "HTTPS");
}

#[test]
fn test_https_transport_google() {
    let url = DnsServerBuilder::google_https();
    let transport = HttpsTransport::new(url.clone(), "dns.google".to_string(), vec![]);

    assert_eq!(transport.protocol_name(), "HTTPS");
}

#[test]
fn test_https_transport_custom_url() {
    let custom_url = "https://example.com/dns-query".to_string();
    let _transport = HttpsTransport::new(custom_url.clone(), "example.com".to_string(), vec![]);
}

#[test]
fn test_https_transport_various_providers() {
    let providers = vec![
        "https://1.1.1.1/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
    ];

    for provider in providers {
        let hostname = provider
            .strip_prefix("https://")
            .and_then(|r| r.split('/').next())
            .unwrap_or("")
            .to_string();
        let transport = HttpsTransport::new(provider.to_string(), hostname, vec![]);

        assert_eq!(transport.protocol_name(), "HTTPS");
    }
}

#[cfg(feature = "dns-over-quic")]
#[test]
fn test_quic_transport_protocol_name() {
    let (addr, hostname) = DnsServerBuilder::cloudflare_doq();
    let transport = QuicTransport::new(addr, hostname.into());

    assert_eq!(transport.protocol_name(), "QUIC");
}

#[cfg(feature = "dns-over-quic")]
#[test]
fn test_quic_transport_google() {
    let (addr, hostname) = DnsServerBuilder::google_doq();
    let transport = QuicTransport::new(addr, hostname.into());

    assert_eq!(transport.protocol_name(), "QUIC");
}

#[cfg(feature = "dns-over-quic")]
#[test]
fn test_quic_transport_creation() {
    let (addr, hostname) = DnsServerBuilder::cloudflare_doq();
    let transport = QuicTransport::new(addr, hostname.into());

    assert_eq!(transport.protocol_name(), "QUIC");
}

#[cfg(feature = "dns-over-h3")]
#[test]
fn test_h3_transport_creation() {
    let url = DnsServerBuilder::cloudflare_h3();
    let transport = H3Transport::new(url, vec![]);

    assert_eq!(transport.protocol_name(), "H3");
}

#[cfg(feature = "dns-over-h3")]
#[test]
fn test_h3_transport_google() {
    let url = DnsServerBuilder::google_h3();
    let transport = H3Transport::new(url, vec![]);

    assert_eq!(transport.protocol_name(), "H3");
}

#[test]
fn test_all_protocols_have_unique_names() {
    let udp = UdpTransport::new(DnsServerBuilder::google_dns());
    let tcp = TcpTransport::new(DnsServerBuilder::google_dns());
    let (tls_addr, tls_host) = DnsServerBuilder::cloudflare_tls();
    let tls = TlsTransport::new(tls_addr, tls_host);
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

#[test]
fn test_port_numbers() {
    let udp_addr = DnsServerBuilder::google_dns_socket_addr();
    let tls_addr = DnsServerBuilder::cloudflare_tls_socket_addr();

    assert_eq!(udp_addr.port(), 53, "Standard DNS port");
    assert_eq!(tls_addr.port(), 853, "DNS-over-TLS port");
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

// ── Fase 5: Health checker, error classification ──────────────────────────────

#[test]
fn test_health_checker_consecutive_failures_does_not_overflow() {
    use ferrous_dns_infrastructure::dns::load_balancer::health::ServerHealth;

    let mut health = ServerHealth::default();

    for _ in 0..300u32 {
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
    }

    assert_eq!(
        health.consecutive_failures, 300,
        "u16 saturating_add must record all 300 failures accurately"
    );
    assert!(
        health.consecutive_failures > u8::MAX as u16,
        "consecutive_failures ({}) must exceed u8::MAX — no u8 wrap-around",
        health.consecutive_failures
    );
}

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
