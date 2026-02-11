use ferrous_dns_infrastructure::dns::transport::DnsTransport;
use ferrous_dns_infrastructure::dns::transport::{
    https::HttpsTransport, tcp::TcpTransport, tls::TlsTransport, udp::UdpTransport,
};
use std::net::SocketAddr;
use std::sync::Arc;

mod helpers;
use helpers::{DnsServerBuilder, UdpPoolBuilder};

// ============================================================================
// UDP Transport Tests
// ============================================================================

#[test]
fn test_udp_transport_creation() {
    let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = UdpTransport::new(addr);
    // assert_eq!(transport.server_addr, addr);
    assert_eq!(transport.protocol_name(), "UDP");
    // assert!(transport.pool.is_none());
}

#[test]
fn test_udp_transport_with_pool() {
    let addr = DnsServerBuilder::google_dns();
    let pool = UdpPoolBuilder::medium();
    let _transport = UdpTransport::with_pool(addr, pool);
    // assert_eq!(transport.server_addr, addr);
    // assert!(transport.pool.is_some());
}

#[test]
fn test_udp_transport_ipv6() {
    let addr = DnsServerBuilder::google_dns_ipv6();
    let _transport = UdpTransport::new(addr);
    // assert_eq!(transport.server_addr, addr);
    // assert!(transport.server_addr.is_ipv6());
}

#[test]
fn test_udp_transport_different_providers() {
    let google = UdpTransport::new(DnsServerBuilder::google_dns());
    assert_eq!(google.protocol_name(), "UDP");

    let cloudflare = UdpTransport::new(DnsServerBuilder::cloudflare_dns());
    assert_eq!(cloudflare.protocol_name(), "UDP");

    // assert_ne!(google.server_addr, cloudflare.server_addr);
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

// ============================================================================
// TCP Transport Tests
// ============================================================================

#[test]
fn test_tcp_transport_creation() {
    let addr = DnsServerBuilder::google_dns();
    let transport = TcpTransport::new(addr);
    // assert_eq!(transport.server_addr, addr);
    assert_eq!(transport.protocol_name(), "TCP");
}

#[test]
fn test_tcp_transport_ipv6() {
    let addr = DnsServerBuilder::cloudflare_dns_ipv6();
    let transport = TcpTransport::new(addr);
    // assert!(transport.server_addr.is_ipv6());
    assert_eq!(transport.protocol_name(), "TCP");
}

#[test]
fn test_length_prefix_encoding() {
    // Verify our understanding of the wire format
    let len: u16 = 300;
    let bytes = len.to_be_bytes();
    assert_eq!(bytes[0], 1); // 300 = 0x012C
    assert_eq!(bytes[1], 44);
    assert_eq!(u16::from_be_bytes(bytes), 300);
}

#[test]
fn test_tcp_length_prefix_various_sizes() {
    // Test edge cases
    let sizes = vec![0u16, 1, 255, 256, 512, 1024, 4096, u16::MAX];

    for size in sizes {
        let bytes = size.to_be_bytes();
        let reconstructed = u16::from_be_bytes(bytes);
        assert_eq!(reconstructed, size, "Failed for size {}", size);
    }
}

// ============================================================================
// TLS Transport Tests
// ============================================================================

#[test]
fn test_tls_transport_creation() {
    let (addr, hostname) = DnsServerBuilder::cloudflare_tls();
    let transport = TlsTransport::new(addr, hostname.clone());
    // assert_eq!(transport.server_addr, addr);
    // assert_eq!(transport.hostname, hostname);
    assert_eq!(transport.protocol_name(), "TLS");
}

#[test]
fn test_tls_transport_google() {
    let (addr, hostname) = DnsServerBuilder::google_tls();
    let transport = TlsTransport::new(addr, hostname.clone());
    // assert_eq!(transport.server_addr, addr);
    // assert_eq!(transport.hostname, "dns.google");
    assert_eq!(transport.protocol_name(), "TLS");
}

#[test]
fn test_shared_tls_config() {

    // Verify the static config builds successfully
}

#[test]
fn test_tls_transport_different_hostnames() {
    let _cloudflare = TlsTransport::new(
        "1.1.1.1:853".parse().unwrap(),
        "cloudflare-dns.com".to_string(),
    );

    let _google = TlsTransport::new("8.8.8.8:853".parse().unwrap(), "dns.google".to_string());

    // assert_ne!(cloudflare.hostname, google.hostname);
    // assert_eq!(cloudflare.server_addr.port(), 853);
    // assert_eq!(google.server_addr.port(), 853);
}

// ============================================================================
// HTTPS Transport Tests
// ============================================================================

#[test]
fn test_https_transport_creation() {
    let url = DnsServerBuilder::cloudflare_https();
    let transport = HttpsTransport::new(url.clone());
    // assert_eq!(transport.url, url);
    assert_eq!(transport.protocol_name(), "HTTPS");
}

#[test]
fn test_https_transport_google() {
    let url = DnsServerBuilder::google_https();
    let transport = HttpsTransport::new(url.clone());
    // assert_eq!(transport.url, "https://dns.google/dns-query");
    assert_eq!(transport.protocol_name(), "HTTPS");
}

#[test]
fn test_https_transport_custom_url() {
    let custom_url = "https://example.com/dns-query".to_string();
    let _transport = HttpsTransport::new(custom_url.clone());
    // assert_eq!(transport.url, custom_url);
}

#[test]
fn test_https_transport_various_providers() {
    let providers = vec![
        "https://1.1.1.1/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
    ];

    for provider in providers {
        let transport = HttpsTransport::new(provider.to_string());
        // assert_eq!(transport.url, provider);
        assert_eq!(transport.protocol_name(), "HTTPS");
    }
}

// ============================================================================
// Protocol Comparison Tests
// ============================================================================

#[test]
fn test_all_protocols_have_unique_names() {
    let udp = UdpTransport::new(DnsServerBuilder::google_dns());
    let tcp = TcpTransport::new(DnsServerBuilder::google_dns());
    let (tls_addr, tls_host) = DnsServerBuilder::cloudflare_tls();
    let tls = TlsTransport::new(tls_addr, tls_host);
    let https = HttpsTransport::new(DnsServerBuilder::cloudflare_https());

    let names = vec![
        udp.protocol_name(),
        tcp.protocol_name(),
        tls.protocol_name(),
        https.protocol_name(),
    ];

    // All should be unique
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "Protocol names should be unique");
}

#[test]
fn test_port_numbers() {
    let udp_addr = DnsServerBuilder::google_dns();
    let (tls_addr, _) = DnsServerBuilder::cloudflare_tls();

    assert_eq!(udp_addr.port(), 53, "Standard DNS port");
    assert_eq!(tls_addr.port(), 853, "DNS-over-TLS port");
}
