#![allow(dead_code)]
use ferrous_dns_domain::UpstreamAddr;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct DnsServerBuilder;

impl DnsServerBuilder {
    pub fn google_dns() -> UpstreamAddr {
        UpstreamAddr::Resolved("8.8.8.8:53".parse().unwrap())
    }

    pub fn google_dns_ipv6() -> UpstreamAddr {
        UpstreamAddr::Resolved("[2001:4860:4860::8888]:53".parse().unwrap())
    }

    pub fn cloudflare_dns() -> UpstreamAddr {
        UpstreamAddr::Resolved("1.1.1.1:53".parse().unwrap())
    }

    pub fn cloudflare_dns_ipv6() -> UpstreamAddr {
        UpstreamAddr::Resolved("[2606:4700:4700::1111]:53".parse().unwrap())
    }

    pub fn cloudflare_tls() -> (UpstreamAddr, String) {
        (
            UpstreamAddr::Resolved("1.1.1.1:853".parse().unwrap()),
            "cloudflare-dns.com".to_string(),
        )
    }

    pub fn google_tls() -> (UpstreamAddr, String) {
        (
            UpstreamAddr::Resolved("8.8.8.8:853".parse().unwrap()),
            "dns.google".to_string(),
        )
    }

    pub fn cloudflare_https() -> String {
        "https://1.1.1.1/dns-query".to_string()
    }

    pub fn google_https() -> String {
        "https://dns.google/dns-query".to_string()
    }

    pub fn cloudflare_doq() -> (UpstreamAddr, String) {
        (
            UpstreamAddr::Resolved("1.1.1.1:853".parse().unwrap()),
            "cloudflare-dns.com".to_string(),
        )
    }

    pub fn google_doq() -> (UpstreamAddr, String) {
        (
            UpstreamAddr::Resolved("8.8.8.8:853".parse().unwrap()),
            "dns.google".to_string(),
        )
    }

    pub fn cloudflare_h3() -> String {
        "h3://1.1.1.1/dns-query".to_string()
    }

    pub fn google_h3() -> String {
        "h3://dns.google/dns-query".to_string()
    }

    pub fn local_test() -> UpstreamAddr {
        UpstreamAddr::Resolved("127.0.0.1:15353".parse().unwrap())
    }

    pub fn custom(addr: &str) -> UpstreamAddr {
        UpstreamAddr::Resolved(addr.parse::<SocketAddr>().expect("Invalid socket address"))
    }

    pub fn google_dns_socket_addr() -> SocketAddr {
        "8.8.8.8:53".parse().unwrap()
    }

    pub fn cloudflare_tls_socket_addr() -> SocketAddr {
        "1.1.1.1:853".parse().unwrap()
    }
}

pub struct UdpPoolBuilder;

impl UdpPoolBuilder {
    pub fn small() -> Arc<ferrous_dns_infrastructure::dns::transport::UdpSocketPool> {
        Arc::new(ferrous_dns_infrastructure::dns::transport::UdpSocketPool::new(4, 50))
    }

    pub fn medium() -> Arc<ferrous_dns_infrastructure::dns::transport::UdpSocketPool> {
        Arc::new(ferrous_dns_infrastructure::dns::transport::UdpSocketPool::new(8, 100))
    }

    pub fn large() -> Arc<ferrous_dns_infrastructure::dns::transport::UdpSocketPool> {
        Arc::new(ferrous_dns_infrastructure::dns::transport::UdpSocketPool::new(16, 200))
    }

    pub fn custom(
        pool_size: usize,
        buffer_size: usize,
    ) -> Arc<ferrous_dns_infrastructure::dns::transport::UdpSocketPool> {
        Arc::new(
            ferrous_dns_infrastructure::dns::transport::UdpSocketPool::new(pool_size, buffer_size),
        )
    }
}
