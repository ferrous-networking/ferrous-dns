#![allow(dead_code)]
use std::net::SocketAddr;
use std::sync::Arc;

pub struct DnsServerBuilder;

impl DnsServerBuilder {
    
    pub fn google_dns() -> SocketAddr {
        "8.8.8.8:53".parse().unwrap()
    }

    pub fn google_dns_ipv6() -> SocketAddr {
        "[2001:4860:4860::8888]:53".parse().unwrap()
    }

    pub fn cloudflare_dns() -> SocketAddr {
        "1.1.1.1:53".parse().unwrap()
    }

    pub fn cloudflare_dns_ipv6() -> SocketAddr {
        "[2606:4700:4700::1111]:53".parse().unwrap()
    }

    pub fn cloudflare_tls() -> (SocketAddr, String) {
        (
            "1.1.1.1:853".parse().unwrap(),
            "cloudflare-dns.com".to_string(),
        )
    }

    pub fn google_tls() -> (SocketAddr, String) {
        ("8.8.8.8:853".parse().unwrap(), "dns.google".to_string())
    }

    pub fn cloudflare_https() -> String {
        "https://1.1.1.1/dns-query".to_string()
    }

    pub fn google_https() -> String {
        "https://dns.google/dns-query".to_string()
    }

    pub fn local_test() -> SocketAddr {
        "127.0.0.1:15353".parse().unwrap()
    }

    pub fn custom(addr: &str) -> SocketAddr {
        addr.parse().expect("Invalid socket address")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_server_builder() {
        let google = DnsServerBuilder::google_dns();
        assert_eq!(google.port(), 53);
        assert!(google.is_ipv4());

        let cloudflare = DnsServerBuilder::cloudflare_dns();
        assert_eq!(cloudflare.port(), 53);

        let (tls_addr, tls_hostname) = DnsServerBuilder::cloudflare_tls();
        assert_eq!(tls_addr.port(), 853);
        assert_eq!(tls_hostname, "cloudflare-dns.com");
    }

    #[test]
    fn test_udp_pool_builder() {
        let small = UdpPoolBuilder::small();
        assert!(Arc::strong_count(&small) == 1);

        let medium = UdpPoolBuilder::medium();
        assert!(Arc::strong_count(&medium) == 1);
    }

    #[test]
    fn test_ipv6_addresses() {
        let google_v6 = DnsServerBuilder::google_dns_ipv6();
        assert!(google_v6.is_ipv6());
        assert_eq!(google_v6.port(), 53);

        let cloudflare_v6 = DnsServerBuilder::cloudflare_dns_ipv6();
        assert!(cloudflare_v6.is_ipv6());
    }
}
