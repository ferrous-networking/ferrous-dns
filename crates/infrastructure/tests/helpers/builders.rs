#![allow(dead_code)]
use ferrous_dns_domain::UpstreamAddr;
use std::net::SocketAddr;

pub struct DnsServerBuilder;

impl DnsServerBuilder {
    pub fn google_dns() -> UpstreamAddr {
        UpstreamAddr::Resolved("8.8.8.8:53".parse().unwrap())
    }

    pub fn cloudflare_dns() -> UpstreamAddr {
        UpstreamAddr::Resolved("1.1.1.1:53".parse().unwrap())
    }

    pub fn cloudflare_tls() -> (UpstreamAddr, String) {
        (
            UpstreamAddr::Resolved("1.1.1.1:853".parse().unwrap()),
            "cloudflare-dns.com".to_string(),
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
}
