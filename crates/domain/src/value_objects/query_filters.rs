use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PRIVATE_IPV4_RANGES: &[(u8, u8, u8, u8, u8)] = &[
    (10, 0, 0, 0, 8),
    (172, 16, 0, 0, 12),
    (192, 168, 0, 0, 16),
    (169, 254, 0, 0, 16),
    (127, 0, 0, 0, 8),
];

pub struct PrivateIpFilter;

impl PrivateIpFilter {
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => Self::is_private_ipv4(ipv4),
            IpAddr::V6(ipv6) => Self::is_private_ipv6(ipv6),
        }
    }

    fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();
        PRIVATE_IPV4_RANGES
            .iter()
            .any(|(a, b, c, d, mask)| Self::matches_ipv4_range(octets, (*a, *b, *c, *d), *mask))
    }

    fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
        // IPv4-mapped addresses (`::ffff:a.b.c.d`) carry an IPv4 payload — unmap
        // and apply the IPv4 ranges so a private IPv4 delivered as an AAAA record
        // can't bypass the rebinding check.
        if let Some(ipv4) = ip.to_ipv4_mapped() {
            return Self::is_private_ipv4(&ipv4);
        }

        let segments = ip.segments();
        // `::1` loopback.
        ip.is_loopback()
            // Unique local addresses: fc00::/7 (RFC 4193).
            || (segments[0] & 0xfe00) == 0xfc00
            // Link-local unicast: fe80::/10 (RFC 4291).
            || (segments[0] & 0xffc0) == 0xfe80
    }

    fn matches_ipv4_range(ip: [u8; 4], network: (u8, u8, u8, u8), mask: u8) -> bool {
        let shift = 32 - mask;
        let ip_int = u32::from_be_bytes(ip);
        let net_int = u32::from_be_bytes([network.0, network.1, network.2, network.3]);
        (ip_int >> shift) == (net_int >> shift)
    }

    pub fn extract_ip_from_ptr(domain: &str) -> Option<IpAddr> {
        if let Some(ipv4_str) = domain.strip_suffix(".in-addr.arpa") {
            let parts: Vec<&str> = ipv4_str.split('.').collect();
            if parts.len() == 4 {
                let reversed: Vec<&str> = parts.iter().rev().copied().collect();
                if let Ok(ip) = reversed.join(".").parse::<Ipv4Addr>() {
                    return Some(IpAddr::V4(ip));
                }
            }
        }

        if let Some(ipv6_hex) = domain.strip_suffix(".ip6.arpa") {
            let nibbles: Vec<char> = ipv6_hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();

            if nibbles.len() == 32 {
                let reversed: String = nibbles.iter().rev().collect();

                let chunks: Vec<String> = reversed
                    .chars()
                    .collect::<Vec<char>>()
                    .chunks(4)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect();

                let ipv6_str = chunks.join(":");

                if let Ok(ip) = ipv6_str.parse::<Ipv6Addr>() {
                    return Some(IpAddr::V6(ip));
                }
            }
        }

        None
    }

    pub fn is_private_ptr_query(domain: &str) -> bool {
        if let Some(ip) = Self::extract_ip_from_ptr(domain) {
            Self::is_private_ip(&ip)
        } else {
            false
        }
    }
}

pub struct FqdnFilter;

impl FqdnFilter {
    pub fn is_fqdn(domain: &str) -> bool {
        let has_dot = domain.contains('.');

        let no_trailing_dot = !domain.ends_with('.');

        let parts: Vec<&str> = domain.split('.').collect();
        let multi_label = parts.len() >= 2;

        has_dot && no_trailing_dot && multi_label
    }

    pub fn is_local_hostname(domain: &str) -> bool {
        !Self::is_fqdn(domain)
    }
}
