use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Private IP ranges as defined by RFC 1918 (IPv4) and RFC 4193 (IPv6)
const PRIVATE_IPV4_RANGES: &[(u8, u8, u8, u8, u8)] = &[
    (10, 0, 0, 0, 8),     // 10.0.0.0/8
    (172, 16, 0, 0, 12),  // 172.16.0.0/12
    (192, 168, 0, 0, 16), // 192.168.0.0/16
    (169, 254, 0, 0, 16), // 169.254.0.0/16 (link-local)
    (127, 0, 0, 0, 8),    // 127.0.0.0/8 (loopback)
];

/// Private IPv6 prefixes
const PRIVATE_IPV6_PREFIXES: &[&str] = &[
    "fc00:", // Unique Local Address (ULA)
    "fd00:", // Unique Local Address (ULA)
    "fe80:", // Link-local
    "::1",   // Loopback
];

/// Filter for private IP addresses (RFC 1918 ranges)
pub struct PrivateIpFilter;

impl PrivateIpFilter {
    /// Check if an IP address is in a private range
    ///
    /// Returns `true` for:
    /// - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8
    /// - IPv6: fc00::/7 (ULA), fe80::/10 (link-local), ::1 (loopback)
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
        let addr_str = ip.to_string();
        PRIVATE_IPV6_PREFIXES
            .iter()
            .any(|prefix| addr_str.starts_with(prefix))
    }

    fn matches_ipv4_range(ip: [u8; 4], network: (u8, u8, u8, u8), mask: u8) -> bool {
        let shift = 32 - mask;
        let ip_int = u32::from_be_bytes(ip);
        let net_int = u32::from_be_bytes([network.0, network.1, network.2, network.3]);
        (ip_int >> shift) == (net_int >> shift)
    }

    /// Extract IP address from PTR query domain
    ///
    /// Examples:
    /// - "1.0.168.192.in-addr.arpa" → Some(192.168.0.1)
    /// - "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" → Some(IPv6)
    pub fn extract_ip_from_ptr(domain: &str) -> Option<IpAddr> {
        // IPv4 PTR: "1.0.168.192.in-addr.arpa" -> "192.168.0.1"
        if let Some(ipv4_str) = domain.strip_suffix(".in-addr.arpa") {
            // Reverse octets: "1.0.168.192" -> ["1", "0", "168", "192"]
            let parts: Vec<&str> = ipv4_str.split('.').collect();
            if parts.len() == 4 {
                // Reverse: ["192", "168", "0", "1"]
                let reversed: Vec<&str> = parts.iter().rev().copied().collect();
                if let Ok(ip) = reversed.join(".").parse::<Ipv4Addr>() {
                    return Some(IpAddr::V4(ip));
                }
            }
        }

        // IPv6 PTR: "b.a.9.8.7.6.5.0...ip6.arpa"
        if let Some(ipv6_hex) = domain.strip_suffix(".ip6.arpa") {
            // Reverse nibbles and reconstruct IPv6
            let nibbles: Vec<char> = ipv6_hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();

            if nibbles.len() == 32 {
                // Reverse nibbles
                let reversed: String = nibbles.iter().rev().collect();

                // Group into 4-char chunks with colons
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

    /// Check if a domain is a PTR query for a private IP
    pub fn is_private_ptr_query(domain: &str) -> bool {
        if let Some(ip) = Self::extract_ip_from_ptr(domain) {
            Self::is_private_ip(&ip)
        } else {
            false
        }
    }
}

/// Filter for Fully Qualified Domain Names (FQDN)
pub struct FqdnFilter;

impl FqdnFilter {
    /// Check if a domain is a Fully Qualified Domain Name
    ///
    /// A FQDN must contain at least one dot and not end with a dot.
    ///
    /// Examples:
    /// - "google.com" → true (FQDN)
    /// - "sub.domain.com" → true (FQDN)
    /// - "nas" → false (local hostname)
    /// - "servidor" → false (local hostname)
    /// - "localhost" → false (local hostname)
    pub fn is_fqdn(domain: &str) -> bool {
        // Must contain at least one dot
        let has_dot = domain.contains('.');

        // Must not end with a dot (trailing dot is used in zone files)
        let no_trailing_dot = !domain.ends_with('.');

        // Special case: single-label domains are not FQDNs
        let parts: Vec<&str> = domain.split('.').collect();
        let multi_label = parts.len() >= 2;

        has_dot && no_trailing_dot && multi_label
    }

    /// Check if a domain appears to be a local hostname (non-FQDN)
    ///
    /// Returns `true` for single-label domains without dots.
    pub fn is_local_hostname(domain: &str) -> bool {
        !Self::is_fqdn(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4_detection() {
        // Private ranges
        assert!(PrivateIpFilter::is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(PrivateIpFilter::is_private_ip(
            &"10.255.255.254".parse().unwrap()
        ));
        assert!(PrivateIpFilter::is_private_ip(
            &"172.16.0.1".parse().unwrap()
        ));
        assert!(PrivateIpFilter::is_private_ip(
            &"172.31.255.254".parse().unwrap()
        ));
        assert!(PrivateIpFilter::is_private_ip(
            &"192.168.1.1".parse().unwrap()
        ));
        assert!(PrivateIpFilter::is_private_ip(
            &"192.168.255.254".parse().unwrap()
        ));
        assert!(PrivateIpFilter::is_private_ip(
            &"127.0.0.1".parse().unwrap()
        ));
        assert!(PrivateIpFilter::is_private_ip(
            &"169.254.1.1".parse().unwrap()
        ));

        // Public ranges
        assert!(!PrivateIpFilter::is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!PrivateIpFilter::is_private_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!PrivateIpFilter::is_private_ip(&"9.9.9.9".parse().unwrap()));
        assert!(!PrivateIpFilter::is_private_ip(
            &"172.15.0.1".parse().unwrap()
        ));
        assert!(!PrivateIpFilter::is_private_ip(
            &"172.32.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn test_extract_ip_from_ptr_ipv4() {
        // Valid IPv4 PTR
        let ip = PrivateIpFilter::extract_ip_from_ptr("1.0.168.192.in-addr.arpa");
        assert_eq!(ip, Some("192.168.0.1".parse().unwrap()));

        let ip = PrivateIpFilter::extract_ip_from_ptr("100.1.168.192.in-addr.arpa");
        assert_eq!(ip, Some("192.168.1.100".parse().unwrap()));

        // Invalid formats
        assert!(PrivateIpFilter::extract_ip_from_ptr("google.com").is_none());
        assert!(PrivateIpFilter::extract_ip_from_ptr("1.2.3.in-addr.arpa").is_none());
    }

    #[test]
    fn test_is_private_ptr_query() {
        // Private IP PTR queries
        assert!(PrivateIpFilter::is_private_ptr_query(
            "1.0.168.192.in-addr.arpa"
        ));
        assert!(PrivateIpFilter::is_private_ptr_query(
            "100.1.0.10.in-addr.arpa"
        ));
        assert!(PrivateIpFilter::is_private_ptr_query(
            "1.0.0.127.in-addr.arpa"
        ));

        // Public IP PTR queries
        assert!(!PrivateIpFilter::is_private_ptr_query(
            "8.8.8.8.in-addr.arpa"
        ));
        assert!(!PrivateIpFilter::is_private_ptr_query(
            "1.1.1.1.in-addr.arpa"
        ));

        // Non-PTR queries
        assert!(!PrivateIpFilter::is_private_ptr_query("google.com"));
        assert!(!PrivateIpFilter::is_private_ptr_query("nas.home.lan"));
    }

    #[test]
    fn test_is_fqdn() {
        // Valid FQDNs
        assert!(FqdnFilter::is_fqdn("google.com"));
        assert!(FqdnFilter::is_fqdn("sub.domain.com"));
        assert!(FqdnFilter::is_fqdn("a.b.c.d.com"));
        assert!(FqdnFilter::is_fqdn("nas.home.lan"));

        // Invalid FQDNs (local hostnames)
        assert!(!FqdnFilter::is_fqdn("nas"));
        assert!(!FqdnFilter::is_fqdn("servidor"));
        assert!(!FqdnFilter::is_fqdn("localhost"));
        assert!(!FqdnFilter::is_fqdn("desktop"));

        // Edge cases
        assert!(!FqdnFilter::is_fqdn("google.com.")); // Trailing dot
        assert!(!FqdnFilter::is_fqdn(""));
    }

    #[test]
    fn test_is_local_hostname() {
        // Local hostnames
        assert!(FqdnFilter::is_local_hostname("nas"));
        assert!(FqdnFilter::is_local_hostname("servidor"));
        assert!(FqdnFilter::is_local_hostname("localhost"));

        // FQDNs
        assert!(!FqdnFilter::is_local_hostname("google.com"));
        assert!(!FqdnFilter::is_local_hostname("nas.home.lan"));
    }
}
