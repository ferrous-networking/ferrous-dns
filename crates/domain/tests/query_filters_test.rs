use ferrous_dns_domain::{FqdnFilter, PrivateIpFilter};

// ============================================================================
// Tests for PrivateIpFilter
// ============================================================================

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
fn test_private_ipv4_edge_cases() {
    // Edge of 10.0.0.0/8
    assert!(PrivateIpFilter::is_private_ip(&"10.0.0.0".parse().unwrap()));
    assert!(PrivateIpFilter::is_private_ip(
        &"10.255.255.255".parse().unwrap()
    ));
    assert!(!PrivateIpFilter::is_private_ip(
        &"9.255.255.255".parse().unwrap()
    ));
    assert!(!PrivateIpFilter::is_private_ip(
        &"11.0.0.0".parse().unwrap()
    ));

    // Edge of 172.16.0.0/12
    assert!(PrivateIpFilter::is_private_ip(
        &"172.16.0.0".parse().unwrap()
    ));
    assert!(PrivateIpFilter::is_private_ip(
        &"172.31.255.255".parse().unwrap()
    ));
    assert!(!PrivateIpFilter::is_private_ip(
        &"172.15.255.255".parse().unwrap()
    ));
    assert!(!PrivateIpFilter::is_private_ip(
        &"172.32.0.0".parse().unwrap()
    ));

    // Edge of 192.168.0.0/16
    assert!(PrivateIpFilter::is_private_ip(
        &"192.168.0.0".parse().unwrap()
    ));
    assert!(PrivateIpFilter::is_private_ip(
        &"192.168.255.255".parse().unwrap()
    ));
    assert!(!PrivateIpFilter::is_private_ip(
        &"192.167.255.255".parse().unwrap()
    ));
    assert!(!PrivateIpFilter::is_private_ip(
        &"192.169.0.0".parse().unwrap()
    ));
}

#[test]
fn test_extract_ip_from_ptr_ipv4() {
    // Valid IPv4 PTR
    let ip = PrivateIpFilter::extract_ip_from_ptr("1.0.168.192.in-addr.arpa");
    assert_eq!(ip, Some("192.168.0.1".parse().unwrap()));

    let ip = PrivateIpFilter::extract_ip_from_ptr("100.1.168.192.in-addr.arpa");
    assert_eq!(ip, Some("192.168.1.100".parse().unwrap()));

    let ip = PrivateIpFilter::extract_ip_from_ptr("8.8.8.8.in-addr.arpa");
    assert_eq!(ip, Some("8.8.8.8".parse().unwrap()));

    // Invalid formats
    assert!(PrivateIpFilter::extract_ip_from_ptr("google.com").is_none());
    assert!(PrivateIpFilter::extract_ip_from_ptr("1.2.3.in-addr.arpa").is_none());
    assert!(PrivateIpFilter::extract_ip_from_ptr("").is_none());
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
    assert!(PrivateIpFilter::is_private_ptr_query(
        "1.1.254.169.in-addr.arpa"
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
    assert!(!PrivateIpFilter::is_private_ptr_query(""));
}

// ============================================================================
// Tests for FqdnFilter
// ============================================================================

#[test]
fn test_is_fqdn() {
    // Valid FQDNs
    assert!(FqdnFilter::is_fqdn("google.com"));
    assert!(FqdnFilter::is_fqdn("sub.domain.com"));
    assert!(FqdnFilter::is_fqdn("a.b.c.d.com"));
    assert!(FqdnFilter::is_fqdn("nas.home.lan"));
    assert!(FqdnFilter::is_fqdn("server.local.network"));

    // Invalid FQDNs (local hostnames)
    assert!(!FqdnFilter::is_fqdn("nas"));
    assert!(!FqdnFilter::is_fqdn("servidor"));
    assert!(!FqdnFilter::is_fqdn("localhost"));
    assert!(!FqdnFilter::is_fqdn("desktop"));
    assert!(!FqdnFilter::is_fqdn("raspberry"));

    // Edge cases
    assert!(!FqdnFilter::is_fqdn("google.com.")); // Trailing dot
    assert!(!FqdnFilter::is_fqdn(""));
    assert!(!FqdnFilter::is_fqdn("."));
}

#[test]
fn test_is_local_hostname() {
    // Local hostnames
    assert!(FqdnFilter::is_local_hostname("nas"));
    assert!(FqdnFilter::is_local_hostname("servidor"));
    assert!(FqdnFilter::is_local_hostname("localhost"));
    assert!(FqdnFilter::is_local_hostname("desktop"));
    assert!(FqdnFilter::is_local_hostname("mypc"));

    // FQDNs
    assert!(!FqdnFilter::is_local_hostname("google.com"));
    assert!(!FqdnFilter::is_local_hostname("nas.home.lan"));
    assert!(!FqdnFilter::is_local_hostname("server.local"));
}

#[test]
fn test_fqdn_edge_cases() {
    // Single character labels
    assert!(FqdnFilter::is_fqdn("a.b"));
    assert!(!FqdnFilter::is_fqdn("a"));

    // Numbers in domain
    assert!(FqdnFilter::is_fqdn("server1.example.com"));
    assert!(FqdnFilter::is_fqdn("192-168-1-1.local"));

    // Hyphens
    assert!(FqdnFilter::is_fqdn("my-server.example.com"));
    assert!(FqdnFilter::is_fqdn("ex-ample.co-m"));

    // Long labels
    assert!(FqdnFilter::is_fqdn("verylongsubdomainname.example.com"));
}

#[test]
fn test_common_local_hostnames() {
    let local_hostnames = vec![
        "localhost",
        "nas",
        "router",
        "printer",
        "desktop",
        "laptop",
        "raspberry",
        "server",
        "workstation",
    ];

    for hostname in local_hostnames {
        assert!(
            FqdnFilter::is_local_hostname(hostname),
            "{} should be local hostname",
            hostname
        );
    }
}

#[test]
fn test_common_fqdns() {
    let fqdns = vec![
        "google.com",
        "github.com",
        "api.example.com",
        "mail.google.com",
        "cdn.cloudflare.com",
    ];

    for fqdn in fqdns {
        assert!(FqdnFilter::is_fqdn(fqdn), "{} should be FQDN", fqdn);
    }
}
