use ferrous_dns_infrastructure::system::PtrHostnameResolver;
use std::net::IpAddr;

#[test]
fn test_ip_to_reverse_domain_ipv4() {
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    let reverse = PtrHostnameResolver::ip_to_reverse_domain(&ip);
    assert_eq!(reverse, "1.1.168.192.in-addr.arpa");
}

#[test]
fn test_ip_to_reverse_domain_ipv4_zeros() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let reverse = PtrHostnameResolver::ip_to_reverse_domain(&ip);
    assert_eq!(reverse, "1.0.0.10.in-addr.arpa");
}

#[test]
fn test_ip_to_reverse_domain_ipv6() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    let reverse = PtrHostnameResolver::ip_to_reverse_domain(&ip);
    assert!(reverse.ends_with(".ip6.arpa"));
    assert!(reverse.contains("8.b.d.0.1.0.0.2"));
}
