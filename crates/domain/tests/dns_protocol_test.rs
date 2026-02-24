use ferrous_dns_domain::DnsProtocol;

#[test]
fn test_parse_udp() {
    let protocol: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    assert!(matches!(protocol, DnsProtocol::Udp { .. }));
}

#[test]
fn test_parse_udp_default() {
    let protocol: DnsProtocol = "8.8.8.8:53".parse().unwrap();
    assert!(matches!(protocol, DnsProtocol::Udp { .. }));
}

#[test]
fn test_parse_tcp() {
    let protocol: DnsProtocol = "tcp://8.8.8.8:53".parse().unwrap();
    assert!(matches!(protocol, DnsProtocol::Tcp { .. }));
}

#[test]
fn test_parse_tls() {
    let protocol: DnsProtocol = "tls://1.1.1.1:853".parse().unwrap();
    assert!(matches!(protocol, DnsProtocol::Tls { .. }));
}

#[test]
fn test_parse_tls_hostname() {
    let protocol: DnsProtocol = "tls://dns.google:853".parse().unwrap();
    if let DnsProtocol::Tls { hostname, addr } = protocol {
        assert_eq!(&*hostname, "dns.google");
        assert_eq!(addr.port(), 853);
    } else {
        panic!("Expected Tls variant");
    }
}

#[test]
fn test_parse_https() {
    let protocol: DnsProtocol = "https://1.1.1.1/dns-query".parse().unwrap();
    assert!(matches!(protocol, DnsProtocol::Https { .. }));
}

#[test]
fn test_parse_https_with_hostname() {
    let protocol: DnsProtocol = "https://dns.google/dns-query".parse().unwrap();
    if let DnsProtocol::Https { url, hostname } = protocol {
        assert_eq!(&*url, "https://dns.google/dns-query");
        assert_eq!(&*hostname, "dns.google");
    } else {
        panic!("Expected Https variant");
    }
}

#[test]
fn test_parse_doq_with_ip() {
    let protocol: DnsProtocol = "doq://1.1.1.1:853".parse().unwrap();
    if let DnsProtocol::Quic { addr, hostname } = protocol {
        assert_eq!(addr.port(), 853);
        assert_eq!(&*hostname, "1.1.1.1");
    } else {
        panic!("Expected Quic variant");
    }
}

#[test]
fn test_parse_doq_with_hostname() {
    let protocol: DnsProtocol = "doq://dns.cloudflare.com:853".parse().unwrap();
    if let DnsProtocol::Quic { addr, hostname } = protocol {
        assert_eq!(addr.port(), 853);
        assert_eq!(&*hostname, "dns.cloudflare.com");
    } else {
        panic!("Expected Quic variant");
    }
}

#[test]
fn test_display_doq() {
    let protocol: DnsProtocol = "doq://dns.cloudflare.com:853".parse().unwrap();
    let displayed = format!("{}", protocol);
    assert!(displayed.starts_with("doq://"));
    assert!(displayed.contains("dns.cloudflare.com"));
    assert!(displayed.contains("853"));
}

#[test]
fn test_protocol_name() {
    let udp: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    assert_eq!(udp.protocol_name(), "UDP");

    let tcp: DnsProtocol = "tcp://8.8.8.8:53".parse().unwrap();
    assert_eq!(tcp.protocol_name(), "TCP");

    let tls: DnsProtocol = "tls://1.1.1.1:853".parse().unwrap();
    assert_eq!(tls.protocol_name(), "TLS");

    let https: DnsProtocol = "https://1.1.1.1/dns-query".parse().unwrap();
    assert_eq!(https.protocol_name(), "HTTPS");

    let quic: DnsProtocol = "doq://1.1.1.1:853".parse().unwrap();
    assert_eq!(quic.protocol_name(), "QUIC");

    let h3: DnsProtocol = "h3://1.1.1.1/dns-query".parse().unwrap();
    assert_eq!(h3.protocol_name(), "H3");
}

#[test]
fn test_socket_addr_extraction() {
    let udp: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    assert!(udp.socket_addr().is_some());

    let tls: DnsProtocol = "tls://1.1.1.1:853".parse().unwrap();
    assert!(tls.socket_addr().is_some());

    let https: DnsProtocol = "https://1.1.1.1/dns-query".parse().unwrap();
    assert!(https.socket_addr().is_none());

    let quic: DnsProtocol = "doq://1.1.1.1:853".parse().unwrap();
    assert!(quic.socket_addr().is_some());

    let h3: DnsProtocol = "h3://1.1.1.1/dns-query".parse().unwrap();
    assert!(h3.socket_addr().is_none());
}

#[test]
fn test_hostname_extraction() {
    let tls: DnsProtocol = "tls://dns.google:853".parse().unwrap();
    assert_eq!(tls.hostname(), Some("dns.google"));

    let https: DnsProtocol = "https://dns.google/dns-query".parse().unwrap();
    assert_eq!(https.hostname(), Some("dns.google"));

    let udp: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    assert_eq!(udp.hostname(), None);

    let quic: DnsProtocol = "doq://dns.cloudflare.com:853".parse().unwrap();
    assert_eq!(quic.hostname(), Some("dns.cloudflare.com"));

    let h3: DnsProtocol = "h3://dns.google/dns-query".parse().unwrap();
    assert_eq!(h3.hostname(), Some("dns.google"));
}

#[test]
fn test_url_extraction() {
    let https: DnsProtocol = "https://1.1.1.1/dns-query".parse().unwrap();
    assert_eq!(https.url(), Some("https://1.1.1.1/dns-query"));

    let h3: DnsProtocol = "h3://1.1.1.1/dns-query".parse().unwrap();
    assert_eq!(h3.url(), Some("h3://1.1.1.1/dns-query"));

    let udp: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    assert_eq!(udp.url(), None);
}

#[test]
fn test_display_formatting() {
    let udp: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    assert_eq!(format!("{}", udp), "udp://8.8.8.8:53");

    let tls: DnsProtocol = "tls://dns.google:853".parse().unwrap();
    assert!(format!("{}", tls).contains("tls://"));
    assert!(format!("{}", tls).contains("dns.google"));

    let https: DnsProtocol = "https://dns.google/dns-query".parse().unwrap();
    assert_eq!(format!("{}", https), "https://dns.google/dns-query");
}

#[test]
fn test_parse_h3() {
    let protocol: DnsProtocol = "h3://1.1.1.1/dns-query".parse().unwrap();
    assert!(matches!(protocol, DnsProtocol::H3 { .. }));
}

#[test]
fn test_parse_h3_with_hostname() {
    let protocol: DnsProtocol = "h3://dns.google/dns-query".parse().unwrap();
    if let DnsProtocol::H3 { url, hostname } = protocol {
        assert_eq!(&*url, "h3://dns.google/dns-query");
        assert_eq!(&*hostname, "dns.google");
    } else {
        panic!("Expected H3 variant");
    }
}

#[test]
fn test_display_h3() {
    let protocol: DnsProtocol = "h3://dns.google/dns-query".parse().unwrap();
    assert_eq!(format!("{}", protocol), "h3://dns.google/dns-query");
}

#[test]
fn test_invalid_protocol_parsing() {
    assert!("invalid://8.8.8.8:53".parse::<DnsProtocol>().is_err());
    assert!("not-a-protocol".parse::<DnsProtocol>().is_err());
    assert!("".parse::<DnsProtocol>().is_err());
}

#[test]
fn test_protocol_equality() {
    let udp1: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    let udp2: DnsProtocol = "8.8.8.8:53".parse().unwrap();
    assert_eq!(udp1, udp2);
}

#[test]
fn test_ipv6_parsing() {
    let protocol: DnsProtocol = "udp://[2001:4860:4860::8888]:53".parse().unwrap();
    assert!(matches!(protocol, DnsProtocol::Udp { .. }));
    if let Some(addr) = protocol.socket_addr() {
        assert!(addr.is_ipv6());
    }
}
