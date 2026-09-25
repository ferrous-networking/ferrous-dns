use ferrous_dns_domain::{DnsProtocol, DomainError, UpstreamAddr};

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
    if let DnsProtocol::Https {
        url,
        hostname,
        port,
        resolved_addrs,
    } = protocol
    {
        assert_eq!(&*url, "https://dns.google/dns-query");
        assert_eq!(&*hostname, "dns.google");
        assert_eq!(port, 443);
        assert!(resolved_addrs.is_empty());
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
    if let DnsProtocol::H3 {
        url,
        hostname,
        port,
        resolved_addrs,
    } = protocol
    {
        assert_eq!(&*url, "h3://dns.google/dns-query");
        assert_eq!(&*hostname, "dns.google");
        assert_eq!(port, 443);
        assert!(resolved_addrs.is_empty());
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

#[test]
fn test_parse_udp_hostname() {
    let protocol: DnsProtocol = "udp://dns.google:53".parse().unwrap();
    if let DnsProtocol::Udp { addr } = &protocol {
        assert!(addr.is_unresolved());
        assert_eq!(addr.unresolved_parts(), Some(("dns.google", 53)));
        assert_eq!(addr.port(), 53);
        assert!(addr.socket_addr().is_none());
    } else {
        panic!("Expected Udp variant");
    }
}

#[test]
fn test_parse_tcp_hostname() {
    let protocol: DnsProtocol = "tcp://dns.google:53".parse().unwrap();
    if let DnsProtocol::Tcp { addr } = &protocol {
        assert!(addr.is_unresolved());
        assert_eq!(addr.unresolved_parts(), Some(("dns.google", 53)));
        assert_eq!(addr.port(), 53);
    } else {
        panic!("Expected Tcp variant");
    }
}

#[test]
fn test_parse_tls_hostname_no_placeholder() {
    let protocol: DnsProtocol = "tls://dns.google:853".parse().unwrap();
    assert!(
        protocol.socket_addr().is_none(),
        "TLS with hostname should not have a placeholder IP"
    );
    assert!(protocol.needs_resolution());
}

#[test]
fn test_parse_doq_hostname_no_placeholder() {
    let protocol: DnsProtocol = "doq://dns.cloudflare.com:853".parse().unwrap();
    assert!(
        protocol.socket_addr().is_none(),
        "DoQ with hostname should not have a placeholder IP"
    );
    assert!(protocol.needs_resolution());
}

#[test]
fn test_parse_udp_ipv6() {
    let protocol: DnsProtocol = "udp://[2001:4860:4860::8888]:53".parse().unwrap();
    if let DnsProtocol::Udp { addr } = &protocol {
        assert!(!addr.is_unresolved());
        let sa = addr.socket_addr().unwrap();
        assert!(sa.is_ipv6());
        assert_eq!(sa.port(), 53);
    } else {
        panic!("Expected Udp variant");
    }
}

#[test]
fn test_parse_tcp_ipv6() {
    let protocol: DnsProtocol = "tcp://[2606:4700:4700::1111]:53".parse().unwrap();
    if let DnsProtocol::Tcp { addr } = &protocol {
        let sa = addr.socket_addr().unwrap();
        assert!(sa.is_ipv6());
        assert_eq!(sa.port(), 53);
    } else {
        panic!("Expected Tcp variant");
    }
}

#[test]
fn test_parse_doq_ipv6() {
    let protocol: DnsProtocol = "doq://[2606:4700:4700::1111]:853".parse().unwrap();
    if let DnsProtocol::Quic { addr, .. } = &protocol {
        let sa = addr.socket_addr().unwrap();
        assert!(sa.is_ipv6());
        assert_eq!(sa.port(), 853);
    } else {
        panic!("Expected Quic variant");
    }
}

#[test]
fn ipv6_literal_tls_and_doq_use_the_bare_ip_as_hostname_and_round_trip() {
    for s in [
        "doq://[2606:4700:4700::1111]:853",
        "tls://[2606:4700:4700::1111]:853",
    ] {
        let protocol: DnsProtocol = s.parse().unwrap();
        assert_eq!(protocol.hostname(), Some("2606:4700:4700::1111"));
        assert_eq!(protocol.to_string(), s);
        assert_eq!(
            protocol.to_string().parse::<DnsProtocol>().unwrap(),
            protocol
        );
    }
}

#[test]
fn test_with_resolved_addr_udp() {
    let protocol: DnsProtocol = "udp://dns.google:53".parse().unwrap();
    let resolved_addr: std::net::SocketAddr = "8.8.8.8:53".parse().unwrap();
    let resolved = protocol.with_resolved_addr(resolved_addr);

    if let DnsProtocol::Udp { addr } = &resolved {
        assert_eq!(addr.socket_addr(), Some(resolved_addr));
        assert!(!addr.is_unresolved());
    } else {
        panic!("Expected Udp variant");
    }
}

#[test]
fn test_with_resolved_addr_tls() {
    let protocol: DnsProtocol = "tls://dns.google:853".parse().unwrap();
    let resolved_addr: std::net::SocketAddr = "8.8.8.8:853".parse().unwrap();
    let resolved = protocol.with_resolved_addr(resolved_addr);

    if let DnsProtocol::Tls { addr, hostname } = &resolved {
        assert_eq!(addr.socket_addr(), Some(resolved_addr));
        assert_eq!(&**hostname, "dns.google");
    } else {
        panic!("Expected Tls variant");
    }
}

#[test]
fn test_with_resolved_addr_quic() {
    let protocol: DnsProtocol = "doq://dns.cloudflare.com:853".parse().unwrap();
    let resolved_addr: std::net::SocketAddr = "1.1.1.1:853".parse().unwrap();
    let resolved = protocol.with_resolved_addr(resolved_addr);

    if let DnsProtocol::Quic { addr, hostname } = &resolved {
        assert_eq!(addr.socket_addr(), Some(resolved_addr));
        assert_eq!(&**hostname, "dns.cloudflare.com");
    } else {
        panic!("Expected Quic variant");
    }
}

#[test]
fn test_with_resolved_addr_https_returns_clone() {
    let protocol: DnsProtocol = "https://dns.google/dns-query".parse().unwrap();
    let resolved_addr: std::net::SocketAddr = "8.8.8.8:443".parse().unwrap();
    let resolved = protocol.with_resolved_addr(resolved_addr);
    assert_eq!(protocol, resolved);
}

#[test]
fn test_needs_resolution_unresolved() {
    let udp: DnsProtocol = "udp://dns.google:53".parse().unwrap();
    assert!(udp.needs_resolution());

    let tcp: DnsProtocol = "tcp://dns.google:53".parse().unwrap();
    assert!(tcp.needs_resolution());

    let tls: DnsProtocol = "tls://dns.google:853".parse().unwrap();
    assert!(tls.needs_resolution());

    let quic: DnsProtocol = "doq://dns.cloudflare.com:853".parse().unwrap();
    assert!(quic.needs_resolution());
}

#[test]
fn test_needs_resolution_resolved() {
    let udp: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    assert!(!udp.needs_resolution());

    let tcp: DnsProtocol = "tcp://1.1.1.1:53".parse().unwrap();
    assert!(!tcp.needs_resolution());

    let tls: DnsProtocol = "tls://1.1.1.1:853".parse().unwrap();
    assert!(!tls.needs_resolution());

    let https_ip: DnsProtocol = "https://1.1.1.1/dns-query".parse().unwrap();
    assert!(!https_ip.needs_resolution());

    let h3_ip: DnsProtocol = "h3://1.1.1.1/dns-query".parse().unwrap();
    assert!(!h3_ip.needs_resolution());
}

#[test]
fn test_upstream_addr_display() {
    let resolved = UpstreamAddr::Resolved("8.8.8.8:53".parse().unwrap());
    assert_eq!(format!("{}", resolved), "8.8.8.8:53");

    let unresolved = UpstreamAddr::Unresolved {
        hostname: "dns.google".into(),
        port: 53,
    };
    assert_eq!(format!("{}", unresolved), "dns.google:53");
}

#[test]
fn test_upstream_addr_unresolved_parts() {
    let unresolved = UpstreamAddr::Unresolved {
        hostname: "dns.google".into(),
        port: 53,
    };
    let (host, port) = unresolved.unresolved_parts().unwrap();
    assert_eq!(host, "dns.google");
    assert_eq!(port, 53);

    let resolved = UpstreamAddr::Resolved("8.8.8.8:53".parse().unwrap());
    assert!(resolved.unresolved_parts().is_none());
}

#[test]
fn test_with_resolved_addr_ipv6() {
    let protocol: DnsProtocol = "udp://dns.google:53".parse().unwrap();
    let ipv6_addr: std::net::SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
    let resolved = protocol.with_resolved_addr(ipv6_addr);

    assert!(!resolved.needs_resolution());
    let sa = resolved.socket_addr().unwrap();
    assert!(sa.is_ipv6());
    assert_eq!(format!("{}", resolved), "udp://[2001:4860:4860::8888]:53");
}

#[test]
fn test_parse_https_starts_with_empty_resolved_addrs() {
    let protocol: DnsProtocol = "https://cloudflare-dns.com/dns-query".parse().unwrap();
    if let DnsProtocol::Https { resolved_addrs, .. } = &protocol {
        assert!(resolved_addrs.is_empty());
    } else {
        panic!("Expected Https variant");
    }
}

#[test]
fn test_parse_h3_starts_with_empty_resolved_addrs() {
    let protocol: DnsProtocol = "h3://dns.google/dns-query".parse().unwrap();
    if let DnsProtocol::H3 { resolved_addrs, .. } = &protocol {
        assert!(resolved_addrs.is_empty());
    } else {
        panic!("Expected H3 variant");
    }
}

#[test]
fn test_https_with_resolved_addrs() {
    let protocol: DnsProtocol = "https://cloudflare-dns.com/dns-query".parse().unwrap();
    let addrs: Vec<std::net::SocketAddr> = vec![
        "104.16.248.249:443".parse().unwrap(),
        "104.16.249.249:443".parse().unwrap(),
    ];
    let resolved = protocol.with_resolved_addrs(addrs.clone());
    if let DnsProtocol::Https { resolved_addrs, .. } = &resolved {
        assert_eq!(resolved_addrs, &addrs);
    } else {
        panic!("Expected Https variant");
    }
}

#[test]
fn test_h3_with_resolved_addrs() {
    let protocol: DnsProtocol = "h3://dns.google/dns-query".parse().unwrap();
    let addrs: Vec<std::net::SocketAddr> = vec![
        "8.8.8.8:443".parse().unwrap(),
        "8.8.4.4:443".parse().unwrap(),
    ];
    let resolved = protocol.with_resolved_addrs(addrs.clone());
    if let DnsProtocol::H3 { resolved_addrs, .. } = &resolved {
        assert_eq!(resolved_addrs, &addrs);
    } else {
        panic!("Expected H3 variant");
    }
}

#[test]
fn test_https_needs_resolution_empty_addrs() {
    let protocol: DnsProtocol = "https://cloudflare-dns.com/dns-query".parse().unwrap();
    assert!(
        protocol.needs_resolution(),
        "HTTPS with hostname and empty resolved_addrs should need resolution"
    );
}

#[test]
fn test_https_needs_resolution_with_addrs() {
    let protocol: DnsProtocol = "https://cloudflare-dns.com/dns-query".parse().unwrap();
    let resolved = protocol.with_resolved_addrs(vec!["104.16.248.249:443".parse().unwrap()]);
    assert!(
        !resolved.needs_resolution(),
        "HTTPS with resolved_addrs should not need resolution"
    );
}

#[test]
fn test_h3_needs_resolution_empty_addrs() {
    let protocol: DnsProtocol = "h3://dns.google/dns-query".parse().unwrap();
    assert!(
        protocol.needs_resolution(),
        "H3 with hostname and empty resolved_addrs should need resolution"
    );
}

#[test]
fn test_h3_needs_resolution_with_addrs() {
    let protocol: DnsProtocol = "h3://dns.google/dns-query".parse().unwrap();
    let resolved = protocol.with_resolved_addrs(vec!["8.8.8.8:443".parse().unwrap()]);
    assert!(
        !resolved.needs_resolution(),
        "H3 with resolved_addrs should not need resolution"
    );
}

#[test]
fn test_https_ip_url_needs_no_resolution() {
    let protocol: DnsProtocol = "https://1.1.1.1/dns-query".parse().unwrap();
    assert!(
        !protocol.needs_resolution(),
        "HTTPS with IP literal should not need resolution"
    );
}

#[test]
fn test_h3_ip_url_needs_no_resolution() {
    let protocol: DnsProtocol = "h3://1.1.1.1/dns-query".parse().unwrap();
    assert!(
        !protocol.needs_resolution(),
        "H3 with IP literal should not need resolution"
    );
}

#[test]
fn https_and_h3_urls_split_into_bare_host_and_port() {
    let cases = [
        (
            "https://[2606:4700::1111]/dns-query",
            "2606:4700::1111",
            443,
        ),
        ("https://[::1]:8443/dns-query", "::1", 8443),
        ("h3://[::1]:8443/dns-query", "::1", 8443),
        ("https://dns.example:8443/dns-query", "dns.example", 8443),
        ("h3://dns.example?dns=AAAB", "dns.example", 443),
    ];
    for (url, expected_host, expected_port) in cases {
        let protocol: DnsProtocol = url.parse().unwrap();
        let (DnsProtocol::Https { hostname, port, .. } | DnsProtocol::H3 { hostname, port, .. }) =
            &protocol
        else {
            panic!("{url}: expected an HTTPS or H3 variant");
        };
        assert_eq!(
            (&**hostname, *port),
            (expected_host, expected_port),
            "{url}"
        );
        assert_eq!(protocol.to_string(), url);
    }
}

#[test]
fn https_and_h3_ipv6_literals_need_no_resolution() {
    for url in [
        "https://[2606:4700::1111]/dns-query",
        "https://[::1]:8443/dns-query",
        "h3://[::1]:8443/dns-query",
    ] {
        let protocol: DnsProtocol = url.parse().unwrap();
        assert!(!protocol.needs_resolution(), "{url}");
    }
}

#[test]
fn malformed_https_and_h3_authorities_are_rejected() {
    for url in [
        "https://2606:4700::1111/dns-query",
        "https://[2606:4700::1111/dns-query",
        "https://[dns.example]/dns-query",
        "https://[::1]x/dns-query",
        "https://dns.example:notaport/dns-query",
        "https://dns.example:70000/dns-query",
        "https:///dns-query",
        "h3://:443/dns-query",
    ] {
        assert!(url.parse::<DnsProtocol>().is_err(), "{url}");
    }
}

fn rejection_message(input: &str) -> String {
    match input.parse::<DnsProtocol>() {
        Err(DomainError::ConfigError(msg)) => msg,
        other => format!("not a ConfigError rejection: {other:?}"),
    }
}

#[test]
fn rejected_upstreams_explain_how_to_write_them() {
    let scheme_list = "use udp://, tcp://, tls://, doq://, https:// or h3://";
    let cases = [
        (
            "quic://abc.d.adguard-dns.com",
            "'quic://' is not a supported scheme — write DNS-over-QUIC as doq://abc.d.adguard-dns.com:853".to_string(),
        ),
        (
            "quic://abc.d.adguard-dns.com/",
            "'quic://' is not a supported scheme — write DNS-over-QUIC as doq://abc.d.adguard-dns.com:853".to_string(),
        ),
        (
            "quic://dns.adguard-dns.com:853",
            "'quic://' is not a supported scheme — write DNS-over-QUIC as doq://dns.adguard-dns.com:853".to_string(),
        ),
        ("foo://dns.google:53", format!("unknown scheme 'foo://' — {scheme_list}")),
        ("DOQ://dns.adguard-dns.com:853", format!("unknown scheme 'DOQ://' — {scheme_list}")),
        (
            "doq://dns.adguard-dns.com",
            "missing port — DNS-over-QUIC usually uses 853, e.g. doq://dns.adguard-dns.com:853".to_string(),
        ),
        (
            "doq://[2a10:50c0::ad1:ff]",
            "missing port — DNS-over-QUIC usually uses 853, e.g. doq://[2a10:50c0::ad1:ff]:853".to_string(),
        ),
        (
            "tls://dns.google",
            "missing port — DNS-over-TLS usually uses 853, e.g. tls://dns.google:853".to_string(),
        ),
        (
            "udp://dns.google",
            "missing port — plain DNS usually uses 53, e.g. udp://dns.google:53".to_string(),
        ),
        (
            "tcp://8.8.8.8",
            "missing port — plain DNS usually uses 53, e.g. tcp://8.8.8.8:53".to_string(),
        ),
        (
            "8.8.8.8",
            "missing port — plain DNS usually uses 53, e.g. 8.8.8.8:53".to_string(),
        ),
        (
            "2001:4860:4860::8888",
            "missing port — plain DNS usually uses 53, e.g. [2001:4860:4860::8888]:53".to_string(),
        ),
        (
            "doq://dns.adguard-dns.com:99999",
            "invalid port '99999' — use a number from 0 to 65535".to_string(),
        ),
        (
            "https://dns.example:70000/dns-query",
            "invalid port '70000' — use a number from 0 to 65535".to_string(),
        ),
        ("doq://:853", "missing host".to_string()),
        ("tls://:853", "missing host".to_string()),
        ("udp://:53", "missing host".to_string()),
        ("tcp://:53", "missing host".to_string()),
        (
            "dns.google:53",
            "add a scheme, e.g. udp://dns.google:53 — only IP:PORT may omit it".to_string(),
        ),
        (
            "dns.google",
            "add a scheme, e.g. udp://dns.google:53 — only IP:PORT may omit it".to_string(),
        ),
        (
            "https://2606:4700::1111/dns-query",
            "IPv6 addresses must be in brackets, e.g. [2606:4700::1111]".to_string(),
        ),
        (
            "not a server",
            "unrecognized server address — use a URL such as doq://dns.adguard-dns.com:853 or IP:PORT such as 8.8.8.8:53".to_string(),
        ),
    ];
    let mismatches: Vec<String> = cases
        .into_iter()
        .filter_map(|(input, hint)| {
            let expected = format!("Invalid server '{input}': {hint}");
            let actual = rejection_message(input);
            (actual != expected).then(|| format!("{input}\n   got: {actual}\n  want: {expected}"))
        })
        .collect();
    assert!(mismatches.is_empty(), "\n{}", mismatches.join("\n"));
}

#[test]
fn upstream_forms_accepted_before_the_new_messages_still_parse() {
    for input in [
        "doq://dns.adguard-dns.com:853",
        "doq://94.140.14.14:853",
        "doq://[2a10:50c0::ad1:ff]:853",
        "tls://dns.google:853",
        "https://cloudflare-dns.com/dns-query",
        "h3://dns.google/dns-query",
        "8.8.8.8:53",
        "[2001:4860:4860::8888]:53",
        "udp://dns.google:53",
        "udp://2001:4860:4860::8888:53",
    ] {
        assert!(input.parse::<DnsProtocol>().is_ok(), "{input}");
    }
}

#[test]
fn test_with_resolved_addrs_on_non_https_h3_returns_clone() {
    let protocol: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
    let resolved = protocol.with_resolved_addrs(vec!["1.1.1.1:53".parse().unwrap()]);
    assert_eq!(protocol, resolved);
}
