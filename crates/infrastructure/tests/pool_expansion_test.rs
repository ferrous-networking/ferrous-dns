use ferrous_dns_domain::{DnsProtocol, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_pool_manager_expands_hostnames() {
    let pool = UpstreamPool {
        name: "test-expansion".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://dns.google:53".into()],
        weight: None,
        ..Default::default()
    };

    let pm = PoolManager::new(vec![pool], None)
        .await
        .expect("PoolManager should create successfully");

    let protocols = pm.get_all_arc_protocols();
    assert!(
        protocols.len() >= 2,
        "dns.google hostname should expand to at least 2 resolved IPs, got {}",
        protocols.len()
    );

    for protocol in &protocols {
        assert!(
            !protocol.needs_resolution(),
            "All expanded protocols should be resolved, but found unresolved: {}",
            protocol
        );
        assert!(
            protocol.socket_addr().is_some(),
            "Each expanded protocol should have a concrete SocketAddr"
        );
    }
}

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_pool_manager_expansion_includes_ipv6() {
    let pool = UpstreamPool {
        name: "test-v6".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://dns.google:53".into()],
        weight: None,
        ..Default::default()
    };

    let pm = PoolManager::new(vec![pool], None)
        .await
        .expect("PoolManager should create successfully");

    let protocols = pm.get_all_arc_protocols();
    let has_v6 = protocols
        .iter()
        .any(|p| p.socket_addr().is_some_and(|a| a.is_ipv6()));

    assert!(
        has_v6,
        "Expanded protocols should include IPv6 addresses: {:?}",
        protocols.iter().map(|p| p.to_string()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_pool_manager_keeps_literal_ips_unchanged() {
    let pool = UpstreamPool {
        name: "test-literal".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://8.8.8.8:53".into(), "udp://1.1.1.1:53".into()],
        weight: None,
        ..Default::default()
    };

    let pm = PoolManager::new(vec![pool], None)
        .await
        .expect("PoolManager should create successfully");

    let protocols = pm.get_all_arc_protocols();
    assert_eq!(
        protocols.len(),
        2,
        "Literal IPs should not be expanded, got {} protocols",
        protocols.len()
    );
}

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_pool_manager_mixed_literal_and_hostname() {
    let pool = UpstreamPool {
        name: "test-mixed".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["udp://8.8.8.8:53".into(), "udp://dns.google:53".into()],
        weight: None,
        ..Default::default()
    };

    let pm = PoolManager::new(vec![pool], None)
        .await
        .expect("PoolManager should create successfully");

    let protocols = pm.get_all_arc_protocols();
    assert!(
        protocols.len() >= 3,
        "1 literal + expanded dns.google should give at least 3 protocols, got {}",
        protocols.len()
    );

    let has_8888 = protocols.iter().any(|p| {
        p.socket_addr()
            .is_some_and(|a| a.to_string() == "8.8.8.8:53")
    });
    assert!(has_8888, "Literal 8.8.8.8:53 should be preserved");
}

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_pool_manager_tls_hostname_expansion() {
    let pool = UpstreamPool {
        name: "test-tls".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["tls://dns.google:853".into()],
        weight: None,
        ..Default::default()
    };

    let pm = PoolManager::new(vec![pool], None)
        .await
        .expect("PoolManager should create successfully");

    let protocols = pm.get_all_arc_protocols();
    assert!(
        protocols.len() >= 2,
        "TLS dns.google should expand to at least 2 resolved IPs, got {}",
        protocols.len()
    );

    for protocol in &protocols {
        match protocol.as_ref() {
            DnsProtocol::Tls { addr, hostname } => {
                assert!(addr.socket_addr().is_some(), "TLS addr should be resolved");
                assert_eq!(
                    hostname.as_ref(),
                    "dns.google",
                    "TLS hostname should be preserved after expansion"
                );
            }
            other => panic!("Expected TLS protocol, got: {}", other),
        }
    }
}

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_pool_manager_https_not_expanded_but_preresolved() {
    let pool = UpstreamPool {
        name: "test-https".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["https://dns.google/dns-query".into()],
        weight: None,
        ..Default::default()
    };

    let pm = PoolManager::new(vec![pool], None)
        .await
        .expect("PoolManager should create successfully");

    let protocols = pm.get_all_arc_protocols();
    assert_eq!(
        protocols.len(),
        1,
        "HTTPS protocols should remain as 1 entry (not expanded like UDP/TCP)"
    );

    if let DnsProtocol::Https { resolved_addrs, .. } = protocols[0].as_ref() {
        assert!(
            !resolved_addrs.is_empty(),
            "HTTPS with hostname should have pre-resolved addresses"
        );
    } else {
        panic!("Expected Https variant, got: {}", protocols[0]);
    }
}

#[tokio::test]
#[ignore = "live network: resolves dns.google; run with --ignored"]
async fn test_pool_manager_preresolves_h3_hostnames() {
    let pool = UpstreamPool {
        name: "test-h3".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["h3://dns.google/dns-query".into()],
        weight: None,
        ..Default::default()
    };

    let pm = PoolManager::new(vec![pool], None)
        .await
        .expect("PoolManager should create successfully");

    let protocols = pm.get_all_arc_protocols();
    assert_eq!(
        protocols.len(),
        1,
        "H3 protocols should remain as 1 entry (not expanded like UDP/TCP)"
    );

    if let DnsProtocol::H3 { resolved_addrs, .. } = protocols[0].as_ref() {
        assert!(
            !resolved_addrs.is_empty(),
            "H3 with hostname should have pre-resolved addresses"
        );
    } else {
        panic!("Expected H3 variant, got: {}", protocols[0]);
    }
}

#[tokio::test]
async fn test_pool_manager_https_ip_no_resolution() {
    for server in ["https://1.1.1.1/dns-query", "https://[::1]:8443/dns-query"] {
        let pool = UpstreamPool {
            name: "test-https-ip".into(),
            strategy: UpstreamStrategy::Parallel,
            priority: 1,
            servers: vec![server.into()],
            weight: None,
            ..Default::default()
        };

        let pm = PoolManager::new(vec![pool], None)
            .await
            .expect("PoolManager should create successfully");

        let protocols = pm.get_all_arc_protocols();
        assert_eq!(protocols.len(), 1);

        if let DnsProtocol::Https { resolved_addrs, .. } = protocols[0].as_ref() {
            assert!(
                resolved_addrs.is_empty(),
                "{server}: HTTPS with IP literal should have empty resolved_addrs"
            );
        } else {
            panic!("Expected Https variant, got: {}", protocols[0]);
        }
    }
}
