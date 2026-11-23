//! A server this host has no route to, as an IPv6 address in a container
//! without IPv6 (#402), is left out at once and sent nothing. When the route
//! comes back, the server starts over as a new one would.

#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_domain::DnsProtocol;
use ferrous_dns_infrastructure::dns::load_balancer::{HealthChecker, ServerHealth, ServerStatus};
use ferrous_dns_infrastructure::dns::transport::route::has_route;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use upstream::{Answer, Upstream};

const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// Probes every server once a second, with a failure threshold of 3, so a
/// no-route verdict taken on the first check cannot come from failures.
fn run_checker(checker: &Arc<HealthChecker>, protocols: Vec<Arc<DnsProtocol>>) {
    let checker = Arc::clone(checker);
    tokio::spawn(async move {
        checker.run(move || protocols.clone(), 1, 300).await;
    });
}

/// The server's health once `ready` holds, or a failure naming `what`.
async fn wait_for(
    checker: &HealthChecker,
    protocol: &Arc<DnsProtocol>,
    what: &str,
    ready: impl Fn(&ServerHealth) -> bool,
) -> ServerHealth {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(health) = checker.get_health_info(protocol).filter(|h| ready(h)) {
            return health;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{protocol} never got {what}: {:?}",
            checker.get_health_info(protocol)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn h3(addrs: &[&str]) -> Arc<DnsProtocol> {
    let protocol: DnsProtocol = "h3://dns.example/dns-query".parse().unwrap();
    Arc::new(protocol.with_resolved_addrs(addrs.iter().map(|a| a.parse().unwrap()).collect()))
}

#[tokio::test]
async fn a_server_without_a_route_is_left_out_at_once_and_sent_nothing() {
    let upstream = Upstream::spawn(Answer::Address(ANSWER_IP)).await;
    let protocol: Arc<DnsProtocol> = Arc::new(upstream.url().parse().unwrap());
    let address = protocol.addresses()[0];
    let checker = Arc::new(HealthChecker::new(3, 1).with_route_probe(Arc::new(|_| false)));
    run_checker(&checker, vec![Arc::clone(&protocol)]);

    let health = wait_for(&checker, &protocol, "no route", |h| {
        h.status == ServerStatus::NoRoute
    })
    .await;

    assert!(!checker.is_healthy(&protocol));
    assert_eq!(health.unroutable, vec![address]);
    assert_eq!(
        health.last_error.as_deref(),
        Some(format!("No route from this host to {address}").as_str())
    );
    assert_eq!(health.consecutive_failures, 0);
    // One more tick: still nothing sent.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(upstream.queries(), 0);
    assert_eq!(checker.get_status(&protocol), ServerStatus::NoRoute);
}

#[tokio::test]
async fn a_server_whose_route_comes_back_is_checked_and_turns_healthy() {
    let upstream = Upstream::spawn(Answer::Address(ANSWER_IP)).await;
    let protocol: Arc<DnsProtocol> = Arc::new(upstream.url().parse().unwrap());
    let routed = Arc::new(AtomicBool::new(false));
    let probe_routed = Arc::clone(&routed);
    let checker = Arc::new(
        HealthChecker::new(3, 1)
            .with_route_probe(Arc::new(move |_| probe_routed.load(Ordering::SeqCst))),
    );
    run_checker(&checker, vec![Arc::clone(&protocol)]);
    wait_for(&checker, &protocol, "no route", |h| {
        h.status == ServerStatus::NoRoute
    })
    .await;

    routed.store(true, Ordering::SeqCst);
    let health = wait_for(&checker, &protocol, "healthy", |h| {
        h.status == ServerStatus::Healthy
    })
    .await;

    assert!(health.unroutable.is_empty());
    assert!(health.last_error.is_none());
    assert!(upstream.queries() > 0);
    assert!(checker.is_healthy(&protocol));
}

#[tokio::test]
async fn an_h3_server_with_some_routable_addresses_is_still_probed() {
    let protocol = h3(&["127.0.0.1:9", "[2001:db8::1]:443"]);
    let checker = Arc::new(
        HealthChecker::new(3, 1).with_route_probe(Arc::new(|addr: SocketAddr| addr.is_ipv4())),
    );
    run_checker(&checker, vec![Arc::clone(&protocol)]);

    let health = wait_for(&checker, &protocol, "a check", |h| !h.unroutable.is_empty()).await;

    assert_eq!(
        health.unroutable,
        vec!["[2001:db8::1]:443".parse::<SocketAddr>().unwrap()]
    );
    assert_ne!(health.status, ServerStatus::NoRoute);
}

#[tokio::test]
async fn an_h3_server_with_no_routable_address_is_left_out() {
    let protocol = h3(&["[2001:db8::1]:443", "[2001:db8::2]:443"]);
    let checker = Arc::new(
        HealthChecker::new(3, 1).with_route_probe(Arc::new(|addr: SocketAddr| addr.is_ipv4())),
    );
    run_checker(&checker, vec![Arc::clone(&protocol)]);

    let health = wait_for(&checker, &protocol, "no route", |h| {
        h.status == ServerStatus::NoRoute
    })
    .await;

    assert_eq!(
        health.last_error.as_deref(),
        Some("No route from this host to [2001:db8::1]:443, [2001:db8::2]:443")
    );
}

#[test]
fn the_route_probe_finds_the_loopback() {
    assert!(has_route(SocketAddr::from((Ipv4Addr::LOCALHOST, 53))));
    // ::1 exists only where this host has IPv6 on its loopback.
    if UdpSocket::bind("[::1]:0").is_ok() {
        assert!(has_route("[::1]:53".parse().unwrap()));
    }
}
