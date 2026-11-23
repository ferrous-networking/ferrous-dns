//! What the dashboard shows for an upstream hostname with addresses this host
//! has no route to (#402): those rows read `no_route`, and the server's status
//! comes from the rest, so a container without IPv6 shows it Healthy instead
//! of Partial.

#[path = "support/router.rs"]
mod router;
#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::ports::{
    ResolvedEndpointHealth, UpstreamGroupHealth, UpstreamHealthPort,
};
use ferrous_dns_domain::UpstreamPool;
use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::load_balancer::{HealthChecker, RouteProbe};
use ferrous_dns_infrastructure::dns::transport::resolver::UpstreamHostResolver;
use ferrous_dns_infrastructure::dns::{PoolManager, UpstreamHealthAdapter};
use router::Router;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use upstream::{Answer, Upstream};

/// `.invalid` never resolves through the system resolver, so only the router
/// answers it.
const NAME: &str = "dual.invalid";
const IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

/// A pool whose one server is `udp://NAME:<upstream port>`, as the router
/// resolves it, health-checked with `probe` every second.
async fn adapter(router: &Router, upstream: &Upstream, probe: RouteProbe) -> UpstreamHealthAdapter {
    let port = upstream.url().rsplit(':').next().unwrap().to_string();
    let pool = UpstreamPool {
        name: "only".into(),
        servers: vec![format!("udp://{NAME}:{port}")],
        ..Default::default()
    };
    let checker = Arc::new(HealthChecker::new(1, 1).with_route_probe(probe));
    let host_resolver =
        UpstreamHostResolver::new(Some(router.spawn().await), HardeningOpts::default());
    let pm = Arc::new(
        PoolManager::with_host_resolver(vec![pool], Some(Arc::clone(&checker)), host_resolver)
            .await
            .unwrap(),
    );
    let probed = Arc::clone(&pm);
    let running = Arc::clone(&checker);
    tokio::spawn(async move {
        running
            .run(move || probed.get_all_arc_protocols(), 1, 300)
            .await;
    });
    UpstreamHealthAdapter::new(pm, Some(checker))
}

/// The server's group once every row has been checked.
async fn checked_group(adapter: &UpstreamHealthAdapter) -> UpstreamGroupHealth {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let group = adapter.get_grouped_upstream_health().remove(0);
        if group
            .resolved
            .iter()
            .all(|row| row.status.as_str() != "Unknown")
        {
            return group;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never checked: {group:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn ipv4_only() -> RouteProbe {
    Arc::new(|addr: SocketAddr| addr.is_ipv4())
}

fn row<'a>(group: &'a UpstreamGroupHealth, family: &str) -> &'a ResolvedEndpointHealth {
    group
        .resolved
        .iter()
        .find(|row| row.family.as_str() == family)
        .unwrap_or_else(|| panic!("no {family} row: {group:?}"))
}

#[tokio::test]
async fn addresses_without_a_route_are_labelled_and_left_out_of_the_status() {
    let upstream = Upstream::spawn(Answer::Address(Ipv4Addr::new(192, 0, 2, 1))).await;
    let router = Router::default();
    router.set(NAME, Ipv4Addr::LOCALHOST, 300);
    router.set_ipv6(NAME, &[IPV6], 300);

    let group = checked_group(&adapter(&router, &upstream, ipv4_only()).await).await;

    assert_eq!(group.resolved.len(), 2, "{group:?}");
    let ipv4 = row(&group, "ipv4");
    let ipv6 = row(&group, "ipv6");
    assert!(!ipv4.no_route, "{group:?}");
    assert_eq!(ipv4.status.as_str(), "Healthy");
    assert!(ipv6.no_route, "{group:?}");
    assert_eq!(ipv6.status.as_str(), "Unhealthy");
    assert_eq!(group.status.as_str(), "Healthy");
}

#[tokio::test]
async fn a_server_with_no_routable_address_is_unhealthy() {
    let upstream = Upstream::spawn(Answer::Address(Ipv4Addr::new(192, 0, 2, 1))).await;
    let router = Router::default();
    router.set_ipv6(NAME, &[IPV6], 300);

    let group = checked_group(&adapter(&router, &upstream, ipv4_only()).await).await;

    assert!(group.resolved.iter().all(|row| row.no_route), "{group:?}");
    assert_eq!(group.status.as_str(), "Unhealthy");
}

/// Guard: with a route to every address, a failing one still makes the
/// server Partial, as before. Nothing answers on the documentation prefix.
#[tokio::test]
async fn a_failing_address_with_a_route_still_makes_the_server_partial() {
    let upstream = Upstream::spawn(Answer::Address(Ipv4Addr::new(192, 0, 2, 1))).await;
    let router = Router::default();
    router.set(NAME, Ipv4Addr::LOCALHOST, 300);
    router.set_ipv6(NAME, &[IPV6], 300);

    let group = checked_group(&adapter(&router, &upstream, Arc::new(|_| true)).await).await;

    assert!(group.resolved.iter().all(|row| !row.no_route), "{group:?}");
    assert_eq!(row(&group, "ipv6").status.as_str(), "Unhealthy");
    assert_eq!(group.status.as_str(), "Partial");
}
