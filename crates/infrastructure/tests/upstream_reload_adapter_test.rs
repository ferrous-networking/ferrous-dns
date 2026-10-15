#[path = "support/refresh.rs"]
mod refresh;

use ferrous_dns_application::ports::UpstreamReloadPort;
use ferrous_dns_domain::{RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use ferrous_dns_infrastructure::dns::{DnsCache, UpstreamReloadAdapter};
use std::sync::Arc;

fn pool(server: &str) -> UpstreamPool {
    UpstreamPool {
        name: "p1".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![server.into()],
        weight: None,
        ..Default::default()
    }
}

async fn manager(server: &str) -> Arc<PoolManager> {
    Arc::new(
        PoolManager::new(vec![pool(server)], None)
            .await
            .expect("PoolManager should create"),
    )
}

fn servers(pm: &PoolManager) -> Vec<String> {
    pm.get_all_servers().iter().map(|a| a.to_string()).collect()
}

#[tokio::test]
async fn valid_reload_updates_both_managers() {
    let main = manager("udp://8.8.8.8:53").await;
    let dnssec = manager("udp://8.8.8.8:53").await;
    let adapter = UpstreamReloadAdapter::new(vec![main.clone(), dnssec.clone()]);

    adapter
        .reload_pools(vec![pool("udp://1.1.1.1:53")])
        .await
        .expect("valid reload should succeed");

    assert!(servers(&main).iter().any(|a| a == "1.1.1.1:53"));
    assert!(servers(&dnssec).iter().any(|a| a == "1.1.1.1:53"));
}

#[tokio::test]
async fn failed_reload_leaves_both_managers_untouched() {
    let main = manager("udp://8.8.8.8:53").await;
    let dnssec = manager("udp://8.8.8.8:53").await;
    let adapter = UpstreamReloadAdapter::new(vec![main.clone(), dnssec.clone()]);

    // An empty pool set fails to rebuild; neither manager may be swapped.
    assert!(
        adapter.reload_pools(Vec::new()).await.is_err(),
        "an invalid pool set must be rejected"
    );

    assert!(
        servers(&main).iter().any(|a| a == "8.8.8.8:53"),
        "main manager must keep its previous live pools after a rejected reload"
    );
    assert!(
        servers(&dnssec).iter().any(|a| a == "8.8.8.8:53"),
        "dnssec manager must keep its previous live pools after a rejected reload"
    );
}

// ── A reload that changes where a name is routed clears the DNS cache ──────

fn conditional(server: &str, domains: &[&str], groups: &[i64]) -> UpstreamPool {
    UpstreamPool {
        name: "office".into(),
        servers: vec![server.into()],
        domains: domains.iter().map(|d| d.to_string()).collect(),
        groups: groups.to_vec(),
        internal: true,
        ..Default::default()
    }
}

/// A cache holding one upstream answer and one local record.
fn filled_cache() -> Arc<DnsCache> {
    let cache = refresh::refresh_cache(100, 0.75, 7_200);
    cache.insert(
        "host.corp.example",
        RecordType::A,
        refresh::address("192.0.2.1"),
        300,
        None,
    );
    cache.insert_permanent("nas.lan", RecordType::A, refresh::address("10.0.0.5"), 300);
    cache
}

fn holds_upstream_answer(cache: &Arc<DnsCache>) -> bool {
    refresh::cached_addresses(cache, "host.corp.example").is_some()
}

async fn reload_with_cache(before: Vec<UpstreamPool>, after: Vec<UpstreamPool>) -> Arc<DnsCache> {
    let main = Arc::new(PoolManager::new(before, None).await.unwrap());
    let cache = filled_cache();
    let adapter = UpstreamReloadAdapter::new(vec![main]).with_cache(Arc::clone(&cache));
    adapter.reload_pools(after).await.expect("valid reload");
    cache
}

#[tokio::test]
async fn adding_a_route_clears_the_cache_but_keeps_local_records() {
    let cache = reload_with_cache(
        vec![pool("udp://8.8.8.8:53")],
        vec![
            pool("udp://8.8.8.8:53"),
            conditional("udp://10.0.0.10:53", &["corp.example"], &[]),
        ],
    )
    .await;

    assert!(
        !holds_upstream_answer(&cache),
        "answers from before the route must go"
    );
    assert!(cache.is_permanent("nas.lan", &RecordType::A));
}

#[tokio::test]
async fn changing_who_a_route_serves_clears_the_cache() {
    let cache = reload_with_cache(
        vec![
            pool("udp://8.8.8.8:53"),
            conditional("udp://10.0.0.10:53", &["corp.example"], &[3]),
        ],
        vec![
            pool("udp://8.8.8.8:53"),
            conditional("udp://10.0.0.10:53", &["corp.example"], &[4]),
        ],
    )
    .await;

    assert!(!holds_upstream_answer(&cache));
}

#[tokio::test]
async fn changing_only_servers_keeps_the_cache() {
    let cache = reload_with_cache(
        vec![
            pool("udp://8.8.8.8:53"),
            conditional("udp://10.0.0.10:53", &["corp.example"], &[3]),
        ],
        vec![
            pool("udp://1.1.1.1:53"),
            conditional("udp://10.0.0.11:53", &["Corp.Example."], &[3]),
        ],
    )
    .await;

    assert!(
        holds_upstream_answer(&cache),
        "no name is routed differently"
    );
}

#[tokio::test]
async fn failed_reload_keeps_the_cache() {
    let main = manager("udp://8.8.8.8:53").await;
    let cache = filled_cache();
    let adapter = UpstreamReloadAdapter::new(vec![main]).with_cache(Arc::clone(&cache));

    assert!(adapter
        .reload_pools(vec![conditional(
            "udp://10.0.0.10:53",
            &["corp.example"],
            &[]
        )])
        .await
        .is_err());

    assert!(holds_upstream_answer(&cache));
}
