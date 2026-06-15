use ferrous_dns_application::ports::UpstreamReloadPort;
use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use ferrous_dns_infrastructure::dns::UpstreamReloadAdapter;
use std::sync::Arc;

fn pool(server: &str) -> UpstreamPool {
    UpstreamPool {
        name: "p1".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![server.into()],
        weight: None,
    }
}

async fn manager(server: &str) -> Arc<PoolManager> {
    Arc::new(
        PoolManager::new(vec![pool(server)], None, QueryEventEmitter::new_disabled())
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
