use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;

fn pool(name: &str, server: &str) -> UpstreamPool {
    UpstreamPool {
        name: name.into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![server.into()],
        weight: None,
    }
}

#[tokio::test]
async fn reload_swaps_live_servers() {
    let pm = PoolManager::new(
        vec![pool("p1", "udp://8.8.8.8:53")],
        None,
        QueryEventEmitter::new_disabled(),
    )
    .await
    .expect("PoolManager should create");

    let before: Vec<String> = pm.get_all_servers().iter().map(|a| a.to_string()).collect();
    assert!(before.iter().any(|a| a == "8.8.8.8:53"));

    pm.reload(vec![pool("p1", "udp://1.1.1.1:53")])
        .await
        .expect("reload should succeed");

    let after: Vec<String> = pm.get_all_servers().iter().map(|a| a.to_string()).collect();
    assert!(
        after.iter().any(|a| a == "1.1.1.1:53"),
        "reloaded server should be live: {after:?}"
    );
    assert!(
        !after.iter().any(|a| a == "8.8.8.8:53"),
        "old server should be gone after reload: {after:?}"
    );
}

#[tokio::test]
async fn reload_rejects_empty_pool_set() {
    let pm = PoolManager::new(
        vec![pool("p1", "udp://8.8.8.8:53")],
        None,
        QueryEventEmitter::new_disabled(),
    )
    .await
    .expect("PoolManager should create");

    assert!(
        pm.reload(Vec::new()).await.is_err(),
        "reloading with no pools must be rejected"
    );

    // The previous pool set must remain live after a rejected reload.
    let servers: Vec<String> = pm.get_all_servers().iter().map(|a| a.to_string()).collect();
    assert!(servers.iter().any(|a| a == "8.8.8.8:53"));
}
