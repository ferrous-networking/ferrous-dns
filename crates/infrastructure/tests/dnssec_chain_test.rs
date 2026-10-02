use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::dnssec::trust_anchor::TrustAnchorStore;
use ferrous_dns_infrastructure::dns::dnssec::{ChainFailure, ChainVerifier, DnssecCache};
use ferrous_dns_infrastructure::dns::PoolManager;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[tokio::test]
async fn chain_walk_honours_the_configured_upstream_timeout() {
    // Receives queries but never answers, so every lookup runs into the timeout.
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pool = UpstreamPool {
        name: "test".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![format!("udp://{}", blackhole.local_addr().unwrap())],
        weight: None,
    };
    let pm = Arc::new(PoolManager::new(vec![pool], None).await.unwrap());
    let mut verifier = ChainVerifier::new(
        pm,
        TrustAnchorStore::new(),
        Arc::new(DnssecCache::new()),
        200,
    );

    let started = Instant::now();
    let verdict = verifier.verify_chain("example.com.").await;

    assert_eq!(verdict, Err(ChainFailure::Indeterminate));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "walk took {:?}; the 200 ms timeout was not applied",
        started.elapsed()
    );
}
