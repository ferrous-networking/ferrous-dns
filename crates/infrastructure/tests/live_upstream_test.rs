//! Live (network) smoke test for upstream anti-spoofing against REAL public
//! resolvers. `#[ignore]`d so it never runs in normal CI; run explicitly with:
//!
//!   cargo test -p ferrous-dns-infrastructure --test live_upstream_test -- --ignored --nocapture
//!
//! These confirm that real-world Do53 resolvers behave as the `ResponseValidator`
//! assumes: the transaction ID + question match, the cookie echo (when supported)
//! validates, and — for the 0x20 cases — the resolver preserves the randomized
//! QNAME case so the case-sensitive question check still passes.

use ferrous_dns_domain::{RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use std::sync::Arc;
use std::time::Duration;

async fn hardened_pm(server: &str, qname_0x20: bool) -> Arc<PoolManager> {
    let pool = UpstreamPool {
        name: "live".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![server.to_string()],
        weight: None,
    };
    Arc::new(
        PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled())
            .await
            .unwrap()
            .with_hardening(HardeningOpts {
                cookie: true,
                qname_0x20,
            }),
    )
}

async fn resolve_live(server: &str, domain: &str, qname_0x20: bool) {
    let pm = hardened_pm(server, qname_0x20).await;
    let domain: Arc<str> = Arc::from(domain);

    // Real Do53 over the open internet drops packets and rate-limits bursts;
    // retry with backoff so the smoke test only fails on a deterministic
    // validation rejection, not a blip. (Each test targets a distinct resolver
    // IP to avoid one process hammering the same server twice.)
    let mut last_err = None;
    for attempt in 0..4 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
        match pm.query(&domain, &RecordType::A, 5000, false).await {
            Ok(result) => {
                assert!(
                    !result.response.addresses.is_empty(),
                    "{server} returned no A records for {domain}"
                );
                println!(
                    "{server} {domain} (cookie=on, 0x20={qname_0x20}) -> {:?}",
                    result.response.addresses
                );
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    panic!("{server} response for {domain} failed anti-spoofing validation after 4 tries: {last_err:?}");
}

#[tokio::test]
#[ignore = "live network: hits 9.9.9.9; run with --ignored"]
async fn live_cookie_only() {
    // Most lenient mode (cookie graceful, case-insensitive question) against Quad9.
    resolve_live("udp://9.9.9.9:53", "example.com", false).await;
}

#[tokio::test]
#[ignore = "live network: hits 1.1.1.1; run with --ignored"]
async fn live_cloudflare_cookie_and_0x20() {
    resolve_live("udp://1.1.1.1:53", "example.com", true).await;
}

#[tokio::test]
#[ignore = "live network: hits 8.8.8.8; run with --ignored"]
async fn live_google_cookie_and_0x20() {
    resolve_live("udp://8.8.8.8:53", "cloudflare.com", true).await;
}
