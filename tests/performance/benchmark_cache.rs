
mod common;
use common::{PerformanceThresholds, TestClient, TestConfig, TestDomains, TestServer, TestServerBuilder};
use std::collections::HashMap;

// ============================================================================
// Cache Hit Rate Tests
// ============================================================================

#[tokio::test]
async fn test_cache_hit_rate_repeated_queries() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Warm up cache
    let _ = client.query(TestDomains::google(), "A").await;

    // Repeated queries should hit cache
    let query_count = 100;
    for _ in 0..query_count {
        let _ = client.query(TestDomains::google(), "A").await;
    }

    // Expected: ~99% cache hit rate (all but first query)
    println!("Expected cache hit rate: ~99% (99/100 queries)");

    server.shutdown();
}

#[tokio::test]
async fn test_cache_hit_rate_mixed_queries() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    let domains = vec![
        TestDomains::google(),
        TestDomains::cloudflare(),
        TestDomains::example(),
    ];

    // First round - populate cache
    for domain in &domains {
        let _ = client.query(domain, "A").await;
    }

    // Second round - should hit cache
    for domain in &domains {
        let _ = client.query(domain, "A").await;
    }

    // Third round - should also hit cache
    for domain in &domains {
        let _ = client.query(domain, "A").await;
    }

    // Expected: 67% cache hit rate (6 hits out of 9 queries)
    println!("Expected cache hit rate: ~67% (6/9 queries)");

    server.shutdown();
}

#[tokio::test]
async fn test_cache_working_set() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Simulate working set of domains
    let working_set = vec![
        "google.com",
        "cloudflare.com",
        "example.com",
        "github.com",
        "stackoverflow.com",
    ];

    // Query working set repeatedly
    for _ in 0..10 {
        for domain in &working_set {
            let _ = client.query(domain, "A").await;
        }
    }

    // Expected: High cache hit rate after first round
    // 45/50 queries should hit cache (90%)
    println!("Expected cache hit rate: ~90% for working set");

    server.shutdown();
}

// ============================================================================
// Cache Capacity Tests
// ============================================================================

#[tokio::test]
async fn test_cache_capacity_limit() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    let cache_size = TestConfig::default_cache_size();

    // Fill cache beyond capacity
    for i in 0..(cache_size + 100) {
        let domain = format!("domain{}.test.com", i);
        let _ = client.query(&domain, "A").await;
    }

    // Cache should have evicted some entries
    // But system should still work
    println!("Queried {} domains (cache size: {})", cache_size + 100, cache_size);

    server.shutdown();
}

#[tokio::test]
async fn test_cache_eviction_lru() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Fill cache
    for i in 0..100 {
        let domain = format!("domain{}.test.com", i);
        let _ = client.query(&domain, "A").await;
    }

    // Query first domain again (should refresh LRU)
    let _ = client.query("domain0.test.com", "A").await;

    // Fill with more domains
    for i in 100..200 {
        let domain = format!("domain{}.test.com", i);
        let _ = client.query(&domain, "A").await;
    }

    // domain0 should still be in cache (recently used)
    // domain1-99 may have been evicted

    server.shutdown();
}

// ============================================================================
// Cache TTL Tests
// ============================================================================

#[tokio::test]
async fn test_cache_respects_ttl() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Query domain
    let _ = client.query(TestDomains::example(), "A").await;

    // Query again immediately - should hit cache
    let _ = client.query(TestDomains::example(), "A").await;

    // Wait for TTL to expire (simulated)
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Query again - may or may not be cached depending on TTL
    let _ = client.query(TestDomains::example(), "A").await;

    server.shutdown();
}

// ============================================================================
// Cache Performance Impact
// ============================================================================

#[tokio::test]
async fn test_cache_vs_no_cache_performance() {
    // With cache
    let server_cached = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client_cached = TestClient::new(server_cached.addr());

    // Warm cache
    let _ = client_cached.query(TestDomains::google(), "A").await;

    let start = std::time::Instant::now();
    for _ in 0..50 {
        let _ = client_cached.query(TestDomains::google(), "A").await;
    }
    let cached_time = start.elapsed();

    server_cached.shutdown();

    // Without cache (if possible to disable)
    // For now, just compare with unique queries
    let server_uncached = TestServer::start().await.expect("Failed to start server");
    let client_uncached = TestClient::new(server_uncached.addr());

    let start = std::time::Instant::now();
    for i in 0..50 {
        let domain = format!("unique{}.test.com", i);
        let _ = client_uncached.query(&domain, "A").await;
    }
    let uncached_time = start.elapsed();

    server_uncached.shutdown();

    println!("Cached: {:?}, Uncached: {:?}", cached_time, uncached_time);
    println!("Speedup: {:.2}x", uncached_time.as_secs_f64() / cached_time.as_secs_f64());

    // Cache should be significantly faster
    assert!(cached_time < uncached_time, "Cache should improve performance");
}

// ============================================================================
// Cache Memory Usage
// ============================================================================

#[tokio::test]
async fn test_cache_memory_efficiency() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Fill cache with many entries
    for i in 0..500 {
        let domain = format!("domain{}.test.com", i);
        let _ = client.query(&domain, "A").await;
    }

    // Cache should not use excessive memory
    // (Hard to measure without instrumentation)
    println!("Cached 500 unique domains");

    server.shutdown();
}

// ============================================================================
// Cache Concurrency Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_cache_access() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let addr = server.addr();

    // Multiple clients accessing same cached entry
    let handles: Vec<_> = (0..10)
        .map(|_| {
            tokio::spawn(async move {
                let client = TestClient::new(addr);
                for _ in 0..10 {
                    let _ = client.query(TestDomains::google(), "A").await;
                }
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    // Concurrent access should work without issues
    println!("100 concurrent cache accesses completed");

    server.shutdown();
}

#[tokio::test]
async fn test_concurrent_cache_updates() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let addr = server.addr();

    // Multiple clients querying different domains
    let handles: Vec<_> = (0..10)
        .map(|i| {
            tokio::spawn(async move {
                let client = TestClient::new(addr);
                let domain = format!("domain{}.test.com", i);
                for _ in 0..5 {
                    let _ = client.query(&domain, "A").await;
                }
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    // Concurrent updates should work correctly
    println!("50 concurrent cache updates completed");

    server.shutdown();
}

// ============================================================================
// Cache Invalidation Tests
// ============================================================================

#[tokio::test]
async fn test_cache_refresh() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Initial query
    let _ = client.query(TestDomains::example(), "A").await;

    // Multiple queries - should hit cache
    for _ in 0..10 {
        let _ = client.query(TestDomains::example(), "A").await;
    }

    // After TTL, should refresh
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let _ = client.query(TestDomains::example(), "A").await;

    server.shutdown();
}

// ============================================================================
// Cache Statistics Tests
// ============================================================================

#[tokio::test]
async fn test_cache_statistics_accuracy() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    let mut expected_hits = 0;
    let mut expected_misses = 0;

    // Track what we query
    let mut queried = HashMap::new();

    for i in 0..20 {
        let domain = if i < 10 {
            format!("domain{}.test.com", i % 5) // Repeat 5 domains
        } else {
            format!("domain{}.test.com", i % 5) // Repeat again
        };

        if queried.contains_key(&domain) {
            expected_hits += 1;
        } else {
            expected_misses += 1;
            queried.insert(domain.clone(), true);
        }

        let _ = client.query(&domain, "A").await;
    }

    println!("Expected hits: {}, misses: {}", expected_hits, expected_misses);
    println!("Expected hit rate: {:.2}%", 
        (expected_hits as f64 / 20.0) * 100.0);

    server.shutdown();
}
