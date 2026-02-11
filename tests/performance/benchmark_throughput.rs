mod common;
use common::{PerformanceThresholds, TestClient, TestConfig, TestDomains, TestServer};
use std::time::Instant;

// ============================================================================
// Throughput Tests
// ============================================================================

#[tokio::test]
async fn test_small_load_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = TestConfig::small_load_queries();
    let start = Instant::now();

    // Send queries sequentially
    for _ in 0..query_count {
        let _ = client.query(TestDomains::google(), "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Small load: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);
    
    // Should handle small load easily
    assert!(qps > 10.0, "Should handle at least 10 QPS");

    server.shutdown();
}

#[tokio::test]
async fn test_medium_load_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = TestConfig::medium_load_queries();
    let start = Instant::now();

    for _ in 0..query_count {
        let _ = client.query(TestDomains::example(), "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Medium load: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    // Should handle medium load
    assert!(qps > 50.0, "Should handle at least 50 QPS");

    server.shutdown();
}

#[tokio::test]
#[ignore] // Ignore by default (slow test)
async fn test_large_load_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = TestConfig::large_load_queries();
    let start = Instant::now();

    for _ in 0..query_count {
        let _ = client.query(TestDomains::cloudflare(), "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Large load: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    // Should meet minimum throughput threshold
    assert!(
        qps > PerformanceThresholds::min_throughput_qps(),
        "Should handle at least {} QPS, got {:.2}",
        PerformanceThresholds::min_throughput_qps(),
        qps
    );

    server.shutdown();
}

// ============================================================================
// Parallel Throughput Tests
// ============================================================================

#[tokio::test]
async fn test_parallel_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = TestConfig::small_load_queries();
    let start = Instant::now();

    // Create queries
    let queries: Vec<_> = (0..query_count)
        .map(|_| (TestDomains::google(), "A"))
        .collect();

    // Execute in parallel
    let _results = client.query_parallel(queries).await;

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Parallel: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    // Parallel should be faster than sequential
    assert!(qps > 50.0, "Parallel queries should be fast");

    server.shutdown();
}

#[tokio::test]
async fn test_concurrent_clients_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");

    let client_count = 5;
    let queries_per_client = 20;
    let total_queries = client_count * queries_per_client;

    let start = Instant::now();

    let handles: Vec<_> = (0..client_count)
        .map(|_| {
            let addr = server.addr();
            tokio::spawn(async move {
                let client = TestClient::new(addr);
                for _ in 0..queries_per_client {
                    let _ = client.query(TestDomains::example(), "A").await;
                }
            })
        })
        .collect();

    // Wait for all clients
    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let qps = total_queries as f64 / elapsed.as_secs_f64();

    println!("Concurrent clients: {} queries in {:?} = {:.2} QPS", total_queries, elapsed, qps);

    // Multiple clients should achieve good throughput
    assert!(qps > 20.0, "Should handle concurrent clients");

    server.shutdown();
}

// ============================================================================
// Sustained Load Tests
// ============================================================================

#[tokio::test]
#[ignore] // Slow test
async fn test_sustained_load() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let duration = tokio::time::Duration::from_secs(10);
    let start = Instant::now();
    let mut query_count = 0;

    // Send queries for specified duration
    while start.elapsed() < duration {
        let _ = client.query(TestDomains::google(), "A").await;
        query_count += 1;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Sustained: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    // Should maintain throughput over time
    assert!(qps > 100.0, "Should sustain at least 100 QPS");

    server.shutdown();
}

// ============================================================================
// Cache Impact on Throughput
// ============================================================================

#[tokio::test]
async fn test_cache_hit_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Warm up cache
    let _ = client.query(TestDomains::google(), "A").await;

    let query_count = 100;
    let start = Instant::now();

    // All queries should hit cache
    for _ in 0..query_count {
        let _ = client.query(TestDomains::google(), "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Cache hit throughput: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    // Cache hits should be very fast
    assert!(qps > 500.0, "Cache hits should achieve high QPS");

    server.shutdown();
}

#[tokio::test]
async fn test_cache_miss_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = 50;
    let start = Instant::now();

    // All unique queries = all cache misses
    for i in 0..query_count {
        let domain = format!("unique{}.example.com", i);
        let _ = client.query(&domain, "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Cache miss throughput: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    // Cache misses should still be reasonable
    assert!(qps > 10.0, "Should handle cache misses");

    server.shutdown();
}

// ============================================================================
// Mixed Workload Tests
// ============================================================================

#[tokio::test]
async fn test_mixed_record_types_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = 100;
    let start = Instant::now();

    let record_types = vec!["A", "AAAA", "MX"];
    
    for i in 0..query_count {
        let record_type = record_types[i % record_types.len()];
        let _ = client.query(TestDomains::google(), record_type).await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Mixed types: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    assert!(qps > 20.0, "Should handle mixed record types");

    server.shutdown();
}

#[tokio::test]
async fn test_mixed_domain_throughput() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let domains = vec![
        TestDomains::google(),
        TestDomains::cloudflare(),
        TestDomains::example(),
    ];

    let query_count = 90;
    let start = Instant::now();

    for i in 0..query_count {
        let domain = domains[i % domains.len()];
        let _ = client.query(domain, "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Mixed domains: {} queries in {:?} = {:.2} QPS", query_count, elapsed, qps);

    assert!(qps > 20.0, "Should handle mixed domains");

    server.shutdown();
}

// ============================================================================
// Throughput Degradation Tests
// ============================================================================

#[tokio::test]
async fn test_no_throughput_degradation() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // First batch
    let start1 = Instant::now();
    for _ in 0..50 {
        let _ = client.query(TestDomains::google(), "A").await;
    }
    let qps1 = 50.0 / start1.elapsed().as_secs_f64();

    // Second batch (should not degrade)
    let start2 = Instant::now();
    for _ in 0..50 {
        let _ = client.query(TestDomains::google(), "A").await;
    }
    let qps2 = 50.0 / start2.elapsed().as_secs_f64();

    println!("QPS batch 1: {:.2}, batch 2: {:.2}", qps1, qps2);

    // Should not degrade significantly
    assert!(qps2 >= qps1 * 0.8, "Throughput should not degrade");

    server.shutdown();
}
