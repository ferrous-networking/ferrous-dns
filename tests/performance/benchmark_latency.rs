mod common;
use common::{PerformanceThresholds, TestClient, TestConfig, TestDomains, TestServer};
use std::time::Instant;

// ============================================================================
// Latency Measurement Tests
// ============================================================================

#[tokio::test]
async fn test_single_query_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let start = Instant::now();
    let _ = client.query(TestDomains::google(), "A").await;
    let latency = start.elapsed();

    println!("Single query latency: {:?}", latency);

    // Should respond quickly
    assert!(latency.as_millis() < 1000, "Single query should be fast");

    server.shutdown();
}

#[tokio::test]
async fn test_p50_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let sample_size = 100;
    let mut latencies = Vec::with_capacity(sample_size);

    // Collect latencies
    for _ in 0..sample_size {
        let start = Instant::now();
        let _ = client.query(TestDomains::example(), "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    // Calculate P50
    latencies.sort();
    let p50 = latencies[sample_size / 2];

    println!("P50 latency: {} ms", p50);

    assert!(
        p50 < PerformanceThresholds::p50_latency_ms(),
        "P50 should be < {} ms, got {} ms",
        PerformanceThresholds::p50_latency_ms(),
        p50
    );

    server.shutdown();
}

#[tokio::test]
async fn test_p95_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let sample_size = 100;
    let mut latencies = Vec::with_capacity(sample_size);

    for _ in 0..sample_size {
        let start = Instant::now();
        let _ = client.query(TestDomains::cloudflare(), "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    let p95 = latencies[sample_size * 95 / 100];

    println!("P95 latency: {} ms", p95);

    assert!(
        p95 < PerformanceThresholds::p95_latency_ms(),
        "P95 should be < {} ms, got {} ms",
        PerformanceThresholds::p95_latency_ms(),
        p95
    );

    server.shutdown();
}

#[tokio::test]
async fn test_p99_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let sample_size = 100;
    let mut latencies = Vec::with_capacity(sample_size);

    for _ in 0..sample_size {
        let start = Instant::now();
        let _ = client.query(TestDomains::google(), "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    let p99 = latencies[sample_size * 99 / 100];

    println!("P99 latency: {} ms", p99);

    assert!(
        p99 < PerformanceThresholds::p99_latency_ms(),
        "P99 should be < {} ms, got {} ms",
        PerformanceThresholds::p99_latency_ms(),
        p99
    );

    server.shutdown();
}

// ============================================================================
// Cache Impact on Latency
// ============================================================================

#[tokio::test]
async fn test_cache_hit_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Warm cache
    let _ = client.query(TestDomains::google(), "A").await;

    let mut latencies = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = client.query(TestDomains::google(), "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    let p50 = latencies[25];
    let p99 = latencies[49];

    println!("Cache hit P50: {} ms, P99: {} ms", p50, p99);

    // Cache hits should be very fast
    assert!(p50 < 10, "Cache hit P50 should be < 10ms");
    assert!(p99 < 50, "Cache hit P99 should be < 50ms");

    server.shutdown();
}

#[tokio::test]
async fn test_cache_miss_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let mut latencies = Vec::new();
    
    // Each query is unique = cache miss
    for i in 0..50 {
        let domain = format!("unique{}.test.com", i);
        let start = Instant::now();
        let _ = client.query(&domain, "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    let p50 = latencies[25];
    let p99 = latencies[49];

    println!("Cache miss P50: {} ms, P99: {} ms", p50, p99);

    // Cache misses are slower but should still be reasonable
    assert!(p50 < 100, "Cache miss P50 should be < 100ms");

    server.shutdown();
}

// ============================================================================
// Cold Start Latency
// ============================================================================

#[tokio::test]
async fn test_first_query_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // First query (cold start)
    let start = Instant::now();
    let _ = client.query(TestDomains::example(), "A").await;
    let cold_latency = start.elapsed();

    // Second query (warm)
    let start = Instant::now();
    let _ = client.query(TestDomains::example(), "A").await;
    let warm_latency = start.elapsed();

    println!("Cold: {:?}, Warm: {:?}", cold_latency, warm_latency);

    // Warm should be faster or similar
    assert!(warm_latency <= cold_latency * 2, "Warm query should not be much slower");

    server.shutdown();
}

// ============================================================================
// Different Query Types Latency
// ============================================================================

#[tokio::test]
async fn test_a_record_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let mut latencies = Vec::new();
    for _ in 0..30 {
        let start = Instant::now();
        let _ = client.query(TestDomains::google(), "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    let median = latencies[15];

    println!("A record latency (median): {} ms", median);

    assert!(median < 100, "A record queries should be fast");

    server.shutdown();
}

#[tokio::test]
async fn test_aaaa_record_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let mut latencies = Vec::new();
    for _ in 0..30 {
        let start = Instant::now();
        let _ = client.query(TestDomains::google(), "AAAA").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    let median = latencies[15];

    println!("AAAA record latency (median): {} ms", median);

    assert!(median < 100, "AAAA record queries should be fast");

    server.shutdown();
}

// ============================================================================
// Concurrent Query Latency
// ============================================================================

#[tokio::test]
async fn test_concurrent_query_latency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let addr = server.addr();

    let handles: Vec<_> = (0..10)
        .map(|_| {
            tokio::spawn(async move {
                let client = TestClient::new(addr);
                let start = Instant::now();
                let _ = client.query(TestDomains::example(), "A").await;
                start.elapsed()
            })
        })
        .collect();

    let mut latencies = Vec::new();
    for handle in handles {
        if let Ok(latency) = handle.await {
            latencies.push(latency.as_millis());
        }
    }

    latencies.sort();
    if !latencies.is_empty() {
        let median = latencies[latencies.len() / 2];
        println!("Concurrent query latency (median): {} ms", median);

        // Concurrent queries should not be much slower
        assert!(median < 200, "Concurrent queries should be reasonably fast");
    }

    server.shutdown();
}

// ============================================================================
// Latency Consistency Tests
// ============================================================================

#[tokio::test]
async fn test_latency_consistency() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let mut latencies = Vec::new();
    for _ in 0..100 {
        let start = Instant::now();
        let _ = client.query(TestDomains::cloudflare(), "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    let p50 = latencies[50];
    let p99 = latencies[99];

    println!("Latency P50: {} ms, P99: {} ms", p50, p99);

    // P99 should not be too far from P50 (consistency)
    let ratio = p99 as f64 / p50 as f64;
    println!("P99/P50 ratio: {:.2}", ratio);

    assert!(ratio < 10.0, "Latency should be relatively consistent");

    server.shutdown();
}

#[tokio::test]
async fn test_no_latency_spikes() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let mut max_latency = 0u128;
    
    for _ in 0..50 {
        let start = Instant::now();
        let _ = client.query(TestDomains::example(), "A").await;
        let latency = start.elapsed().as_millis();
        
        if latency > max_latency {
            max_latency = latency;
        }
    }

    println!("Max latency observed: {} ms", max_latency);

    // Should not have extreme spikes
    assert!(max_latency < 500, "Should not have latency spikes > 500ms");

    server.shutdown();
}

// ============================================================================
// Percentile Distribution Tests
// ============================================================================

#[tokio::test]
async fn test_full_latency_distribution() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let sample_size = 100;
    let mut latencies = Vec::with_capacity(sample_size);

    for _ in 0..sample_size {
        let start = Instant::now();
        let _ = client.query(TestDomains::google(), "A").await;
        latencies.push(start.elapsed().as_millis());
    }

    latencies.sort();
    
    let p50 = latencies[50];
    let p90 = latencies[90];
    let p95 = latencies[95];
    let p99 = latencies[99];

    println!("Latency distribution:");
    println!("  P50: {} ms", p50);
    println!("  P90: {} ms", p90);
    println!("  P95: {} ms", p95);
    println!("  P99: {} ms", p99);

    // Verify reasonable distribution
    assert!(p50 < p90);
    assert!(p90 < p95);
    assert!(p95 < p99);

    server.shutdown();
}
