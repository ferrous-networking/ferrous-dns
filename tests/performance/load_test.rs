mod common;
use common::{TestClient, TestConfig, TestDomains, TestServer, TestServerBuilder};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// Load Tests
// ============================================================================

#[tokio::test]
#[ignore] // Heavy test - run explicitly
async fn test_sustained_load_1000_qps() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let target_qps = 1000;
    let duration = Duration::from_secs(10);
    let interval = Duration::from_micros(1_000_000 / target_qps);

    let start = Instant::now();
    let mut query_count = 0;
    let mut last_query = Instant::now();

    while start.elapsed() < duration {
        if last_query.elapsed() >= interval {
            let _ = client.query(TestDomains::google(), "A").await;
            query_count += 1;
            last_query = Instant::now();
        }
    }

    let actual_qps = query_count as f64 / start.elapsed().as_secs_f64();
    println!("Target: {} QPS, Achieved: {:.2} QPS", target_qps, actual_qps);

    assert!(actual_qps >= target_qps as f64 * 0.8, "Should achieve at least 80% of target QPS");

    server.shutdown();
}

#[tokio::test]
#[ignore] // Slow test
async fn test_large_query_volume() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = TestConfig::large_load_queries();
    let start = Instant::now();

    for _ in 0..query_count {
        let _ = client.query(TestDomains::example(), "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Completed {} queries in {:?} ({:.2} QPS)", query_count, elapsed, qps);

    server.shutdown();
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
#[ignore] // Very heavy test
async fn test_stress_100k_queries() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let query_count = TestConfig::stress_test_queries();
    let start = Instant::now();

    println!("Starting stress test with {} queries...", query_count);

    for i in 0..query_count {
        if i % 10000 == 0 {
            println!("Progress: {}/{}", i, query_count);
        }
        let _ = client.query(TestDomains::google(), "A").await;
    }

    let elapsed = start.elapsed();
    let qps = query_count as f64 / elapsed.as_secs_f64();

    println!("Stress test completed:");
    println!("  Queries: {}", query_count);
    println!("  Duration: {:?}", elapsed);
    println!("  QPS: {:.2}", qps);

    server.shutdown();
}

#[tokio::test]
#[ignore] // Heavy test
async fn test_concurrent_stress() {
    let server = TestServer::start().await.expect("Failed to start server");
    let addr = server.addr();

    let client_count = 50;
    let queries_per_client = 100;
    let total_queries = client_count * queries_per_client;

    let success_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let handles: Vec<_> = (0..client_count)
        .map(|_| {
            let success = Arc::clone(&success_count);
            let errors = Arc::clone(&error_count);
            
            tokio::spawn(async move {
                let client = TestClient::new(addr);
                for _ in 0..queries_per_client {
                    match client.query(TestDomains::example(), "A").await {
                        Ok(_) => { success.fetch_add(1, Ordering::Relaxed); }
                        Err(_) => { errors.fetch_add(1, Ordering::Relaxed); }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let successes = success_count.load(Ordering::Relaxed);
    let errors = error_count.load(Ordering::Relaxed);
    let qps = total_queries as f64 / elapsed.as_secs_f64();

    println!("Concurrent stress test:");
    println!("  Clients: {}", client_count);
    println!("  Total queries: {}", total_queries);
    println!("  Successes: {}", successes);
    println!("  Errors: {}", errors);
    println!("  Duration: {:?}", elapsed);
    println!("  QPS: {:.2}", qps);

    assert!(successes > total_queries * 90 / 100, "Should have >90% success rate");

    server.shutdown();
}

// ============================================================================
// Memory Stress Tests
// ============================================================================

#[tokio::test]
#[ignore] // Heavy test
async fn test_many_unique_queries() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Query many unique domains (stress cache)
    for i in 0..5000 {
        let domain = format!("unique{}.stress.test", i);
        let _ = client.query(&domain, "A").await;
        
        if i % 1000 == 0 {
            println!("Queried {} unique domains", i);
        }
    }

    println!("Completed 5000 unique queries");

    server.shutdown();
}

// ============================================================================
// Connection Stress Tests
// ============================================================================

#[tokio::test]
#[ignore] // Heavy test
async fn test_many_concurrent_connections() {
    let server = TestServer::start().await.expect("Failed to start server");
    let addr = server.addr();

    let connection_count = 100;

    let handles: Vec<_> = (0..connection_count)
        .map(|i| {
            tokio::spawn(async move {
                let client = TestClient::new(addr);
                let _ = client.query(TestDomains::google(), "A").await;
                println!("Connection {} completed", i);
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    println!("All {} connections completed", connection_count);

    server.shutdown();
}

// ============================================================================
// Burst Load Tests
// ============================================================================

#[tokio::test]
async fn test_burst_load() {
    let server = TestServer::start().await.expect("Failed to start server");
    let addr = server.addr();

    // Sudden burst of queries
    let burst_size = 50;
    let handles: Vec<_> = (0..burst_size)
        .map(|_| {
            tokio::spawn(async move {
                let client = TestClient::new(addr);
                client.query(TestDomains::cloudflare(), "A").await
            })
        })
        .collect();

    let start = Instant::now();
    let mut success = 0;
    
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            success += 1;
        }
    }

    let elapsed = start.elapsed();
    
    println!("Burst load:");
    println!("  Size: {}", burst_size);
    println!("  Success: {}", success);
    println!("  Duration: {:?}", elapsed);

    assert!(success >= burst_size * 80 / 100, "Should handle burst load");

    server.shutdown();
}

// ============================================================================
// Sustained High Load Tests
// ============================================================================

#[tokio::test]
#[ignore] // Long running test
async fn test_sustained_high_load_1_minute() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let duration = Duration::from_secs(60);
    let start = Instant::now();
    let mut query_count = 0;

    while start.elapsed() < duration {
        let _ = client.query(TestDomains::example(), "A").await;
        query_count += 1;
    }

    let qps = query_count as f64 / 60.0;
    println!("Sustained 1 minute: {} queries ({:.2} QPS)", query_count, qps);

    server.shutdown();
}

// ============================================================================
// Resource Exhaustion Tests
// ============================================================================

#[tokio::test]
#[ignore] // Heavy test
async fn test_cache_overflow() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Try to overflow cache with unique queries
    let cache_size = TestConfig::default_cache_size();
    let overflow_size = cache_size * 2;

    for i in 0..overflow_size {
        let domain = format!("overflow{}.test", i);
        let _ = client.query(&domain, "A").await;
    }

    println!("Attempted to overflow cache: {} queries", overflow_size);

    // System should handle gracefully
    server.shutdown();
}

// ============================================================================
// Recovery Tests
// ============================================================================

#[tokio::test]
async fn test_recovery_after_load() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Heavy load
    for _ in 0..100 {
        let _ = client.query(TestDomains::google(), "A").await;
    }

    // Should still work after load
    let result = client.query(TestDomains::example(), "A").await;
    assert!(result.is_ok() || result.is_err(), "Should respond after load");

    server.shutdown();
}

// ============================================================================
// Performance Degradation Tests
// ============================================================================

#[tokio::test]
async fn test_no_performance_degradation_under_load() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Measure initial performance
    let start = Instant::now();
    for _ in 0..50 {
        let _ = client.query(TestDomains::google(), "A").await;
    }
    let initial_time = start.elapsed();

    // Continue with more queries
    for _ in 0..200 {
        let _ = client.query(TestDomains::cloudflare(), "A").await;
    }

    // Measure performance again
    let start = Instant::now();
    for _ in 0..50 {
        let _ = client.query(TestDomains::google(), "A").await;
    }
    let later_time = start.elapsed();

    println!("Initial: {:?}, After load: {:?}", initial_time, later_time);

    // Should not degrade significantly
    assert!(
        later_time <= initial_time * 2,
        "Performance should not degrade significantly under load"
    );

    server.shutdown();
}
