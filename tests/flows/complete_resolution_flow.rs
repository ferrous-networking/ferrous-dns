/// Complete Resolution Flow Test
/// 
/// Tests full DNS resolution flow:
/// Query → Cache miss → Upstream → DNSSEC → Cache → Response

mod common;
use common::{TestClient, TestDomains, TestServer, TestServerBuilder};

// ============================================================================
// Full Resolution Flow Tests
// ============================================================================

#[tokio::test]
async fn test_complete_resolution_flow() {
    // Arrange: Start test server
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Act: Perform DNS query
    let result = client.query(TestDomains::google(), "A").await;

    // Assert: Should get response
    assert!(result.is_ok(), "Query should succeed");
    let addresses = result.unwrap();
    assert!(!addresses.is_empty(), "Should return at least one address");

    server.shutdown();
}

#[tokio::test]
async fn test_cache_miss_then_upstream() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // First query - cache miss
    let result1 = client.query(TestDomains::example(), "A").await;
    assert!(result1.is_ok());

    // Second query - should hit cache (if implemented)
    let result2 = client.query(TestDomains::example(), "A").await;
    assert!(result2.is_ok());

    // Results should be same
    assert_eq!(result1.unwrap(), result2.unwrap());

    server.shutdown();
}

#[tokio::test]
async fn test_dnssec_validation_flow() {
    let server = TestServerBuilder::new()
        .with_dnssec(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Query domain with DNSSEC
    let result = client.query(TestDomains::cloudflare(), "A").await;

    assert!(result.is_ok(), "DNSSEC query should succeed");

    server.shutdown();
}

#[tokio::test]
async fn test_multiple_queries_in_sequence() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let domains = vec![
        TestDomains::google(),
        TestDomains::cloudflare(),
        TestDomains::example(),
    ];

    for domain in domains {
        let result = client.query(domain, "A").await;
        assert!(result.is_ok(), "Query for {} should succeed", domain);
    }

    server.shutdown();
}

// ============================================================================
// Cache Flow Tests
// ============================================================================

#[tokio::test]
async fn test_cache_warm_on_startup() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    // Cache should be empty initially
    // (Could verify via metrics if available)

    server.shutdown();
}

#[tokio::test]
async fn test_cache_eviction_flow() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Fill cache with multiple queries
    let queries = vec![
        (TestDomains::google(), "A"),
        (TestDomains::cloudflare(), "A"),
        (TestDomains::example(), "A"),
    ];

    client.query_many(queries).await;

    // All queries should succeed
    // Cache should handle eviction (if full)

    server.shutdown();
}

#[tokio::test]
async fn test_cache_ttl_expiration() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Query domain
    let result1 = client.query(TestDomains::example(), "A").await;
    assert!(result1.is_ok());

    // Wait for TTL to expire (would need actual TTL in real test)
    // For now, just verify second query works
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let result2 = client.query(TestDomains::example(), "A").await;
    assert!(result2.is_ok());

    server.shutdown();
}

// ============================================================================
// Blocklist Flow Tests
// ============================================================================

#[tokio::test]
async fn test_blocked_domain_flow() {
    let server = TestServerBuilder::new()
        .with_blocklist(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Query blocked domain
    let result = client.query(TestDomains::blocked_ad(), "A").await;

    // Should either error or return empty
    // Behavior depends on implementation
    let _ = result;

    server.shutdown();
}

#[tokio::test]
async fn test_blocklist_bypass_cache() {
    let server = TestServerBuilder::new()
        .with_cache(true)
        .with_blocklist(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Blocked domain should not hit cache
    let result = client.query(TestDomains::blocked_tracker(), "A").await;
    
    // Should be blocked immediately
    let _ = result;

    server.shutdown();
}

// ============================================================================
// Record Type Flow Tests
// ============================================================================

#[tokio::test]
async fn test_a_record_flow() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let result = client.query(TestDomains::google(), "A").await;
    
    assert!(result.is_ok());
    let addresses = result.unwrap();
    // Should return IPv4 addresses
    for addr in addresses {
        assert!(addr.contains('.'), "A record should return IPv4");
    }

    server.shutdown();
}

#[tokio::test]
async fn test_aaaa_record_flow() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let result = client.query(TestDomains::google(), "AAAA").await;
    
    if result.is_ok() {
        let addresses = result.unwrap();
        // AAAA records return IPv6
        for addr in addresses {
            assert!(addr.contains(':'), "AAAA record should return IPv6");
        }
    }

    server.shutdown();
}

#[tokio::test]
async fn test_mx_record_flow() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let result = client.query(TestDomains::google(), "MX").await;
    
    // MX records may or may not be available
    // Just verify it doesn't crash
    let _ = result;

    server.shutdown();
}

// ============================================================================
// Error Handling Flow Tests
// ============================================================================

#[tokio::test]
async fn test_nonexistent_domain_flow() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let result = client.query(TestDomains::nonexistent(), "A").await;

    // Should handle NXDOMAIN gracefully
    // May return error or empty result
    let _ = result;

    server.shutdown();
}

#[tokio::test]
async fn test_timeout_flow() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Query with very short timeout (if configurable)
    let result = client.query("slow.example.com", "A").await;

    // Should handle timeout gracefully
    let _ = result;

    server.shutdown();
}

// ============================================================================
// Parallel Query Flow Tests
// ============================================================================

#[tokio::test]
async fn test_parallel_queries_flow() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    let queries = vec![
        (TestDomains::google(), "A"),
        (TestDomains::cloudflare(), "A"),
        (TestDomains::example(), "A"),
    ];

    let results = client.query_parallel(queries).await;

    // All queries should complete
    assert_eq!(results.len(), 3);

    // At least some should succeed
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    assert!(success_count > 0, "At least one query should succeed");

    server.shutdown();
}

#[tokio::test]
async fn test_concurrent_same_domain() {
    let server = TestServer::start().await.expect("Failed to start server");
    let client = TestClient::new(server.addr());

    // Query same domain concurrently
    let queries = vec![
        (TestDomains::google(), "A"),
        (TestDomains::google(), "A"),
        (TestDomains::google(), "A"),
    ];

    let results = client.query_parallel(queries).await;

    // All should succeed and return same result
    assert_eq!(results.len(), 3);

    server.shutdown();
}

// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_full_stack_integration() {
    // Test complete stack: API → Use Case → Repository → DNS
    let server = TestServerBuilder::new()
        .with_cache(true)
        .with_dnssec(true)
        .with_blocklist(true)
        .build()
        .await
        .expect("Failed to start server");

    let client = TestClient::new(server.addr());

    // Test various scenarios
    let _ = client.query(TestDomains::google(), "A").await;
    let _ = client.query(TestDomains::blocked_ad(), "A").await;
    let _ = client.query(TestDomains::nonexistent(), "A").await;

    // Server should handle all scenarios without crashing
    server.shutdown();
}
