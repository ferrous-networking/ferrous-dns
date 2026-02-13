use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_infrastructure::repositories::client_repository::SqliteClientRepository;
use sqlx::sqlite::SqlitePoolOptions;
use std::net::IpAddr;
use std::sync::Arc;

async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // Create groups table first
    sqlx::query(
        r#"
        CREATE TABLE groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            comment TEXT,
            is_default BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Insert Protected group
    sqlx::query(
        r#"
        INSERT INTO groups (id, name, enabled, comment, is_default)
        VALUES (1, 'Protected', 1, 'Default group for all clients. Cannot be disabled or deleted.', 1)
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Create clients table with group_id foreign key
    sqlx::query(
        r#"
        CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            query_count INTEGER NOT NULL DEFAULT 0,
            last_mac_update DATETIME,
            last_hostname_update DATETIME,
            group_id INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

#[tokio::test]
async fn test_update_last_seen_creates_client() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();

    let client = repo.get_or_create(ip).await.unwrap();
    assert_eq!(client.ip_address, ip);
    assert_eq!(client.query_count, 1);
}

#[tokio::test]
async fn test_update_last_seen_increments_count() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();

    repo.update_last_seen(ip).await.unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.update_last_seen(ip).await.unwrap();

    let client = repo.get_or_create(ip).await.unwrap();
    assert_eq!(client.query_count, 3);
}

#[tokio::test]
async fn test_update_mac_address() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();

    repo.update_mac_address(ip, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();

    let client = repo.get_or_create(ip).await.unwrap();
    assert_eq!(client.mac_address, Some(Arc::from("aa:bb:cc:dd:ee:ff")));
    assert!(client.last_mac_update.is_some());
}

#[tokio::test]
async fn test_update_hostname() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();

    repo.update_hostname(ip, "my-device.local".to_string())
        .await
        .unwrap();

    let client = repo.get_or_create(ip).await.unwrap();
    assert_eq!(client.hostname, Some(Arc::from("my-device.local")));
    assert!(client.last_hostname_update.is_some());
}

#[tokio::test]
async fn test_get_all_with_pagination() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    // Create 10 clients
    for i in 1..=10 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    let clients = repo.get_all(5, 0).await.unwrap();
    assert_eq!(clients.len(), 5);

    let clients = repo.get_all(5, 5).await.unwrap();
    assert_eq!(clients.len(), 5);
}

#[tokio::test]
async fn test_get_active_clients() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool.clone());

    // Create 5 clients
    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    // Manually set some clients as old
    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-31 days') WHERE ip_address IN ('192.168.1.1', '192.168.1.2')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Get active clients from last 30 days
    let active = repo.get_active(30, 100).await.unwrap();
    assert_eq!(active.len(), 3); // Only 3 are active
}

#[tokio::test]
async fn test_get_stats() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    // Create clients
    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();

        if i <= 3 {
            repo.update_mac_address(ip, format!("aa:bb:cc:dd:ee:{:02x}", i))
                .await
                .unwrap();
        }

        if i <= 2 {
            repo.update_hostname(ip, format!("device-{}.local", i))
                .await
                .unwrap();
        }
    }

    let stats = repo.get_stats().await.unwrap();
    assert_eq!(stats.total_clients, 5);
    assert_eq!(stats.with_mac, 3);
    assert_eq!(stats.with_hostname, 2);
}

#[tokio::test]
async fn test_delete_older_than() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool.clone());

    // Create clients
    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    // Manually set some clients as old
    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-31 days') WHERE ip_address IN ('192.168.1.1', '192.168.1.2')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let deleted = repo.delete_older_than(30).await.unwrap();
    assert_eq!(deleted, 2);

    let stats = repo.get_stats().await.unwrap();
    assert_eq!(stats.total_clients, 3);
}

#[tokio::test]
async fn test_get_needs_mac_update() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool.clone());

    // Create 3 clients
    for i in 1..=3 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    // Update MAC for one client recently
    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    repo.update_mac_address(ip1, "aa:bb:cc:dd:ee:01".to_string())
        .await
        .unwrap();

    // Set one client's MAC update to old
    sqlx::query(
        "UPDATE clients SET last_mac_update = datetime('now', '-10 minutes') WHERE ip_address = '192.168.1.2'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let needs_update = repo.get_needs_mac_update(10).await.unwrap();
    // Should include clients without MAC and those with old MAC update
    assert!(needs_update.len() >= 2);
}

#[tokio::test]
async fn test_get_needs_hostname_update() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool.clone());

    // Create 3 clients
    for i in 1..=3 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    // Update hostname for one client recently
    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    repo.update_hostname(ip1, "device1.local".to_string())
        .await
        .unwrap();

    // Set one client's hostname update to old
    sqlx::query(
        "UPDATE clients SET last_hostname_update = datetime('now', '-2 hours') WHERE ip_address = '192.168.1.2'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let needs_update = repo.get_needs_hostname_update(10).await.unwrap();
    // Should include clients without hostname and those with old hostname update
    assert!(needs_update.len() >= 2);
}

// ============================================================================
// Delete Client Tests
// ============================================================================

#[tokio::test]
async fn test_delete_existing_client() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();

    // Get the client ID
    let client = repo.get_or_create(ip).await.unwrap();
    let client_id = client.id.unwrap();

    // Delete the client
    let result = repo.delete(client_id).await;
    assert!(result.is_ok());

    // Verify client is gone
    let get_result = repo.get_by_id(client_id).await.unwrap();
    assert!(get_result.is_none());
}

#[tokio::test]
async fn test_delete_nonexistent_client() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    // Try to delete a client that doesn't exist
    let result = repo.delete(9999).await;

    assert!(result.is_err());
    match result {
        Err(ferrous_dns_domain::DomainError::NotFound(msg)) => {
            assert!(msg.contains("9999"));
        }
        _ => panic!("Expected NotFound error"),
    }
}

#[tokio::test]
async fn test_delete_client_removes_from_get_all() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    // Create 3 clients
    for i in 1..=3 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    let all_clients = repo.get_all(100, 0).await.unwrap();
    assert_eq!(all_clients.len(), 3);

    // Delete one client
    let client_id = all_clients[1].id.unwrap();
    repo.delete(client_id).await.unwrap();

    // Verify only 2 remain
    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(!remaining.iter().any(|c| c.id == Some(client_id)));
}

#[tokio::test]
async fn test_delete_client_with_mac_and_hostname() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.update_mac_address(ip, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();
    repo.update_hostname(ip, "test-device.local".to_string())
        .await
        .unwrap();

    let client = repo.get_or_create(ip).await.unwrap();
    let client_id = client.id.unwrap();

    // Delete should succeed even with additional data
    let result = repo.delete(client_id).await;
    assert!(result.is_ok());

    // Verify deletion
    let get_result = repo.get_by_id(client_id).await.unwrap();
    assert!(get_result.is_none());
}

#[tokio::test]
async fn test_delete_updates_stats() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    // Create clients
    for i in 1..=5 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    let stats_before = repo.get_stats().await.unwrap();
    assert_eq!(stats_before.total_clients, 5);

    // Delete 2 clients
    let clients = repo.get_all(100, 0).await.unwrap();
    repo.delete(clients[0].id.unwrap()).await.unwrap();
    repo.delete(clients[1].id.unwrap()).await.unwrap();

    let stats_after = repo.get_stats().await.unwrap();
    assert_eq!(stats_after.total_clients, 3);
}

#[tokio::test]
async fn test_delete_all_clients() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    // Create 3 clients
    for i in 1..=3 {
        let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
        repo.update_last_seen(ip).await.unwrap();
    }

    let all_clients = repo.get_all(100, 0).await.unwrap();
    assert_eq!(all_clients.len(), 3);

    // Delete all clients
    for client in all_clients {
        repo.delete(client.id.unwrap()).await.unwrap();
    }

    // Verify all are gone
    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 0);

    let stats = repo.get_stats().await.unwrap();
    assert_eq!(stats.total_clients, 0);
}

#[tokio::test]
async fn test_delete_idempotency() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();

    let client = repo.get_or_create(ip).await.unwrap();
    let client_id = client.id.unwrap();

    // First delete should succeed
    let result1 = repo.delete(client_id).await;
    assert!(result1.is_ok());

    // Second delete should fail
    let result2 = repo.delete(client_id).await;
    assert!(result2.is_err());
    assert!(matches!(
        result2,
        Err(ferrous_dns_domain::DomainError::NotFound(_))
    ));
}

#[tokio::test]
async fn test_delete_with_invalid_id() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    // Test various invalid IDs
    let invalid_ids = vec![0i64, -1i64, -999i64, i64::MAX];

    for invalid_id in invalid_ids {
        let result = repo.delete(invalid_id).await;
        assert!(
            result.is_err(),
            "Delete should fail for invalid ID: {}",
            invalid_id
        );
    }
}

#[tokio::test]
async fn test_delete_preserves_other_clients() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool.clone());

    // Create multiple clients
    let ips: Vec<IpAddr> = (1..=10)
        .map(|i| format!("192.168.1.{}", i).parse().unwrap())
        .collect();

    for ip in &ips {
        repo.update_last_seen(*ip).await.unwrap();
    }

    let all_clients = repo.get_all(100, 0).await.unwrap();
    assert_eq!(all_clients.len(), 10);

    // Delete client at index 5
    let delete_id = all_clients[5].id.unwrap();
    let delete_ip = all_clients[5].ip_address;

    repo.delete(delete_id).await.unwrap();

    // Verify exactly 9 clients remain
    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 9);

    // Verify all other clients are intact
    for client in remaining {
        assert_ne!(client.ip_address, delete_ip);
        assert!(ips.contains(&client.ip_address));
    }
}

#[tokio::test]
async fn test_delete_client_cascade_behavior() {
    let pool = create_test_db().await;
    let repo = SqliteClientRepository::new(pool);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    repo.update_last_seen(ip).await.unwrap();
    repo.update_mac_address(ip, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();
    repo.update_hostname(ip, "device.local".to_string())
        .await
        .unwrap();

    let client = repo.get_or_create(ip).await.unwrap();
    let client_id = client.id.unwrap();

    // Verify all data is present
    assert!(client.mac_address.is_some());
    assert!(client.hostname.is_some());

    // Delete client
    repo.delete(client_id).await.unwrap();

    // Try to get client by ID - should return None
    let result = repo.get_by_id(client_id).await.unwrap();
    assert!(result.is_none());

    // All associated data should be deleted with the client
    let all_clients = repo.get_all(100, 0).await.unwrap();
    assert!(!all_clients.iter().any(|c| c.ip_address == ip));
}
