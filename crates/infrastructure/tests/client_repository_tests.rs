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

    // Run migration
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
