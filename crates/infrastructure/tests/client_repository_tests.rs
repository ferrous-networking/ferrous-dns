#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{DomainError, HostnameSource};
use ferrous_dns_infrastructure::repositories::client_repository::SqliteClientRepository;
use std::net::IpAddr;
use std::sync::Arc;

async fn repo() -> (SqliteClientRepository, sqlx::SqlitePool) {
    let pool = db::migrated_pool().await;
    (
        SqliteClientRepository::new(pool.clone(), &DatabaseConfig::default()),
        pool,
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

async fn seen(repo: &SqliteClientRepository, count: u8) {
    for i in 1..=count {
        repo.update_last_seen(ip(&format!("192.168.1.{i}")))
            .await
            .unwrap();
    }
    repo.flush_writes().await;
}

#[tokio::test]
async fn test_update_last_seen_creates_client() {
    let (repo, _pool) = repo().await;

    repo.update_last_seen(ip("192.168.1.100")).await.unwrap();
    repo.flush_writes().await;

    let client = repo.get_or_create(ip("192.168.1.100")).await.unwrap();
    assert_eq!(client.ip_address, ip("192.168.1.100"));
    assert_eq!(client.query_count, 1);
}

#[tokio::test]
async fn test_update_last_seen_increments_count() {
    let (repo, _pool) = repo().await;
    let addr = ip("192.168.1.100");

    for _ in 0..3 {
        repo.update_last_seen(addr).await.unwrap();
    }
    repo.flush_writes().await;

    let client = repo.get_or_create(addr).await.unwrap();
    assert_eq!(client.query_count, 3);
}

#[tokio::test]
async fn test_get_or_create_new_client_starts_at_zero_queries() {
    let (repo, _pool) = repo().await;

    let client = repo.get_or_create(ip("2001:db8::1")).await.unwrap();

    assert_eq!(client.ip_address, ip("2001:db8::1"));
    assert_eq!(client.query_count, 0);
    assert_eq!(client.group_id, None);
}

#[tokio::test]
async fn test_update_mac_address() {
    let (repo, _pool) = repo().await;
    let addr = ip("192.168.1.100");
    repo.update_last_seen(addr).await.unwrap();
    repo.flush_writes().await;

    repo.update_mac_address(addr, "aa:bb:cc:dd:ee:ff".to_string())
        .await
        .unwrap();

    let client = repo.get_or_create(addr).await.unwrap();
    assert_eq!(client.mac_address, Some(Arc::from("aa:bb:cc:dd:ee:ff")));
    assert!(client.last_mac_update.is_some());
}

#[tokio::test]
async fn test_batch_update_mac_addresses_counts_only_known_clients() {
    let (repo, _pool) = repo().await;
    seen(&repo, 2).await;

    let updated = repo
        .batch_update_mac_addresses(vec![
            (ip("192.168.1.1"), "aa:aa:aa:aa:aa:01".to_string()),
            (ip("192.168.1.2"), "aa:aa:aa:aa:aa:02".to_string()),
            (ip("192.168.1.99"), "aa:aa:aa:aa:aa:99".to_string()),
        ])
        .await
        .unwrap();

    assert_eq!(updated, 2);
    let client = repo.get_or_create(ip("192.168.1.2")).await.unwrap();
    assert_eq!(client.mac_address, Some(Arc::from("aa:aa:aa:aa:aa:02")));
}

#[tokio::test]
async fn test_update_hostname() {
    let (repo, _pool) = repo().await;
    let addr = ip("192.168.1.100");
    repo.update_last_seen(addr).await.unwrap();
    repo.flush_writes().await;

    repo.update_hostname(addr, "my-device.local".to_string(), HostnameSource::Ptr)
        .await
        .unwrap();

    let client = repo.get_or_create(addr).await.unwrap();
    assert_eq!(client.hostname, Some(Arc::from("my-device.local")));
    assert!(client.last_hostname_update.is_some());
}

#[tokio::test]
async fn test_ptr_name_never_replaces_a_manual_one() {
    let (repo, _pool) = repo().await;
    let addr = ip("192.168.1.100");
    repo.get_or_create(addr).await.unwrap();

    repo.update_hostname(addr, "Living room TV".into(), HostnameSource::Manual)
        .await
        .unwrap();
    repo.update_hostname(addr, "android-3f2a.lan".into(), HostnameSource::Ptr)
        .await
        .unwrap();

    let client = repo.get_or_create(addr).await.unwrap();
    assert_eq!(client.hostname, Some(Arc::from("Living room TV")));
}

#[tokio::test]
async fn test_manual_name_replaces_a_ptr_one_and_another_manual_one() {
    let (repo, _pool) = repo().await;
    let addr = ip("192.168.1.100");
    repo.get_or_create(addr).await.unwrap();

    repo.update_hostname(addr, "android-3f2a.lan".into(), HostnameSource::Ptr)
        .await
        .unwrap();
    repo.update_hostname(addr, "TV".into(), HostnameSource::Manual)
        .await
        .unwrap();
    repo.update_hostname(addr, "Living room TV".into(), HostnameSource::Manual)
        .await
        .unwrap();

    let client = repo.get_or_create(addr).await.unwrap();
    assert_eq!(client.hostname, Some(Arc::from("Living room TV")));
}

/// Writes `(name, source)` in order and returns the name the client ends with.
async fn name_after(writes: &[(&str, HostnameSource)]) -> Option<Arc<str>> {
    let (repo, _pool) = repo().await;
    let addr = ip("192.168.1.100");
    repo.get_or_create(addr).await.unwrap();
    for (name, source) in writes {
        repo.update_hostname(addr, name.to_string(), *source)
            .await
            .unwrap();
    }
    repo.get_or_create(addr).await.unwrap().hostname
}

#[tokio::test]
async fn test_hostname_precedence_is_manual_then_mdns_then_ptr() {
    use HostnameSource::{Manual, Mdns, Ptr};

    let cases: [(&[(&str, HostnameSource)], &str); 6] = [
        (&[("ptr.lan", Ptr), ("iPhone", Mdns)], "iPhone"),
        (&[("iPhone", Mdns), ("ptr.lan", Ptr)], "iPhone"),
        (&[("iPhone", Mdns), ("iPhone-2", Mdns)], "iPhone-2"),
        (&[("TV", Manual), ("iPhone", Mdns)], "TV"),
        (&[("iPhone", Mdns), ("TV", Manual)], "TV"),
        (&[("TV", Manual), ("ptr.lan", Ptr)], "TV"),
    ];
    for (writes, expected) in cases {
        assert_eq!(
            name_after(writes).await.as_deref(),
            Some(expected),
            "{writes:?}"
        );
    }
}

/// A device that stopped announcing its name gives it back to PTR after a
/// day, so an address DHCP moved to another device does not keep a stale name.
#[tokio::test]
async fn test_ptr_takes_back_an_mdns_name_after_a_day() {
    let (repo, pool) = repo().await;
    let fresh = ip("192.168.1.1");
    let stale = ip("192.168.1.2");
    seen(&repo, 2).await;
    for addr in [fresh, stale] {
        repo.update_hostname(addr, "iPhone".into(), HostnameSource::Mdns)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE clients SET last_hostname_update = datetime('now', '-2 hours') WHERE ip_address = '192.168.1.1'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE clients SET last_hostname_update = datetime('now', '-2 days') WHERE ip_address = '192.168.1.2'")
        .execute(&pool)
        .await
        .unwrap();

    let needs: Vec<IpAddr> = repo
        .get_needs_hostname_update(10)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.ip_address)
        .collect();
    assert_eq!(needs, vec![stale], "only the stale mDNS name is looked up");

    for addr in [fresh, stale] {
        repo.update_hostname(addr, "ptr.lan".into(), HostnameSource::Ptr)
            .await
            .unwrap();
    }
    assert_eq!(
        repo.get_or_create(fresh).await.unwrap().hostname.as_deref(),
        Some("iPhone")
    );
    assert_eq!(
        repo.get_or_create(stale).await.unwrap().hostname.as_deref(),
        Some("ptr.lan")
    );
}

#[tokio::test]
async fn test_get_all_with_pagination() {
    let (repo, _pool) = repo().await;
    seen(&repo, 10).await;

    let first = repo.get_all(5, 0).await.unwrap();
    let second = repo.get_all(5, 5).await.unwrap();

    assert_eq!(first.len(), 5);
    assert_eq!(second.len(), 5);
    assert!(first.iter().all(|a| second.iter().all(|b| a.id != b.id)));
}

#[tokio::test]
async fn test_get_active_clients() {
    let (repo, pool) = repo().await;
    seen(&repo, 5).await;

    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-31 days') WHERE ip_address IN ('192.168.1.1', '192.168.1.2')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let active = repo.get_active(30, 100).await.unwrap();
    assert_eq!(active.len(), 3);
}

#[tokio::test]
async fn test_count_active_since_uses_hour_window() {
    let (repo, pool) = repo().await;
    seen(&repo, 3).await;

    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-2 hours') WHERE ip_address = '192.168.1.1'",
    )
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(repo.count_active_since(1.0).await.unwrap(), 2);
    assert_eq!(repo.count_active_since(3.0).await.unwrap(), 3);
}

#[tokio::test]
async fn test_get_stats() {
    let (repo, _pool) = repo().await;
    seen(&repo, 5).await;

    for i in 1..=3u8 {
        repo.update_mac_address(
            ip(&format!("192.168.1.{i}")),
            format!("aa:bb:cc:dd:ee:{i:02x}"),
        )
        .await
        .unwrap();
    }
    for i in 1..=2u8 {
        repo.update_hostname(
            ip(&format!("192.168.1.{i}")),
            format!("device-{i}.local"),
            HostnameSource::Ptr,
        )
        .await
        .unwrap();
    }

    let stats = repo.get_stats().await.unwrap();
    assert_eq!(stats.total_clients, 5);
    assert_eq!(stats.active_24h, 5);
    assert_eq!(stats.with_mac, 3);
    assert_eq!(stats.with_hostname, 2);
}

#[tokio::test]
async fn test_delete_older_than() {
    let (repo, pool) = repo().await;
    seen(&repo, 5).await;

    sqlx::query(
        "UPDATE clients SET last_seen = datetime('now', '-31 days') WHERE ip_address IN ('192.168.1.1', '192.168.1.2')",
    )
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(repo.delete_older_than(30).await.unwrap(), 2);
    assert_eq!(repo.get_stats().await.unwrap().total_clients, 3);
}

#[tokio::test]
async fn test_get_needs_mac_update() {
    let (repo, pool) = repo().await;
    seen(&repo, 3).await;

    repo.update_mac_address(ip("192.168.1.1"), "aa:bb:cc:dd:ee:01".to_string())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE clients SET last_mac_update = datetime('now', '-10 minutes') WHERE ip_address = '192.168.1.2'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let mut needs: Vec<IpAddr> = repo
        .get_needs_mac_update(10)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.ip_address)
        .collect();
    needs.sort();

    assert_eq!(needs, vec![ip("192.168.1.2"), ip("192.168.1.3")]);
}

#[tokio::test]
async fn test_get_needs_hostname_update() {
    let (repo, pool) = repo().await;
    seen(&repo, 4).await;

    repo.update_hostname(
        ip("192.168.1.1"),
        "device1.local".to_string(),
        HostnameSource::Ptr,
    )
    .await
    .unwrap();
    repo.update_hostname(
        ip("192.168.1.4"),
        "Printer".to_string(),
        HostnameSource::Manual,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE clients SET last_hostname_update = datetime('now', '-2 hours') WHERE ip_address IN ('192.168.1.2', '192.168.1.4')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let mut needs: Vec<IpAddr> = repo
        .get_needs_hostname_update(10)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.ip_address)
        .collect();
    needs.sort();

    // .4 was named by hand, so the sync never looks it up again.
    assert_eq!(needs, vec![ip("192.168.1.2"), ip("192.168.1.3")]);
}

#[tokio::test]
async fn test_assign_group_sets_group() {
    let (repo, pool) = repo().await;
    sqlx::query("INSERT INTO groups (id, name) VALUES (2, 'Kids')")
        .execute(&pool)
        .await
        .unwrap();
    let client = repo.get_or_create(ip("192.168.1.10")).await.unwrap();
    let id = client.id.unwrap();

    repo.assign_group(id, 2).await.unwrap();

    assert_eq!(repo.get_by_id(id).await.unwrap().unwrap().group_id, Some(2));
}

#[tokio::test]
async fn test_assign_group_missing_group_returns_group_not_found() {
    let (repo, _pool) = repo().await;
    let client = repo.get_or_create(ip("192.168.1.10")).await.unwrap();

    let result = repo.assign_group(client.id.unwrap(), 999).await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_assign_group_missing_client_returns_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo.assign_group(9999, 1).await;

    assert!(matches!(result, Err(DomainError::NotFound(_))));
}

#[tokio::test]
async fn test_delete_existing_client() {
    let (repo, _pool) = repo().await;
    let client = repo.get_or_create(ip("192.168.1.100")).await.unwrap();
    let client_id = client.id.unwrap();

    repo.delete(client_id).await.unwrap();

    assert!(repo.get_by_id(client_id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_nonexistent_client() {
    let (repo, _pool) = repo().await;

    match repo.delete(9999).await {
        Err(DomainError::NotFound(msg)) => assert!(msg.contains("9999")),
        other => panic!("Expected NotFound error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_delete_preserves_other_clients() {
    let (repo, _pool) = repo().await;
    seen(&repo, 10).await;

    let all_clients = repo.get_all(100, 0).await.unwrap();
    let delete_id = all_clients[5].id.unwrap();
    let delete_ip = all_clients[5].ip_address;

    repo.delete(delete_id).await.unwrap();

    let remaining = repo.get_all(100, 0).await.unwrap();
    assert_eq!(remaining.len(), 9);
    assert!(remaining.iter().all(|c| c.ip_address != delete_ip));
}
