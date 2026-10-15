use async_trait::async_trait;
use ferrous_dns_application::ports::{ArpReader, ArpTable, HostnameResolver};
use ferrous_dns_application::use_cases::{SyncArpCacheUseCase, SyncHostnamesUseCase};
use ferrous_dns_domain::{Client, DomainError};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

mod helpers;
use helpers::MockClientRepository;

fn make_client(id: i64, ip: &str) -> Client {
    let now = chrono::Utc::now().to_rfc3339();
    Client {
        id: Some(id),
        ip_address: ip.parse().unwrap(),
        mac_address: None,
        hostname: None,
        first_seen: Some(now.clone()),
        last_seen: Some(now),
        query_count: 1,
        last_mac_update: None,
        last_hostname_update: None,
        group_id: Some(1),
        comment: None,
    }
}

async fn client_by_ip(repo: &MockClientRepository, ip: &str) -> Option<Client> {
    let ip: IpAddr = ip.parse().unwrap();
    repo.get_all_clients()
        .await
        .into_iter()
        .find(|c| c.ip_address == ip)
}

#[derive(Default)]
struct MockArpReader {
    table: ArpTable,
}

impl MockArpReader {
    fn with_entries(entries: Vec<(&str, &str)>) -> Self {
        Self {
            table: entries
                .into_iter()
                .map(|(ip, mac)| (ip.parse().unwrap(), mac.to_string()))
                .collect(),
        }
    }
}

#[async_trait]
impl ArpReader for MockArpReader {
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError> {
        Ok(self.table.clone())
    }
}

#[derive(Default)]
struct MockHostnameResolver {
    responses: RwLock<HashMap<IpAddr, Option<String>>>,
    calls: AtomicU64,
    should_fail: AtomicBool,
}

impl MockHostnameResolver {
    async fn set_response(&self, ip: &str, hostname: Option<&str>) {
        self.responses
            .write()
            .await
            .insert(ip.parse().unwrap(), hostname.map(str::to_string));
    }

    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl HostnameResolver for MockHostnameResolver {
    async fn resolve_hostname(&self, ip: IpAddr) -> Result<Option<String>, DomainError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.should_fail.load(Ordering::Relaxed) {
            return Err(DomainError::IoError(
                "Hostname resolution failed".to_string(),
            ));
        }
        Ok(self.responses.read().await.get(&ip).cloned().flatten())
    }
}

#[tokio::test]
async fn test_arp_sync_updates_known_clients() {
    let repo =
        Arc::new(MockClientRepository::with_clients(vec![make_client(1, "192.168.1.10")]).await);
    let arp = Arc::new(MockArpReader::with_entries(vec![(
        "192.168.1.10",
        "aa:bb:cc:dd:ee:ff",
    )]));
    let use_case = SyncArpCacheUseCase::new(arp.clone(), repo.clone());

    let result = use_case.execute().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    let client = client_by_ip(&repo, "192.168.1.10").await.unwrap();
    assert_eq!(client.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
}

#[tokio::test]
async fn test_arp_sync_empty_table_returns_zero() {
    let repo = Arc::new(MockClientRepository::with_clients(Vec::new()).await);
    let arp = Arc::new(MockArpReader::default());
    let use_case = SyncArpCacheUseCase::new(arp, repo);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_arp_sync_unknown_ip_skipped() {
    let repo = Arc::new(MockClientRepository::with_clients(Vec::new()).await);
    let arp = Arc::new(MockArpReader::with_entries(vec![(
        "10.0.0.99",
        "ff:ee:dd:cc:bb:aa",
    )]));
    let use_case = SyncArpCacheUseCase::new(arp, repo.clone());

    let result = use_case.execute().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_arp_sync_multiple_entries() {
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
            make_client(3, "192.168.1.3"),
        ])
        .await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("192.168.1.1", "aa:aa:aa:aa:aa:01"),
        ("192.168.1.2", "aa:aa:aa:aa:aa:02"),
        ("192.168.1.3", "aa:aa:aa:aa:aa:03"),
    ]));
    let use_case = SyncArpCacheUseCase::new(arp, repo.clone());

    let result = use_case.execute().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    for (ip, mac) in [
        ("192.168.1.1", "aa:aa:aa:aa:aa:01"),
        ("192.168.1.2", "aa:aa:aa:aa:aa:02"),
        ("192.168.1.3", "aa:aa:aa:aa:aa:03"),
    ] {
        let client = client_by_ip(&repo, ip).await.unwrap();
        assert_eq!(client.mac_address.as_deref(), Some(mac));
    }
}

#[tokio::test]
async fn test_arp_sync_partial_match() {
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
            make_client(3, "192.168.1.3"),
        ])
        .await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("192.168.1.1", "aa:bb:cc:00:00:01"),
        ("192.168.1.2", "aa:bb:cc:00:00:02"),
    ]));
    let use_case = SyncArpCacheUseCase::new(arp, repo.clone());

    let result = use_case.execute().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 2);

    let client3 = client_by_ip(&repo, "192.168.1.3").await.unwrap();
    assert!(client3.mac_address.is_none());
}

#[tokio::test]
async fn test_hostname_sync_resolves_known_clients() {
    let client = make_client(1, "192.168.1.50");
    let repo = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let resolver = Arc::new(MockHostnameResolver::default());
    resolver
        .set_response("192.168.1.50", Some("my-device.local"))
        .await;

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver);

    let result = use_case.execute(10).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    let client = client_by_ip(&repo, "192.168.1.50").await.unwrap();
    assert_eq!(client.hostname.as_deref(), Some("my-device.local"));
}

#[tokio::test]
async fn test_hostname_sync_no_ptr_record_skips_client() {
    let client = make_client(1, "192.168.1.60");
    let repo = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let resolver = Arc::new(MockHostnameResolver::default());
    resolver.set_response("192.168.1.60", None).await;

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver);

    let result = use_case.execute(10).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    let client = client_by_ip(&repo, "192.168.1.60").await.unwrap();
    assert!(client.hostname.is_none());
}

#[tokio::test]
async fn test_hostname_sync_empty_repository() {
    let repo = Arc::new(MockClientRepository::with_clients(Vec::new()).await);
    let resolver = Arc::new(MockHostnameResolver::default());
    let use_case = SyncHostnamesUseCase::new(repo, resolver.clone());

    let result = use_case.execute(10).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(resolver.call_count(), 0);
}

#[tokio::test]
async fn test_hostname_sync_respects_batch_size() {
    let clients = (1..=5)
        .map(|i| make_client(i, &format!("192.168.1.{}", i + 10)))
        .collect();
    let repo = Arc::new(MockClientRepository::with_clients(clients).await);
    let resolver = Arc::new(MockHostnameResolver::default());

    for i in 1..=5 {
        resolver
            .set_response(
                &format!("192.168.1.{}", i + 10),
                Some(&format!("device-{}.local", i)),
            )
            .await;
    }

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver.clone());

    let result = use_case.execute(3).await;

    assert!(result.is_ok());
    assert!(result.unwrap() <= 3);
    assert!(resolver.call_count() <= 3);
}

#[tokio::test]
async fn test_hostname_sync_resolver_error_is_non_fatal() {
    let clients = vec![make_client(1, "192.168.1.100")];
    let repo = Arc::new(MockClientRepository::with_clients(clients).await);
    let resolver = Arc::new(MockHostnameResolver {
        should_fail: AtomicBool::new(true),
        ..MockHostnameResolver::default()
    });

    let use_case = SyncHostnamesUseCase::new(repo, resolver);

    let result = use_case.execute(10).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}
