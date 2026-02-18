use ferrous_dns_application::use_cases::{SyncArpCacheUseCase, SyncHostnamesUseCase};
use ferrous_dns_jobs::ClientSyncJob;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

mod helpers;
use helpers::{make_client, MockArpReader, MockClientRepository, MockHostnameResolver};

#[tokio::test]
async fn test_arp_sync_updates_known_clients() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![make_client(1, "192.168.1.10")]).await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("192.168.1.10", "aa:bb:cc:dd:ee:ff"),
    ]));
    let use_case = SyncArpCacheUseCase::new(arp.clone(), repo.clone());

    let result = use_case.execute().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    let client = repo.get_client_by_ip("192.168.1.10").await.unwrap();
    assert_eq!(
        client.mac_address.as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
}

#[tokio::test]
async fn test_arp_sync_empty_table_returns_zero() {
    
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::new());
    let use_case = SyncArpCacheUseCase::new(arp, repo);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_arp_sync_unknown_ip_skipped() {
    
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("10.0.0.99", "ff:ee:dd:cc:bb:aa"),
    ]));
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
    assert_eq!(repo.mac_update_count(), 3);
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

    let client3 = repo.get_client_by_ip("192.168.1.3").await.unwrap();
    assert!(client3.mac_address.is_none());
}

#[tokio::test]
async fn test_hostname_sync_resolves_known_clients() {
    
    let client = make_client(1, "192.168.1.50");
    let repo = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver
        .set_response("192.168.1.50", Some("my-device.local"))
        .await;

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver);

    let result = use_case.execute(10).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    let client = repo.get_client_by_ip("192.168.1.50").await.unwrap();
    assert_eq!(client.hostname.as_deref(), Some("my-device.local"));
}

#[tokio::test]
async fn test_hostname_sync_no_ptr_record_skips_client() {
    
    let client = make_client(1, "192.168.1.60");
    let repo = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver.set_response("192.168.1.60", None).await;

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver);

    let result = use_case.execute(10).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    let client = repo.get_client_by_ip("192.168.1.60").await.unwrap();
    assert!(client.hostname.is_none());
}

#[tokio::test]
async fn test_hostname_sync_empty_repository() {
    
    let repo = Arc::new(MockClientRepository::new());
    let resolver = Arc::new(MockHostnameResolver::new());
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
    let resolver = Arc::new(MockHostnameResolver::new());
    
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
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver.set_should_fail(true).await;

    let use_case = SyncHostnamesUseCase::new(repo, resolver);

    let result = use_case.execute(10).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_client_sync_job_starts_without_panic() {
    
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::new());
    let resolver = Arc::new(MockHostnameResolver::new());

    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp, repo.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo, resolver));

    let job = Arc::new(ClientSyncJob::new(sync_arp, sync_hostnames));

    job.start().await;

    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_client_sync_job_with_custom_intervals() {
    
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![make_client(1, "10.0.0.1")]).await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("10.0.0.1", "de:ad:be:ef:00:01"),
    ]));
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver.set_response("10.0.0.1", Some("router.local")).await;

    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp.clone(), repo.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo.clone(), resolver.clone()));

    let job = Arc::new(
        ClientSyncJob::new(sync_arp, sync_hostnames).with_intervals(1, 1), 
    );

    job.start().await;

    sleep(Duration::from_millis(1100)).await;

    assert!(arp.call_count() >= 1, "ARP sync should have run at least once");
}
