use ferrous_dns_application::use_cases::{
    CleanupOldClientsUseCase, SyncArpCacheUseCase, SyncHostnamesUseCase,
};
use ferrous_dns_jobs::{ClientSyncJob, JobRunner, RetentionJob};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

mod helpers;
use helpers::{
    make_client, make_old_client, MockArpReader, MockClientRepository, MockHostnameResolver,
};

fn make_client_sync_job(
    repo: Arc<MockClientRepository>,
    arp: Arc<MockArpReader>,
    resolver: Arc<MockHostnameResolver>,
) -> ClientSyncJob {
    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp, repo.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo, resolver));
    ClientSyncJob::new(sync_arp, sync_hostnames)
}

fn make_retention_job(repo: Arc<MockClientRepository>, retention_days: u32) -> RetentionJob {
    let cleanup = Arc::new(CleanupOldClientsUseCase::new(repo));
    RetentionJob::new(cleanup, retention_days)
}

#[tokio::test]
async fn test_job_runner_empty_starts_cleanly() {
    JobRunner::new().start().await;
}

#[tokio::test]
async fn test_job_runner_with_only_client_sync() {
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::new());
    let resolver = Arc::new(MockHostnameResolver::new());

    let job = make_client_sync_job(repo, arp, resolver);

    JobRunner::new().with_client_sync(job).start().await;
    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_job_runner_with_only_retention() {
    let repo = Arc::new(MockClientRepository::new());
    let job = make_retention_job(repo, 30);

    JobRunner::new().with_retention(job).start().await;
    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_job_runner_with_all_jobs() {
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::new());
    let resolver = Arc::new(MockHostnameResolver::new());

    let client_sync = make_client_sync_job(repo.clone(), arp, resolver);
    let retention = make_retention_job(repo, 30);

    JobRunner::new()
        .with_client_sync(client_sync)
        .with_retention(retention)
        .start()
        .await;

    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_job_runner_client_sync_fires_arp() {
    let repo =
        Arc::new(MockClientRepository::with_clients(vec![make_client(1, "192.168.1.200")]).await);
    let arp = Arc::new(MockArpReader::with_entries(vec![(
        "192.168.1.200",
        "ca:fe:ba:be:00:01",
    )]));
    let resolver = Arc::new(MockHostnameResolver::new());

    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp.clone(), repo.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo.clone(), resolver.clone()));

    let client_sync = ClientSyncJob::new(sync_arp, sync_hostnames).with_intervals(1, 3600);

    JobRunner::new().with_client_sync(client_sync).start().await;

    sleep(Duration::from_millis(1100)).await;

    assert!(arp.call_count() >= 1);

    let client = repo.get_client_by_ip("192.168.1.200").await.unwrap();
    assert_eq!(client.mac_address.as_deref(), Some("ca:fe:ba:be:00:01"));
}

#[tokio::test]
async fn test_job_runner_retention_fires_and_cleans() {
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_old_client(2, "192.168.1.2", 45),
        ])
        .await,
    );

    let cleanup = Arc::new(CleanupOldClientsUseCase::new(repo.clone()));
    let retention = RetentionJob::new(cleanup, 30).with_interval(1);

    JobRunner::new().with_retention(retention).start().await;

    sleep(Duration::from_millis(1100)).await;

    assert_eq!(repo.count().await, 1);
    assert!(repo.get_client_by_ip("192.168.1.1").await.is_some());
    assert!(repo.get_client_by_ip("192.168.1.2").await.is_none());
}

#[tokio::test]
async fn test_job_runner_both_jobs_run_concurrently() {
    let repo_sync =
        Arc::new(MockClientRepository::with_clients(vec![make_client(1, "10.0.0.1")]).await);
    let repo_retention = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "10.0.0.10"),
            make_old_client(2, "10.0.0.20", 60),
        ])
        .await,
    );

    let arp = Arc::new(MockArpReader::with_entries(vec![(
        "10.0.0.1",
        "00:11:22:33:44:55",
    )]));
    let resolver = Arc::new(MockHostnameResolver::new());

    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp.clone(), repo_sync.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo_sync.clone(), resolver));
    let client_sync = ClientSyncJob::new(sync_arp, sync_hostnames).with_intervals(1, 3600);

    let cleanup = Arc::new(CleanupOldClientsUseCase::new(repo_retention.clone()));
    let retention = RetentionJob::new(cleanup, 30).with_interval(1);

    JobRunner::new()
        .with_client_sync(client_sync)
        .with_retention(retention)
        .start()
        .await;

    sleep(Duration::from_millis(1200)).await;

    assert!(arp.call_count() >= 1);
    let client = repo_sync.get_client_by_ip("10.0.0.1").await.unwrap();
    assert_eq!(client.mac_address.as_deref(), Some("00:11:22:33:44:55"));

    assert_eq!(repo_retention.count().await, 1);
    assert!(repo_retention.get_client_by_ip("10.0.0.10").await.is_some());
    assert!(repo_retention.get_client_by_ip("10.0.0.20").await.is_none());
}

#[tokio::test]
async fn test_job_runner_builder_is_chainable() {
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::new());
    let resolver = Arc::new(MockHostnameResolver::new());

    let runner = JobRunner::new()
        .with_client_sync(make_client_sync_job(repo.clone(), arp, resolver))
        .with_retention(make_retention_job(repo, 7));

    runner.start().await;
}
