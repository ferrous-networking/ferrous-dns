//! mDNS announcements name the clients that sent them. They repeat every few
//! minutes on a busy network, so an unchanged name is written at most once an
//! hour, and an address that is not a client is looked up again only after
//! five minutes.

use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_application::use_cases::RecordMdnsHostnamesUseCase;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

mod helpers;
use helpers::MockClientRepository;

const PHONE: &str = "192.168.1.20";

fn phone() -> IpAddr {
    PHONE.parse().unwrap()
}

fn announced(name: &str) -> Vec<(IpAddr, Arc<str>)> {
    vec![(phone(), Arc::from(name))]
}

async fn recorder_with_phone() -> (RecordMdnsHostnamesUseCase, Arc<MockClientRepository>) {
    let repo = Arc::new(MockClientRepository::new());
    repo.get_or_create(phone()).await.unwrap();
    let recorder = RecordMdnsHostnamesUseCase::new(Arc::clone(&repo) as Arc<dyn ClientRepository>);
    (recorder, repo)
}

async fn hostname(repo: &MockClientRepository) -> Option<String> {
    repo.get_by_ip(phone())
        .await
        .unwrap()
        .and_then(|c| c.hostname)
        .map(|h| h.to_string())
}

#[tokio::test]
async fn a_known_client_is_named_after_its_announcement() {
    let (recorder, repo) = recorder_with_phone().await;

    assert_eq!(
        recorder.execute(&announced("iPhone-de-Ana")).await.unwrap(),
        1
    );

    assert_eq!(hostname(&repo).await.as_deref(), Some("iPhone-de-Ana"));
}

#[tokio::test]
async fn an_address_that_is_not_a_client_is_not_added() {
    let repo = Arc::new(MockClientRepository::new());
    let recorder = RecordMdnsHostnamesUseCase::new(Arc::clone(&repo) as Arc<dyn ClientRepository>);

    assert_eq!(
        recorder.execute(&announced("HP-LaserJet")).await.unwrap(),
        0
    );

    assert_eq!(repo.count().await, 0);
}

#[tokio::test(start_paused = true)]
async fn an_unchanged_name_is_written_again_only_after_an_hour() {
    let (recorder, _repo) = recorder_with_phone().await;

    assert_eq!(recorder.execute(&announced("iPhone")).await.unwrap(), 1);
    tokio::time::advance(Duration::from_secs(59 * 60)).await;
    assert_eq!(recorder.execute(&announced("iPhone")).await.unwrap(), 0);
    tokio::time::advance(Duration::from_secs(2 * 60)).await;
    assert_eq!(recorder.execute(&announced("iPhone")).await.unwrap(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_changed_name_is_written_at_once() {
    let (recorder, repo) = recorder_with_phone().await;

    recorder.execute(&announced("iPhone")).await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;

    assert_eq!(recorder.execute(&announced("iPhone-2")).await.unwrap(), 1);
    assert_eq!(hostname(&repo).await.as_deref(), Some("iPhone-2"));
}

/// A device that starts using this server after announcing is named by a
/// later announcement.
#[tokio::test(start_paused = true)]
async fn an_address_that_becomes_a_client_is_named_within_five_minutes() {
    let repo = Arc::new(MockClientRepository::new());
    let recorder = RecordMdnsHostnamesUseCase::new(Arc::clone(&repo) as Arc<dyn ClientRepository>);
    assert_eq!(recorder.execute(&announced("iPhone")).await.unwrap(), 0);

    repo.get_or_create(phone()).await.unwrap();
    assert_eq!(recorder.execute(&announced("iPhone")).await.unwrap(), 0);
    tokio::time::advance(Duration::from_secs(5 * 60 + 1)).await;

    assert_eq!(recorder.execute(&announced("iPhone")).await.unwrap(), 1);
    assert_eq!(hostname(&repo).await.as_deref(), Some("iPhone"));
}
