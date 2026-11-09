//! A request carrying a DoH Client ID resolves its group from the ID when the
//! ID is registered, and from the connecting address otherwise; and it leaves
//! the IP-based `clients` table alone.

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsRequest, RecordType};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

mod helpers;
use helpers::{
    MockBlockFilterEngine, MockClientRepository, MockDnsResolver, MockQueryLogRepository,
};

const IP_GROUP: i64 = 2;
const DOH_ID_GROUP: i64 = 3;
const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 42));
const DOMAIN: &str = "example.org";

async fn resolver() -> Arc<MockDnsResolver> {
    let resolver = Arc::new(MockDnsResolver::new());
    resolver
        .set_response(
            DOMAIN,
            DnsResolution::new(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))], false),
        )
        .await;
    resolver
}

fn filter() -> Arc<MockBlockFilterEngine> {
    let filter = MockBlockFilterEngine::new();
    filter.set_client_group(IP_GROUP);
    filter.set_doh_id_group("kids-tablet", DOH_ID_GROUP);
    Arc::new(filter)
}

async fn groups_seen_for(request: DnsRequest) -> Vec<Option<i64>> {
    let resolver = resolver().await;
    HandleDnsQueryUseCase::new(
        resolver.clone(),
        filter(),
        Arc::new(MockQueryLogRepository::new()),
    )
    .execute(&request)
    .await
    .unwrap();
    resolver
        .seen_groups()
        .into_iter()
        .map(|(_, group)| group)
        .collect()
}

#[tokio::test]
async fn test_registered_doh_client_id_takes_its_group_over_the_ip_group() {
    let request =
        DnsRequest::new(DOMAIN, RecordType::A, CLIENT_IP).with_doh_client_id("kids-tablet");

    let groups = groups_seen_for(request).await;

    assert!(!groups.is_empty());
    assert!(groups.iter().all(|g| *g == Some(DOH_ID_GROUP)));
}

#[tokio::test]
async fn test_unregistered_doh_client_id_keeps_the_ip_group() {
    let request =
        DnsRequest::new(DOMAIN, RecordType::A, CLIENT_IP).with_doh_client_id("made-up-id");

    let groups = groups_seen_for(request).await;

    assert!(!groups.is_empty());
    assert!(groups.iter().all(|g| *g == Some(IP_GROUP)));
}

#[tokio::test]
async fn test_request_without_doh_client_id_uses_the_ip_group() {
    let groups = groups_seen_for(DnsRequest::new(DOMAIN, RecordType::A, CLIENT_IP)).await;

    assert!(!groups.is_empty());
    assert!(groups.iter().all(|g| *g == Some(IP_GROUP)));
}

#[tokio::test]
async fn test_request_with_doh_client_id_is_not_tracked_as_an_ip_client() {
    let client_repo = Arc::new(MockClientRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        resolver().await,
        filter(),
        Arc::new(MockQueryLogRepository::new()),
    )
    .with_client_tracking(client_repo.clone(), 0);

    use_case
        .execute(
            &DnsRequest::new(DOMAIN, RecordType::A, CLIENT_IP).with_doh_client_id("kids-tablet"),
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(client_repo.get_all_clients().await.is_empty());
}
