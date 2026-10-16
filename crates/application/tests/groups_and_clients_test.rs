use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_application::use_cases::{
    CreateGroupUseCase, DeleteGroupUseCase, UpdateClientUseCase,
};
use ferrous_dns_domain::config::upstream::UpstreamPool;
use ferrous_dns_domain::{Client, Config, DomainError};
use std::sync::Arc;
use tokio::sync::RwLock;

mod helpers;
use helpers::{MockBlockFilterEngine, MockClientRepository, MockGroupRepository};

fn client_in_default_group(id: i64, ip: &str) -> Client {
    Client {
        id: Some(id),
        ip_address: ip.parse().unwrap(),
        mac_address: None,
        hostname: None,
        first_seen: None,
        last_seen: None,
        query_count: 0,
        last_mac_update: None,
        last_hostname_update: None,
        group_id: Some(1),
        comment: None,
    }
}

fn no_pools() -> Arc<RwLock<Config>> {
    Arc::new(RwLock::new(Config::default()))
}

#[tokio::test]
async fn test_update_client_rejects_unknown_group_and_keeps_assignment() {
    let clients = Arc::new(
        MockClientRepository::with_clients(vec![client_in_default_group(1, "10.0.0.5")]).await,
    );
    let use_case = UpdateClientUseCase::new(
        clients.clone(),
        Arc::new(MockGroupRepository::new()),
        Arc::new(MockBlockFilterEngine::new()),
    );

    let result = use_case.execute(1, None, Some(999)).await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
    let stored = clients.get_all_clients().await;
    assert_eq!(stored[0].group_id, Some(1));
}

#[tokio::test]
async fn test_create_group_honours_enabled_flag() {
    let use_case = CreateGroupUseCase::new(Arc::new(MockGroupRepository::new()));

    let disabled = use_case
        .execute("Kids".to_string(), None, false)
        .await
        .unwrap();
    let enabled = use_case
        .execute("Adults".to_string(), None, true)
        .await
        .unwrap();

    assert!(!disabled.enabled);
    assert!(enabled.enabled);
}

#[tokio::test]
async fn test_delete_group_reloads_block_filter() {
    let groups = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let group = groups.create("Kids".to_string(), None, true).await.unwrap();
    let use_case = DeleteGroupUseCase::new(groups, engine.clone(), no_pools());

    use_case.execute(group.id.unwrap()).await.unwrap();

    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_delete_group_routed_by_a_pool_is_refused() {
    let groups = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let group_id = groups
        .create("Office".to_string(), None, true)
        .await
        .unwrap()
        .id
        .unwrap();
    let mut config = Config::default();
    config.dns.pools.push(UpstreamPool {
        name: "office".to_string(),
        servers: vec!["udp://10.0.0.10:53".to_string()],
        domains: vec!["corp.example".to_string()],
        groups: vec![group_id],
        ..Default::default()
    });
    let use_case = DeleteGroupUseCase::new(
        groups.clone(),
        engine.clone(),
        Arc::new(RwLock::new(config)),
    );

    let result = use_case.execute(group_id).await;

    assert!(
        matches!(&result, Err(DomainError::GroupRoutedByPool(pool)) if pool == "office"),
        "got {result:?}"
    );
    assert!(groups.get_by_id(group_id).await.unwrap().is_some());
    assert_eq!(engine.reload_count().await, 0);
}

#[tokio::test]
async fn test_delete_protected_group_does_not_reload_block_filter() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = DeleteGroupUseCase::new(
        Arc::new(MockGroupRepository::new()),
        engine.clone(),
        no_pools(),
    );

    let result = use_case.execute(1).await;

    assert!(matches!(
        result,
        Err(DomainError::ProtectedGroupCannotBeDeleted)
    ));
    assert_eq!(engine.reload_count().await, 0);
}
