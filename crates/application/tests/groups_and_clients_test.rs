use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_application::use_cases::{
    CreateGroupUseCase, DeleteGroupUseCase, UpdateClientUseCase,
};
use ferrous_dns_domain::{Client, DomainError};
use std::sync::Arc;

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
    let use_case = DeleteGroupUseCase::new(groups, engine.clone());

    use_case.execute(group.id.unwrap()).await.unwrap();

    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_delete_protected_group_does_not_reload_block_filter() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = DeleteGroupUseCase::new(Arc::new(MockGroupRepository::new()), engine.clone());

    let result = use_case.execute(1).await;

    assert!(matches!(
        result,
        Err(DomainError::ProtectedGroupCannotBeDeleted)
    ));
    assert_eq!(engine.reload_count().await, 0);
}
