use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_application::use_cases::{
    CreateGroupUseCase, DeleteGroupUseCase, UpdateClientUseCase, UpdateGroupUseCase,
};
use ferrous_dns_domain::config::upstream::UpstreamPool;
use ferrous_dns_domain::{Client, Config, DomainError};
use std::sync::Arc;
use tokio::sync::RwLock;

mod helpers;
use helpers::{
    MockBlockFilterEngine, MockClientRepository, MockGroupRepository, MockMalwareExemptions,
};

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

fn exemptions() -> Arc<MockMalwareExemptions> {
    Arc::new(MockMalwareExemptions::new())
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
    let use_case = CreateGroupUseCase::new(Arc::new(MockGroupRepository::new()), exemptions());

    let disabled = use_case
        .execute("Kids".to_string(), None, false, true)
        .await
        .unwrap();
    let enabled = use_case
        .execute("Adults".to_string(), None, true, true)
        .await
        .unwrap();

    assert!(!disabled.enabled);
    assert!(enabled.enabled);
}

/// The query path reads the exempt groups from memory, so a group created
/// with the detectors off must reach it at once; one created with them on
/// changes nothing there.
#[tokio::test]
async fn test_create_group_with_malware_detection_off_reloads_the_exemptions() {
    let exempt = exemptions();
    let use_case = CreateGroupUseCase::new(Arc::new(MockGroupRepository::new()), exempt.clone());

    let servers = use_case
        .execute("Servers".to_string(), None, true, false)
        .await
        .unwrap();
    assert!(!servers.malware_detection_enabled);
    assert_eq!(exempt.reload_count(), 1);

    let kids = use_case
        .execute("Kids".to_string(), None, true, true)
        .await
        .unwrap();
    assert!(kids.malware_detection_enabled);
    assert_eq!(exempt.reload_count(), 1, "a group with the detectors on");
}

#[tokio::test]
async fn test_update_group_toggling_malware_detection_reloads_the_exemptions() {
    let groups = Arc::new(MockGroupRepository::new());
    let exempt = exemptions();
    let use_case = UpdateGroupUseCase::new(
        groups.clone(),
        Arc::new(MockBlockFilterEngine::new()),
        exempt.clone(),
    );

    let updated = use_case
        .execute(1, None, None, None, Some(false))
        .await
        .unwrap();
    assert!(!updated.malware_detection_enabled, "the default group too");
    assert_eq!(exempt.reload_count(), 1);

    let renamed = use_case
        .execute(1, Some("Home".to_string()), None, None, None)
        .await
        .unwrap();
    assert!(
        !renamed.malware_detection_enabled,
        "an omitted flag is kept"
    );
    assert_eq!(exempt.reload_count(), 1, "nothing to reload");
}

/// The DNS path reads which group each client resolves to from memory, so
/// switching a group off or on must reload it; saving the flag a group
/// already has changes nothing there.
#[tokio::test]
async fn test_update_group_toggling_enabled_reloads_client_groups() {
    let groups = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let kids = CreateGroupUseCase::new(groups.clone(), exemptions())
        .execute("Kids".to_string(), None, true, true)
        .await
        .unwrap()
        .id
        .unwrap();
    let use_case = UpdateGroupUseCase::new(groups.clone(), engine.clone(), exemptions());

    let disabled = use_case
        .execute(kids, None, Some(false), None, None)
        .await
        .unwrap();
    assert!(!disabled.enabled);
    assert_eq!(engine.load_client_groups_count().await, 1);

    use_case
        .execute(kids, None, Some(false), None, None)
        .await
        .unwrap();
    use_case
        .execute(kids, Some("Children".to_string()), None, None, None)
        .await
        .unwrap();
    assert_eq!(
        engine.load_client_groups_count().await,
        1,
        "nothing to reload"
    );

    use_case
        .execute(kids, None, Some(true), None, None)
        .await
        .unwrap();
    assert_eq!(engine.load_client_groups_count().await, 2);
}

/// The row is written before the exemptions reload, so a failed reload must
/// not report the change as failed: the API would answer 500 for a saved
/// group, and a retried create would get "already exists".
#[tokio::test]
async fn test_create_and_update_group_succeed_when_the_exemption_reload_fails() {
    let groups = Arc::new(MockGroupRepository::new());
    let exempt = exemptions();
    exempt.fail_reloads();
    let create = CreateGroupUseCase::new(groups.clone(), exempt.clone());
    let update = UpdateGroupUseCase::new(
        groups.clone(),
        Arc::new(MockBlockFilterEngine::new()),
        exempt.clone(),
    );

    let created = create
        .execute("Servers".to_string(), None, true, false)
        .await;
    let updated = update.execute(1, None, None, None, Some(false)).await;

    assert!(
        created.as_ref().is_ok_and(|g| !g.malware_detection_enabled),
        "{created:?}"
    );
    assert!(
        updated.as_ref().is_ok_and(|g| !g.malware_detection_enabled),
        "{updated:?}"
    );
    assert_eq!(exempt.reload_count(), 2, "both still tried the reload");
}

#[tokio::test]
async fn test_delete_group_exempt_from_malware_detection_reloads_the_exemptions() {
    let groups = Arc::new(MockGroupRepository::new());
    let exempt = exemptions();
    let servers = groups
        .create("Servers".to_string(), None, true, false)
        .await
        .unwrap();
    let kids = groups
        .create("Kids".to_string(), None, true, true)
        .await
        .unwrap();
    let use_case = DeleteGroupUseCase::new(
        groups,
        Arc::new(MockBlockFilterEngine::new()),
        exempt.clone(),
        no_pools(),
    );

    use_case.execute(kids.id.unwrap()).await.unwrap();
    assert_eq!(exempt.reload_count(), 0, "kids was not exempt");

    use_case.execute(servers.id.unwrap()).await.unwrap();
    assert_eq!(exempt.reload_count(), 1);
}

#[tokio::test]
async fn test_delete_group_reloads_block_filter() {
    let groups = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let group = groups
        .create("Kids".to_string(), None, true, true)
        .await
        .unwrap();
    let use_case = DeleteGroupUseCase::new(groups, engine.clone(), exemptions(), no_pools());

    use_case.execute(group.id.unwrap()).await.unwrap();

    assert_eq!(engine.reload_count().await, 1);
    assert_eq!(engine.load_client_groups_count().await, 1);
}

#[tokio::test]
async fn test_delete_group_with_assigned_doh_ids_is_refused() {
    let groups = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let group_id = groups
        .create("Kids".to_string(), None, true, true)
        .await
        .unwrap()
        .id
        .unwrap();
    groups.set_doh_id_count(group_id, 2).await;
    let use_case =
        DeleteGroupUseCase::new(groups.clone(), engine.clone(), exemptions(), no_pools());

    let result = use_case.execute(group_id).await;

    assert!(
        matches!(result, Err(DomainError::GroupHasAssignedDohIds(2))),
        "got {result:?}"
    );
    assert!(groups.get_by_id(group_id).await.unwrap().is_some());
    assert_eq!(engine.reload_count().await, 0);
}

#[tokio::test]
async fn test_delete_group_routed_by_a_pool_is_refused() {
    let groups = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let group_id = groups
        .create("Office".to_string(), None, true, true)
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
        exemptions(),
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
        exemptions(),
        no_pools(),
    );

    let result = use_case.execute(1).await;

    assert!(matches!(
        result,
        Err(DomainError::ProtectedGroupCannotBeDeleted)
    ));
    assert_eq!(engine.reload_count().await, 0);
}
