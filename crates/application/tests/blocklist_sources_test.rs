use ferrous_dns_application::ports::{BlocklistSourceRepository, GroupRepository};
use ferrous_dns_application::use_cases::blocklist_sources::{
    CreateBlocklistSourceUseCase, DeleteBlocklistSourceUseCase, GetBlocklistSourcesUseCase,
    UpdateBlocklistSourceUseCase,
};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

mod helpers;
use helpers::{MockBlocklistSourceRepository, MockGroupRepository};

#[tokio::test]
async fn test_get_all_empty() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let use_case = GetBlocklistSourcesUseCase::new(repo);

    let result = use_case.get_all().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_all_with_sources() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    repo.create(
        "List A".to_string(),
        Some("https://example.com/a.txt".to_string()),
        1,
        None,
        true,
    )
    .await
    .unwrap();
    repo.create(
        "List B".to_string(),
        None,
        1,
        Some("Manual list".to_string()),
        false,
    )
    .await
    .unwrap();

    let use_case = GetBlocklistSourcesUseCase::new(repo);

    let result = use_case.get_all().await;

    assert!(result.is_ok());
    let sources = result.unwrap();
    assert_eq!(sources.len(), 2);
}

#[tokio::test]
async fn test_get_by_id_found() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let created = repo
        .create("Test List".to_string(), None, 1, None, true)
        .await
        .unwrap();
    let id = created.id.unwrap();

    let use_case = GetBlocklistSourcesUseCase::new(repo);

    let result = use_case.get_by_id(id).await;

    assert!(result.is_ok());
    let maybe_source = result.unwrap();
    assert!(maybe_source.is_some());
    assert_eq!(maybe_source.unwrap().name.as_ref(), "Test List");
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let use_case = GetBlocklistSourcesUseCase::new(repo);

    let result = use_case.get_by_id(999).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_create_success() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo);

    let result = use_case
        .execute(
            "AdGuard List".to_string(),
            Some("https://adguard.com/list.txt".to_string()),
            1,
            Some("Main ad block list".to_string()),
            true,
        )
        .await;

    assert!(result.is_ok());
    let source = result.unwrap();
    assert!(source.id.is_some());
    assert_eq!(source.name.as_ref(), "AdGuard List");
    assert_eq!(source.group_id, 1);
    assert!(source.enabled);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_create_without_url_succeeds() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo, group_repo);

    let result = use_case
        .execute("Manual List".to_string(), None, 1, None, true)
        .await;

    assert!(result.is_ok());
    let source = result.unwrap();
    assert!(source.url.is_none());
}

#[tokio::test]
async fn test_create_invalid_name_empty() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo, group_repo);

    let result = use_case.execute("".to_string(), None, 1, None, true).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidBlocklistSource(_) => {}
        other => panic!("Expected InvalidBlocklistSource, got {:?}", other),
    }
}

#[tokio::test]
async fn test_create_invalid_url_scheme() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo, group_repo);

    let result = use_case
        .execute(
            "Bad URL List".to_string(),
            Some("ftp://example.com/list.txt".to_string()),
            1,
            None,
            true,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidBlocklistSource(_) => {}
        other => panic!("Expected InvalidBlocklistSource, got {:?}", other),
    }
}

#[tokio::test]
async fn test_create_group_not_found() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo, group_repo);

    let result = use_case
        .execute("Test List".to_string(), None, 999, None, true)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::GroupNotFound(_) => {}
        other => panic!("Expected GroupNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_create_duplicate_name() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo, group_repo);

    use_case
        .execute("Duplicate".to_string(), None, 1, None, true)
        .await
        .unwrap();

    let result = use_case
        .execute("Duplicate".to_string(), None, 1, None, true)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidBlocklistSource(_) => {}
        other => panic!("Expected InvalidBlocklistSource, got {:?}", other),
    }
}

#[tokio::test]
async fn test_update_toggle_enabled() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo.clone());
    let update_uc = UpdateBlocklistSourceUseCase::new(repo, group_repo);

    let source = create_uc
        .execute("Toggle List".to_string(), None, 1, None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    let result = update_uc
        .execute(id, None, None, None, None, Some(false))
        .await;

    assert!(result.is_ok());
    assert!(!result.unwrap().enabled);
}

#[tokio::test]
async fn test_update_change_group() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    group_repo.create("Office".to_string(), None).await.unwrap();

    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo.clone());
    let update_uc = UpdateBlocklistSourceUseCase::new(repo, group_repo);

    let source = create_uc
        .execute("Group Change List".to_string(), None, 1, None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    let result = update_uc.execute(id, None, None, Some(2), None, None).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().group_id, 2);
}

#[tokio::test]
async fn test_update_source_not_found() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = UpdateBlocklistSourceUseCase::new(repo, group_repo);

    let result = use_case
        .execute(999, None, None, None, None, Some(false))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::BlocklistSourceNotFound(_) => {}
        other => panic!("Expected BlocklistSourceNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_update_invalid_group() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo.clone());
    let update_uc = UpdateBlocklistSourceUseCase::new(repo, group_repo);

    let source = create_uc
        .execute("List".to_string(), None, 1, None, true)
        .await
        .unwrap();

    let result = update_uc
        .execute(source.id.unwrap(), None, None, Some(999), None, None)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::GroupNotFound(_) => {}
        other => panic!("Expected GroupNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_update_clear_url() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo.clone());
    let update_uc = UpdateBlocklistSourceUseCase::new(repo, group_repo);

    let source = create_uc
        .execute(
            "URL List".to_string(),
            Some("https://example.com/list.txt".to_string()),
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let result = update_uc
        .execute(source.id.unwrap(), None, Some(None), None, None, None)
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().url.is_none());
}

#[tokio::test]
async fn test_delete_success() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo);
    let delete_uc = DeleteBlocklistSourceUseCase::new(repo.clone());

    let source = create_uc
        .execute("To Delete".to_string(), None, 1, None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();
    assert_eq!(repo.count().await, 1);

    let result = delete_uc.execute(id).await;

    assert!(result.is_ok());
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_delete_not_found() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let use_case = DeleteBlocklistSourceUseCase::new(repo);

    let result = use_case.execute(999).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::BlocklistSourceNotFound(_) => {}
        other => panic!("Expected BlocklistSourceNotFound, got {:?}", other),
    }
}
