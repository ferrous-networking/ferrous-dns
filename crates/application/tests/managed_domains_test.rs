use ferrous_dns_application::ports::ManagedDomainRepository;
use ferrous_dns_application::use_cases::managed_domains::{
    CreateManagedDomainUseCase, DeleteManagedDomainUseCase, GetManagedDomainsUseCase,
    UpdateManagedDomainUseCase,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use std::sync::Arc;

mod helpers;
use helpers::{MockBlockFilterEngine, MockGroupRepository, MockManagedDomainRepository};

// ── GetManagedDomainsUseCase ──────────────────────────────────────────────────

#[tokio::test]
async fn test_get_all_empty() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let use_case = GetManagedDomainsUseCase::new(repo);

    let result = use_case.get_all().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_all_with_domains() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    repo.create(
        "Block Ads".to_string(),
        "ads.example.com".to_string(),
        DomainAction::Deny,
        1,
        None,
        true,
    )
    .await
    .unwrap();
    repo.create(
        "Allow Company".to_string(),
        "mycompany.com".to_string(),
        DomainAction::Allow,
        1,
        None,
        true,
    )
    .await
    .unwrap();

    let use_case = GetManagedDomainsUseCase::new(repo);
    let result = use_case.get_all().await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[tokio::test]
async fn test_get_by_id_found() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let created = repo
        .create(
            "Block Ads".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();
    let id = created.id.unwrap();

    let use_case = GetManagedDomainsUseCase::new(repo);
    let result = use_case.get_by_id(id).await;

    assert!(result.is_ok());
    let maybe = result.unwrap();
    assert!(maybe.is_some());
    assert_eq!(maybe.unwrap().name.as_ref(), "Block Ads");
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let use_case = GetManagedDomainsUseCase::new(repo);

    let result = use_case.get_by_id(999).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

// ── CreateManagedDomainUseCase ────────────────────────────────────────────────

#[tokio::test]
async fn test_create_deny_success() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo.clone(), group_repo, engine.clone());

    let result = use_case
        .execute(
            "Block Ads".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            Some("Block ads domain".to_string()),
            true,
        )
        .await;

    assert!(result.is_ok());
    let domain = result.unwrap();
    assert!(domain.id.is_some());
    assert_eq!(domain.name.as_ref(), "Block Ads");
    assert_eq!(domain.domain.as_ref(), "ads.example.com");
    assert_eq!(domain.action, DomainAction::Deny);
    assert_eq!(domain.group_id, 1);
    assert!(domain.enabled);
    assert_eq!(repo.count().await, 1);
    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_create_allow_success() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine);

    let result = use_case
        .execute(
            "Allow Company".to_string(),
            "mycompany.com".to_string(),
            DomainAction::Allow,
            1,
            None,
            true,
        )
        .await;

    assert!(result.is_ok());
    let domain = result.unwrap();
    assert_eq!(domain.action, DomainAction::Allow);
}

#[tokio::test]
async fn test_create_invalid_name_empty() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine);

    let result = use_case
        .execute(
            "".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidManagedDomain(_) => {}
        other => panic!("Expected InvalidManagedDomain, got {:?}", other),
    }
}

#[tokio::test]
async fn test_create_invalid_domain_empty() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine);

    let result = use_case
        .execute(
            "Empty Domain".to_string(),
            "".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidManagedDomain(_) => {}
        other => panic!("Expected InvalidManagedDomain, got {:?}", other),
    }
}

#[tokio::test]
async fn test_create_group_not_found() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine);

    let result = use_case
        .execute(
            "Test".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            999,
            None,
            true,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::GroupNotFound(_) => {}
        other => panic!("Expected GroupNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_create_duplicate_name() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine);

    use_case
        .execute(
            "Duplicate".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let result = use_case
        .execute(
            "Duplicate".to_string(),
            "tracker.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidManagedDomain(_) => {}
        other => panic!("Expected InvalidManagedDomain, got {:?}", other),
    }
}

// ── UpdateManagedDomainUseCase ────────────────────────────────────────────────

#[tokio::test]
async fn test_update_toggle_enabled() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc =
        CreateManagedDomainUseCase::new(repo.clone(), group_repo.clone(), engine.clone());
    let update_uc = UpdateManagedDomainUseCase::new(repo, group_repo, engine.clone());

    let created = create_uc
        .execute(
            "Toggle Domain".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let result = update_uc
        .execute(
            created.id.unwrap(),
            None,
            None,
            None,
            None,
            None,
            Some(false),
        )
        .await;

    assert!(result.is_ok());
    assert!(!result.unwrap().enabled);
    assert_eq!(engine.reload_count().await, 2);
}

#[tokio::test]
async fn test_update_change_action() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc =
        CreateManagedDomainUseCase::new(repo.clone(), group_repo.clone(), engine.clone());
    let update_uc = UpdateManagedDomainUseCase::new(repo, group_repo, engine);

    let created = create_uc
        .execute(
            "Change Action".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let result = update_uc
        .execute(
            created.id.unwrap(),
            None,
            None,
            Some(DomainAction::Allow),
            None,
            None,
            None,
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().action, DomainAction::Allow);
}

#[tokio::test]
async fn test_update_not_found() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = UpdateManagedDomainUseCase::new(repo, group_repo, engine);

    let result = use_case
        .execute(999, None, None, None, None, None, Some(false))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::ManagedDomainNotFound(_) => {}
        other => panic!("Expected ManagedDomainNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_update_invalid_group() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc =
        CreateManagedDomainUseCase::new(repo.clone(), group_repo.clone(), engine.clone());
    let update_uc = UpdateManagedDomainUseCase::new(repo, group_repo, engine);

    let created = create_uc
        .execute(
            "Test Domain".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();

    let result = update_uc
        .execute(created.id.unwrap(), None, None, None, Some(999), None, None)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::GroupNotFound(_) => {}
        other => panic!("Expected GroupNotFound, got {:?}", other),
    }
}

// ── DeleteManagedDomainUseCase ────────────────────────────────────────────────

#[tokio::test]
async fn test_delete_success() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc = CreateManagedDomainUseCase::new(repo.clone(), group_repo, engine.clone());
    let delete_uc = DeleteManagedDomainUseCase::new(repo.clone(), engine.clone());

    let created = create_uc
        .execute(
            "To Delete".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();
    let id = created.id.unwrap();
    assert_eq!(repo.count().await, 1);

    let result = delete_uc.execute(id).await;

    assert!(result.is_ok());
    assert_eq!(repo.count().await, 0);
    assert_eq!(engine.reload_count().await, 2);
}

#[tokio::test]
async fn test_delete_not_found() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = DeleteManagedDomainUseCase::new(repo, engine);

    let result = use_case.execute(999).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::ManagedDomainNotFound(_) => {}
        other => panic!("Expected ManagedDomainNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_reload_called_even_if_fails_gracefully() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    engine.set_should_fail_reload(true).await;

    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine.clone());

    let result = use_case
        .execute(
            "Test".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    // CRUD should succeed even if reload fails
    assert!(result.is_ok());
}
