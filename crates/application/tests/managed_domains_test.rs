use ferrous_dns_application::ports::{
    ManagedDomainRepository, ManagedDomainUpdate, NewManagedDomain,
};
use ferrous_dns_application::use_cases::managed_domains::{
    CreateManagedDomainUseCase, DeleteManagedDomainUseCase, GetManagedDomainsUseCase,
    PurgeExpiredManagedDomainsUseCase, UpdateManagedDomainUseCase,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use std::sync::Arc;
use std::time::Duration;

mod helpers;
use helpers::{MockBlockFilterEngine, MockGroupRepository, MockManagedDomainRepository};

/// An enabled, permanent rule in the default group, with no comment.
fn new_domain(name: &str, domain: &str, action: DomainAction) -> NewManagedDomain {
    NewManagedDomain {
        name: name.to_string(),
        domain: domain.to_string(),
        action,
        group_id: 1,
        comment: None,
        enabled: true,
        expires_in: None,
    }
}

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
    repo.create(new_domain(
        "Block Ads",
        "ads.example.com",
        DomainAction::Deny,
    ))
    .await
    .unwrap();
    repo.create(new_domain(
        "Allow Company",
        "mycompany.com",
        DomainAction::Allow,
    ))
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
        .create(new_domain(
            "Block Ads",
            "ads.example.com",
            DomainAction::Deny,
        ))
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

#[tokio::test]
async fn test_create_deny_success() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo.clone(), group_repo, engine.clone());

    let result = use_case
        .execute(NewManagedDomain {
            comment: Some("Block ads domain".to_string()),
            ..new_domain("Block Ads", "ads.example.com", DomainAction::Deny)
        })
        .await;

    assert!(result.is_ok());
    let domain = result.unwrap();
    assert!(domain.id.is_some());
    assert_eq!(domain.name.as_ref(), "Block Ads");
    assert_eq!(domain.domain.as_ref(), "ads.example.com");
    assert_eq!(domain.action, DomainAction::Deny);
    assert_eq!(domain.group_id, 1);
    assert!(domain.enabled);
    assert!(domain.expires_at.is_none());
    assert_eq!(repo.count().await, 1);
    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_create_with_expiry_stores_expires_at() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine.clone());

    let domain = use_case
        .execute(NewManagedDomain {
            expires_in: Some(Duration::from_secs(3600)),
            ..new_domain("Allow for an hour", "ads.example.com", DomainAction::Allow)
        })
        .await
        .unwrap();

    assert!(domain.expires_at.is_some());
    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_create_rejects_expiry_outside_bounds() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo.clone(), group_repo, engine.clone());
    let with_expiry = |secs: u64| NewManagedDomain {
        expires_in: Some(Duration::from_secs(secs)),
        ..new_domain(
            &format!("Expiry {secs}"),
            "ads.example.com",
            DomainAction::Allow,
        )
    };

    for secs in [0, 59, 30 * 24 * 3600 + 1] {
        let result = use_case.execute(with_expiry(secs)).await;

        assert!(
            matches!(result, Err(DomainError::InvalidManagedDomain(_))),
            "{secs} s: {result:?}"
        );
    }
    for secs in [60, 30 * 24 * 3600] {
        use_case
            .execute(with_expiry(secs))
            .await
            .unwrap_or_else(|e| panic!("{secs} s: {e:?}"));
    }

    assert_eq!(repo.count().await, 2);
    assert_eq!(engine.reload_count().await, 2);
}

#[tokio::test]
async fn test_create_allow_success() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = CreateManagedDomainUseCase::new(repo, group_repo, engine);

    let result = use_case
        .execute(new_domain(
            "Allow Company",
            "mycompany.com",
            DomainAction::Allow,
        ))
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
        .execute(new_domain("", "ads.example.com", DomainAction::Deny))
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
        .execute(new_domain("Empty Domain", "", DomainAction::Deny))
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
        .execute(NewManagedDomain {
            group_id: 999,
            ..new_domain("Test", "ads.example.com", DomainAction::Deny)
        })
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::GroupNotFound(_) => {}
        other => panic!("Expected GroupNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_update_toggle_enabled() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc =
        CreateManagedDomainUseCase::new(repo.clone(), group_repo.clone(), engine.clone());
    let update_uc = UpdateManagedDomainUseCase::new(repo, group_repo, engine.clone());

    let created = create_uc
        .execute(new_domain(
            "Toggle Domain",
            "ads.example.com",
            DomainAction::Deny,
        ))
        .await
        .unwrap();

    let result = update_uc
        .execute(
            created.id.unwrap(),
            ManagedDomainUpdate {
                enabled: Some(false),
                ..Default::default()
            },
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
        .execute(new_domain(
            "Change Action",
            "ads.example.com",
            DomainAction::Deny,
        ))
        .await
        .unwrap();

    let result = update_uc
        .execute(
            created.id.unwrap(),
            ManagedDomainUpdate {
                action: Some(DomainAction::Allow),
                ..Default::default()
            },
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
        .execute(
            999,
            ManagedDomainUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
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
        .execute(new_domain(
            "Test Domain",
            "ads.example.com",
            DomainAction::Deny,
        ))
        .await
        .unwrap();

    let result = update_uc
        .execute(
            created.id.unwrap(),
            ManagedDomainUpdate {
                group_id: Some(999),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::GroupNotFound(_) => {}
        other => panic!("Expected GroupNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_delete_success() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc = CreateManagedDomainUseCase::new(repo.clone(), group_repo, engine.clone());
    let delete_uc = DeleteManagedDomainUseCase::new(repo.clone(), engine.clone());

    let created = create_uc
        .execute(new_domain(
            "To Delete",
            "ads.example.com",
            DomainAction::Deny,
        ))
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
        .execute(new_domain("Test", "ads.example.com", DomainAction::Deny))
        .await;

    // CRUD should succeed even if reload fails
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_purge_expired_deletes_past_rules_and_reloads_only_then() {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let mut ids = Vec::new();
    for (name, expires_in) in [
        ("Permanent", None),
        ("Future", Some(Duration::from_secs(3600))),
        ("Past", Some(Duration::from_secs(3600))),
    ] {
        let created = repo
            .create(NewManagedDomain {
                expires_in,
                ..new_domain(name, "ads.example.com", DomainAction::Allow)
            })
            .await
            .unwrap();
        ids.push(created.id);
    }
    repo.expire(ids[2].unwrap()).await;
    let purge = PurgeExpiredManagedDomainsUseCase::new(repo.clone(), engine.clone());

    assert_eq!(purge.execute().await.unwrap(), 1);
    assert_eq!(engine.reload_count().await, 1);
    let left: Vec<Option<i64>> = repo
        .get_all_domains()
        .await
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(left, ids[..2]);

    assert_eq!(purge.execute().await.unwrap(), 0);
    assert_eq!(
        engine.reload_count().await,
        1,
        "nothing expired, so nothing to reload"
    );
}
