#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::{ManagedDomainRepository, ManagedDomainUpdate};
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository;
use sqlx::SqlitePool;

async fn repo() -> (SqliteManagedDomainRepository, SqlitePool) {
    let pool = db::migrated_pool().await;
    (SqliteManagedDomainRepository::new(pool.clone()), pool)
}

async fn create(
    repo: &SqliteManagedDomainRepository,
    name: &str,
    action: DomainAction,
    enabled: bool,
) -> ManagedDomain {
    repo.create(
        name.to_string(),
        "ads.example.com".to_string(),
        action,
        1,
        None,
        enabled,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_create_and_get_by_id() {
    let (repo, _pool) = repo().await;

    let domain = repo
        .create(
            "Block Ads".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            1,
            Some("Block ads".to_string()),
            true,
        )
        .await
        .unwrap();

    assert_eq!(domain.name.as_ref(), "Block Ads");
    assert_eq!(domain.domain.as_ref(), "ads.example.com");
    assert_eq!(domain.action, DomainAction::Deny);
    assert_eq!(domain.group_id, 1);
    assert_eq!(domain.comment.as_deref(), Some("Block ads"));
    assert!(domain.enabled);
    assert!(domain.service_id.is_none());

    let fetched = repo.get_by_id(domain.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Block Ads");
    assert_eq!(fetched.action, DomainAction::Deny);
}

#[tokio::test]
async fn test_create_allow_disabled_round_trips() {
    let (repo, _pool) = repo().await;

    let id = create(&repo, "Allow Company", DomainAction::Allow, false)
        .await
        .id
        .unwrap();

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(fetched.action, DomainAction::Allow);
    assert!(!fetched.enabled);
    assert!(fetched.comment.is_none());
}

#[tokio::test]
async fn test_create_duplicate_name_fails() {
    let (repo, _pool) = repo().await;
    create(&repo, "Duplicate", DomainAction::Deny, true).await;

    let result = repo
        .create(
            "Duplicate".to_string(),
            "tracker.example.com".to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await;

    assert!(
        matches!(result, Err(DomainError::AlreadyExists(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_create_missing_group_returns_group_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo
        .create(
            "Orphan".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            999,
            None,
            true,
        )
        .await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let (repo, _pool) = repo().await;

    assert!(repo.get_by_id(999).await.unwrap().is_none());
}

#[tokio::test]
async fn test_get_all_ordered_by_name() {
    let (repo, _pool) = repo().await;
    create(&repo, "Zebra Domain", DomainAction::Deny, true).await;
    create(&repo, "Alpha Domain", DomainAction::Allow, true).await;
    create(&repo, "Middle Domain", DomainAction::Deny, false).await;

    let names: Vec<String> = repo
        .get_all()
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.name.to_string())
        .collect();

    assert_eq!(names, vec!["Alpha Domain", "Middle Domain", "Zebra Domain"]);
}

#[tokio::test]
async fn test_get_all_paged_reports_total() {
    let (repo, _pool) = repo().await;
    for name in ["a", "b", "c"] {
        create(&repo, name, DomainAction::Deny, true).await;
    }

    let (page, total) = repo.get_all_paged(2, 1, None).await.unwrap();

    assert_eq!(total, 3);
    let names: Vec<&str> = page.iter().map(|d| d.name.as_ref()).collect();
    assert_eq!(names, vec!["b", "c"]);
}

#[tokio::test]
async fn test_get_all_paged_search_filters_total_and_page() {
    let (repo, _pool) = repo().await;
    for (name, domain) in [
        ("Alpha", "ads.example.com"),
        ("Bravo", "tracker.example.net"),
        ("Charlie", "cdn.other.org"),
        ("Delta", "pixel.EXAMPLE.io"),
    ] {
        repo.create(
            name.to_string(),
            domain.to_string(),
            DomainAction::Deny,
            1,
            None,
            true,
        )
        .await
        .unwrap();
    }

    let (page, total) = repo.get_all_paged(2, 1, Some("example")).await.unwrap();

    assert_eq!(total, 3);
    let names: Vec<&str> = page.iter().map(|d| d.name.as_ref()).collect();
    assert_eq!(names, vec!["Bravo", "Delta"]);
}

#[tokio::test]
async fn test_get_all_paged_orders_name_ties_by_group() {
    let (repo, pool) = repo().await;
    sqlx::query("INSERT INTO groups (id, name) VALUES (2, 'Kids')")
        .execute(&pool)
        .await
        .unwrap();
    for group_id in [2, 1] {
        repo.create(
            "Shared".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Deny,
            group_id,
            None,
            true,
        )
        .await
        .unwrap();
    }

    let (first, _) = repo.get_all_paged(1, 0, None).await.unwrap();
    let (second, _) = repo.get_all_paged(1, 1, None).await.unwrap();

    assert_eq!(first[0].group_id, 1);
    assert_eq!(second[0].group_id, 2);
}

#[tokio::test]
async fn test_update_name_keeps_other_fields() {
    let (repo, _pool) = repo().await;
    let id = repo
        .create(
            "Original Name".to_string(),
            "ads.example.com".to_string(),
            DomainAction::Allow,
            1,
            Some("note".to_string()),
            false,
        )
        .await
        .unwrap()
        .id
        .unwrap();

    let updated = repo
        .update(
            id,
            ManagedDomainUpdate {
                name: Some("New Name".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "New Name");
    assert_eq!(updated.domain.as_ref(), "ads.example.com");
    assert_eq!(updated.action, DomainAction::Allow);
    assert_eq!(updated.comment.as_deref(), Some("note"));
    assert!(!updated.enabled);
}

#[tokio::test]
async fn test_update_action_and_enabled() {
    let (repo, _pool) = repo().await;
    let id = create(&repo, "Toggle", DomainAction::Deny, true)
        .await
        .id
        .unwrap();

    repo.update(
        id,
        ManagedDomainUpdate {
            action: Some(DomainAction::Allow),
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let stored = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(stored.action, DomainAction::Allow);
    assert!(!stored.enabled);
}

#[tokio::test]
async fn test_update_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo
        .update(
            999,
            ManagedDomainUpdate {
                name: Some("New".to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(
        matches!(result, Err(DomainError::ManagedDomainNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_update_to_missing_group_returns_group_not_found() {
    let (repo, _pool) = repo().await;
    let id = create(&repo, "Move", DomainAction::Deny, true)
        .await
        .id
        .unwrap();

    let result = repo
        .update(
            id,
            ManagedDomainUpdate {
                group_id: Some(999),
                ..Default::default()
            },
        )
        .await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_delete_success() {
    let (repo, _pool) = repo().await;
    let id = create(&repo, "To Delete", DomainAction::Deny, true)
        .await
        .id
        .unwrap();

    repo.delete(id).await.unwrap();

    assert!(repo.get_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo.delete(999).await;

    assert!(
        matches!(result, Err(DomainError::ManagedDomainNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_bulk_create_for_service_is_idempotent() {
    let (repo, _pool) = repo().await;
    let rules = || {
        vec![
            ("[Svc] a.example".to_string(), "a.example".to_string()),
            ("[Svc] b.example".to_string(), "b.example".to_string()),
        ]
    };

    assert_eq!(
        repo.bulk_create_for_service("svc", 1, rules())
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        repo.bulk_create_for_service("svc", 1, rules())
            .await
            .unwrap(),
        0
    );

    let all = repo.get_all().await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|d| d.service_id.as_deref() == Some("svc")
        && d.action == DomainAction::Deny
        && d.enabled));
}

#[tokio::test]
async fn test_delete_by_service_scopes_to_group() {
    let (repo, pool) = repo().await;
    sqlx::query("INSERT INTO groups (id, name) VALUES (2, 'Kids')")
        .execute(&pool)
        .await
        .unwrap();
    repo.bulk_create_for_service(
        "svc",
        1,
        vec![("[Svc] g1".to_string(), "a.example".to_string())],
    )
    .await
    .unwrap();
    repo.bulk_create_for_service(
        "svc",
        2,
        vec![("[Svc] g2".to_string(), "a.example".to_string())],
    )
    .await
    .unwrap();

    assert_eq!(repo.delete_by_service("svc", 1).await.unwrap(), 1);
    assert_eq!(repo.delete_all_by_service("svc").await.unwrap(), 1);
    assert!(repo.get_all().await.unwrap().is_empty());
}
