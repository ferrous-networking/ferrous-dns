#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::{
    BulkManagedDomain, CreateManyOutcome, ManagedDomainRepository, ManagedDomainUpdate,
    NewManagedDomain,
};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use ferrous_dns_infrastructure::database::{create_query_log_pool, create_write_pool};
use ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository;
use sqlx::SqlitePool;
use std::time::Duration;

async fn repo() -> (SqliteManagedDomainRepository, SqlitePool) {
    let pool = db::migrated_pool().await;
    (SqliteManagedDomainRepository::new(pool.clone()), pool)
}

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

async fn create(
    repo: &SqliteManagedDomainRepository,
    name: &str,
    action: DomainAction,
    enabled: bool,
) -> ManagedDomain {
    repo.create(NewManagedDomain {
        enabled,
        ..new_domain(name, "ads.example.com", action)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn test_create_and_get_by_id() {
    let (repo, _pool) = repo().await;

    let domain = repo
        .create(NewManagedDomain {
            comment: Some("Block ads".to_string()),
            ..new_domain("Block Ads", "ads.example.com", DomainAction::Deny)
        })
        .await
        .unwrap();

    assert_eq!(domain.name.as_ref(), "Block Ads");
    assert_eq!(domain.domain.as_ref(), "ads.example.com");
    assert_eq!(domain.action, DomainAction::Deny);
    assert_eq!(domain.group_id, 1);
    assert_eq!(domain.comment.as_deref(), Some("Block ads"));
    assert!(domain.enabled);
    assert!(domain.service_id.is_none());
    assert!(domain.expires_at.is_none());

    let fetched = repo.get_by_id(domain.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.name.as_ref(), "Block Ads");
    assert_eq!(fetched.action, DomainAction::Deny);
}

#[tokio::test]
async fn test_create_with_expiry_stores_expires_at() {
    let (repo, _pool) = repo().await;
    let before = chrono::Utc::now() + chrono::Duration::minutes(59);

    let domain = repo
        .create(NewManagedDomain {
            expires_in: Some(Duration::from_secs(3600)),
            ..new_domain("Temporary", "ads.example.com", DomainAction::Allow)
        })
        .await
        .unwrap();

    let expires_at = domain.expires_at.clone().expect("expiry stored");
    let parsed = chrono::NaiveDateTime::parse_from_str(&expires_at, "%Y-%m-%d %H:%M:%S")
        .unwrap()
        .and_utc();
    assert!(parsed > before, "{expires_at} is not about an hour away");
    assert!(parsed <= chrono::Utc::now() + chrono::Duration::minutes(61));

    let fetched = repo.get_by_id(domain.id.unwrap()).await.unwrap().unwrap();
    assert_eq!(fetched.expires_at, Some(expires_at));
}

#[tokio::test]
async fn test_delete_expired_removes_only_rules_past_their_expiry() {
    let (repo, pool) = repo().await;
    let permanent = create(&repo, "Permanent", DomainAction::Allow, true).await;
    let future = repo
        .create(NewManagedDomain {
            expires_in: Some(Duration::from_secs(3600)),
            ..new_domain("Future", "ads.example.com", DomainAction::Allow)
        })
        .await
        .unwrap();
    let past = create(&repo, "Past", DomainAction::Allow, true).await;
    sqlx::query("UPDATE managed_domains SET expires_at = '2000-01-01 00:00:00' WHERE id = ?")
        .bind(past.id)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(repo.delete_expired().await.unwrap(), 1);

    let ids: Vec<Option<i64>> = repo
        .get_all()
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(ids, vec![future.id, permanent.id]);
    assert_eq!(repo.delete_expired().await.unwrap(), 0);
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
        .create(new_domain(
            "Duplicate",
            "tracker.example.com",
            DomainAction::Deny,
        ))
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
        .create(NewManagedDomain {
            group_id: 999,
            ..new_domain("Orphan", "ads.example.com", DomainAction::Deny)
        })
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
        repo.create(new_domain(name, domain, DomainAction::Deny))
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
        repo.create(NewManagedDomain {
            group_id,
            ..new_domain("Shared", "ads.example.com", DomainAction::Deny)
        })
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
        .create(NewManagedDomain {
            comment: Some("note".to_string()),
            enabled: false,
            ..new_domain("Original Name", "ads.example.com", DomainAction::Allow)
        })
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

/// `rule` with no fallback name.
fn bulk(rule: NewManagedDomain) -> BulkManagedDomain {
    BulkManagedDomain {
        rule,
        fallback_name: None,
    }
}

/// A rule named after its domain, falling back to `"<domain> (<action>)"`.
fn bulk_named_after(domain: &str, action: DomainAction) -> BulkManagedDomain {
    BulkManagedDomain {
        rule: new_domain(domain, domain, action),
        fallback_name: Some(ManagedDomain::fallback_name(domain, action)),
    }
}

fn created(outcome: &CreateManyOutcome) -> &ManagedDomain {
    match outcome {
        CreateManyOutcome::Created(rule) => rule,
        other => panic!("expected a created rule, got {other:?}"),
    }
}

#[tokio::test]
async fn test_create_many_inserts_every_row() {
    let (repo, _pool) = repo().await;

    let outcomes = repo
        .create_many(vec![
            bulk(new_domain("a.com", "a.com", DomainAction::Allow)),
            bulk(new_domain("*.b.com", "*.b.com", DomainAction::Deny)),
        ])
        .await
        .unwrap();

    assert_eq!(created(&outcomes[0]).domain.as_ref(), "a.com");
    assert_eq!(created(&outcomes[1]).action, DomainAction::Deny);
    assert!(created(&outcomes[0]).id.is_some());
    assert_eq!(repo.get_all().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_create_many_reports_same_domain_group_action_as_already_present() {
    let (repo, _pool) = repo().await;
    repo.create(new_domain("Shop", "shop.com", DomainAction::Allow))
        .await
        .unwrap();

    let outcomes = repo
        .create_many(vec![bulk_named_after("shop.com", DomainAction::Allow)])
        .await
        .unwrap();

    assert!(
        matches!(outcomes[0], CreateManyOutcome::AlreadyPresent),
        "{outcomes:?}"
    );
    assert_eq!(repo.get_all().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_create_many_matches_a_legacy_uppercase_rule_as_already_present() {
    let (repo, _pool) = repo().await;
    repo.create(new_domain("Legacy", "Shop.COM", DomainAction::Allow))
        .await
        .unwrap();

    let outcomes = repo
        .create_many(vec![bulk_named_after("shop.com", DomainAction::Allow)])
        .await
        .unwrap();

    assert!(
        matches!(outcomes[0], CreateManyOutcome::AlreadyPresent),
        "{outcomes:?}"
    );
}

#[tokio::test]
async fn test_create_many_does_not_count_a_temporary_or_differently_enabled_rule() {
    let (repo, _pool) = repo().await;
    repo.create(NewManagedDomain {
        expires_in: Some(Duration::from_secs(3600)),
        ..new_domain("qlog-allow-for-a.com", "a.com", DomainAction::Allow)
    })
    .await
    .unwrap();
    repo.create(NewManagedDomain {
        enabled: false,
        ..new_domain("Off", "b.com", DomainAction::Allow)
    })
    .await
    .unwrap();

    let outcomes = repo
        .create_many(vec![
            bulk_named_after("a.com", DomainAction::Allow),
            bulk_named_after("b.com", DomainAction::Allow),
        ])
        .await
        .unwrap();

    assert!(created(&outcomes[0]).expires_at.is_none());
    assert!(created(&outcomes[1]).enabled);
}

#[tokio::test]
async fn test_create_many_treats_a_repeat_in_the_batch_as_already_present() {
    let (repo, _pool) = repo().await;

    let outcomes = repo
        .create_many(vec![
            bulk_named_after("a.com", DomainAction::Allow),
            bulk_named_after("a.com", DomainAction::Allow),
        ])
        .await
        .unwrap();

    created(&outcomes[0]);
    assert!(
        matches!(outcomes[1], CreateManyOutcome::AlreadyPresent),
        "{outcomes:?}"
    );
    assert_eq!(repo.get_all().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_create_many_adds_the_opposite_action() {
    let (repo, _pool) = repo().await;
    repo.create(new_domain("Ads", "ads.com", DomainAction::Deny))
        .await
        .unwrap();

    let outcomes = repo
        .create_many(vec![bulk_named_after("ads.com", DomainAction::Allow)])
        .await
        .unwrap();

    let rule = created(&outcomes[0]);
    assert_eq!(rule.name.as_ref(), "ads.com");
    assert_eq!(rule.action, DomainAction::Allow);
}

#[tokio::test]
async fn test_create_many_uses_the_fallback_name_when_the_name_is_taken() {
    let (repo, _pool) = repo().await;
    repo.create_many(vec![bulk_named_after("both.com", DomainAction::Deny)])
        .await
        .unwrap();

    let outcomes = repo
        .create_many(vec![bulk_named_after("both.com", DomainAction::Allow)])
        .await
        .unwrap();

    let rule = created(&outcomes[0]);
    assert_eq!(rule.name.as_ref(), "both.com (allow)");
    assert_eq!(rule.domain.as_ref(), "both.com");
    assert_eq!(repo.get_all().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_create_many_reports_name_taken_when_both_names_are_taken() {
    let (repo, _pool) = repo().await;
    repo.create(new_domain("both.com", "other.com", DomainAction::Deny))
        .await
        .unwrap();
    repo.create(new_domain(
        "both.com (allow)",
        "else.com",
        DomainAction::Deny,
    ))
    .await
    .unwrap();

    let outcomes = repo
        .create_many(vec![
            bulk_named_after("both.com", DomainAction::Allow),
            bulk(new_domain("both.com", "both.com", DomainAction::Allow)),
        ])
        .await
        .unwrap();

    assert!(
        matches!(outcomes[0], CreateManyOutcome::NameTaken),
        "{outcomes:?}"
    );
    assert!(
        matches!(outcomes[1], CreateManyOutcome::NameTaken),
        "{outcomes:?}"
    );
    assert_eq!(repo.get_all().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_create_many_keeps_comment_enabled_and_expiry() {
    let (repo, _pool) = repo().await;

    let outcomes = repo
        .create_many(vec![bulk(NewManagedDomain {
            comment: Some("bulk import".to_string()),
            enabled: false,
            expires_in: Some(Duration::from_secs(3600)),
            ..new_domain("a.com", "a.com", DomainAction::Allow)
        })])
        .await
        .unwrap();

    let stored = repo
        .get_by_id(created(&outcomes[0]).id.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.comment.as_deref(), Some("bulk import"));
    assert!(!stored.enabled);
    assert!(stored.expires_at.is_some());
}

#[tokio::test]
async fn test_create_many_unknown_group_writes_nothing() {
    let (repo, _pool) = repo().await;

    let result = repo
        .create_many(vec![
            bulk(new_domain("a.com", "a.com", DomainAction::Allow)),
            bulk(NewManagedDomain {
                group_id: 999,
                ..new_domain("b.com", "b.com", DomainAction::Allow)
            }),
        ])
        .await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
    assert!(repo.get_all().await.unwrap().is_empty(), "rolled back");
}

/// The production layout: the write pool and the query log pool on one WAL
/// file.
async fn file_pools() -> (SqlitePool, SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("ferrous.db").display());
    let config = DatabaseConfig::default();
    let write = create_write_pool(&url, &config).await.unwrap();
    let query_log = create_query_log_pool(&url, &config).await.unwrap();
    (write, query_log, dir)
}

/// Holds the write lock on another connection, as the query log writer
/// does, for 300 ms.
async fn hold_write_lock(query_log: &SqlitePool) -> tokio::task::JoinHandle<()> {
    let mut conn = query_log.acquire().await.unwrap().detach();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut conn)
        .await
        .unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        sqlx::query("COMMIT").execute(&mut conn).await.unwrap();
    })
}

#[tokio::test]
async fn test_create_many_waits_for_a_concurrent_writer() {
    let (write, query_log, _dir) = file_pools().await;
    let repo = SqliteManagedDomainRepository::new(write);
    let holder = hold_write_lock(&query_log).await;

    let result = repo
        .create_many(vec![bulk_named_after("a.com", DomainAction::Deny)])
        .await;
    holder.await.unwrap();

    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn test_create_many_does_not_count_a_service_rule_as_present() {
    let (repo, _pool) = repo().await;
    repo.bulk_create_for_service(
        "youtube",
        1,
        vec![(
            "[YouTube] youtube.com".to_string(),
            "youtube.com".to_string(),
        )],
    )
    .await
    .unwrap();

    let outcomes = repo
        .create_many(vec![bulk_named_after("youtube.com", DomainAction::Deny)])
        .await
        .unwrap();
    repo.delete_by_service("youtube", 1).await.unwrap();

    assert!(
        matches!(outcomes[0], CreateManyOutcome::Created(_)),
        "{outcomes:?}"
    );
    assert_eq!(
        repo.get_all().await.unwrap().len(),
        1,
        "the user's deny outlives the service"
    );
}
