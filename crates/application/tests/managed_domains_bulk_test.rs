use ferrous_dns_application::ports::{
    CreateManyOutcome, ManagedDomainRepository, NewManagedDomain,
};
use ferrous_dns_application::use_cases::managed_domains::{
    BulkCreateManagedDomainsUseCase, BulkEntryResult, BulkNewManagedDomains,
};
use ferrous_dns_domain::{DomainAction, DomainError};
use std::sync::Arc;

mod helpers;
use helpers::{MockBlockFilterEngine, MockGroupRepository, MockManagedDomainRepository};

struct Fixture {
    repo: Arc<MockManagedDomainRepository>,
    engine: Arc<MockBlockFilterEngine>,
    use_case: BulkCreateManagedDomainsUseCase,
}

fn fixture() -> Fixture {
    let repo = Arc::new(MockManagedDomainRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = BulkCreateManagedDomainsUseCase::new(
        repo.clone(),
        Arc::new(MockGroupRepository::new()),
        engine.clone(),
    );
    Fixture {
        repo,
        engine,
        use_case,
    }
}

/// Enabled allow rules in the default group, with no comment.
fn allow(domains: &[&str]) -> BulkNewManagedDomains {
    BulkNewManagedDomains {
        domains: domains.iter().map(|d| d.to_string()).collect(),
        action: DomainAction::Allow,
        group_id: 1,
        comment: None,
        enabled: true,
    }
}

/// `added`, `present`, `name taken` or `invalid` for each result.
fn statuses(results: &[BulkEntryResult]) -> Vec<&'static str> {
    results
        .iter()
        .map(|r| match &r.outcome {
            Ok(CreateManyOutcome::Created(_)) => "added",
            Ok(CreateManyOutcome::AlreadyPresent) => "present",
            Ok(CreateManyOutcome::NameTaken) => "name taken",
            Err(_) => "invalid",
        })
        .collect()
}

#[tokio::test]
async fn test_bulk_create_reloads_once_for_many_domains() {
    let f = fixture();

    let results = f
        .use_case
        .execute(allow(&["a.com", "b.com", "c.com"]))
        .await
        .unwrap();

    assert_eq!(statuses(&results), ["added", "added", "added"]);
    assert_eq!(f.repo.count().await, 3);
    assert_eq!(f.engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_bulk_create_skips_reload_when_nothing_is_added() {
    let f = fixture();
    f.use_case.execute(allow(&["a.com"])).await.unwrap();

    let results = f
        .use_case
        .execute(allow(&["a.com", "bad..com"]))
        .await
        .unwrap();

    assert_eq!(statuses(&results), ["present", "invalid"]);
    assert_eq!(f.engine.reload_count().await, 1, "only the first call");
}

#[tokio::test]
async fn test_bulk_create_saves_valid_entries_and_reports_invalid_ones() {
    let f = fixture();

    let results = f
        .use_case
        .execute(allow(&[
            "ok.com",
            "x..com",
            "",
            "*.cdn.example.net",
            "bad host.com",
        ]))
        .await
        .unwrap();

    assert_eq!(
        statuses(&results),
        ["added", "invalid", "invalid", "added", "invalid"]
    );
    match &results[1].outcome {
        Err(DomainError::InvalidManagedDomain(msg)) => {
            assert_eq!(msg, "Domain cannot contain an empty label")
        }
        other => panic!("expected an invalid managed domain, got {other:?}"),
    }
    assert_eq!(f.repo.count().await, 2);
}

#[tokio::test]
async fn test_bulk_create_trims_and_lowercases_like_the_single_add() {
    let f = fixture();

    let results = f
        .use_case
        .execute(allow(&["  Ads.Example.COM\t", "example.com."]))
        .await
        .unwrap();

    let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
    assert_eq!(domains, ["ads.example.com", "example.com."]);
    assert_eq!(statuses(&results), ["added", "added"]);
}

#[tokio::test]
async fn test_bulk_create_reports_a_repeat_in_the_batch_as_already_present() {
    let f = fixture();

    let results = f
        .use_case
        .execute(allow(&["a.com", "A.com", "a.com"]))
        .await
        .unwrap();

    assert_eq!(statuses(&results), ["added", "present", "present"]);
    assert_eq!(f.repo.count().await, 1);
}

#[tokio::test]
async fn test_bulk_create_names_each_rule_after_its_domain() {
    let f = fixture();

    f.use_case
        .execute(BulkNewManagedDomains {
            comment: Some("bulk import".to_string()),
            enabled: false,
            ..allow(&["a.com"])
        })
        .await
        .unwrap();

    let stored = &f.repo.get_all_domains().await[0];
    assert_eq!(stored.name.as_ref(), "a.com");
    assert_eq!(stored.domain.as_ref(), "a.com");
    assert_eq!(stored.action, DomainAction::Allow);
    assert_eq!(stored.comment.as_deref(), Some("bulk import"));
    assert!(!stored.enabled);
    assert!(stored.expires_at.is_none());
}

#[tokio::test]
async fn test_bulk_create_gives_an_allow_beside_a_same_named_deny_the_fallback_name() {
    let f = fixture();
    f.repo
        .create(NewManagedDomain {
            name: "both.com".to_string(),
            domain: "both.com".to_string(),
            action: DomainAction::Deny,
            group_id: 1,
            comment: None,
            enabled: true,
            expires_in: None,
        })
        .await
        .unwrap();

    let results = f.use_case.execute(allow(&["both.com"])).await.unwrap();

    assert_eq!(statuses(&results), ["added"]);
    match &results[0].outcome {
        Ok(CreateManyOutcome::Created(rule)) => {
            assert_eq!(rule.name.as_ref(), "both.com (allow)");
            assert_eq!(rule.action, DomainAction::Allow);
        }
        other => panic!("expected a created rule, got {other:?}"),
    }
}

#[tokio::test]
async fn test_bulk_create_omits_a_fallback_name_over_200_chars() {
    let f = fixture();
    // 196 characters: a valid name on its own, too long with " (allow)".
    let domain = format!("{}.com", "a".repeat(192));
    f.repo
        .create(NewManagedDomain {
            name: domain.clone(),
            domain: domain.clone(),
            action: DomainAction::Deny,
            group_id: 1,
            comment: None,
            enabled: true,
            expires_in: None,
        })
        .await
        .unwrap();

    let results = f.use_case.execute(allow(&[&domain])).await.unwrap();

    assert_eq!(statuses(&results), ["name taken"]);
    assert_eq!(f.engine.reload_count().await, 0);
}

#[tokio::test]
async fn test_bulk_create_rejects_unknown_group_before_writing() {
    let f = fixture();

    let result = f
        .use_case
        .execute(BulkNewManagedDomains {
            group_id: 99,
            ..allow(&["a.com"])
        })
        .await;

    assert!(matches!(result, Err(DomainError::GroupNotFound(99))));
    assert_eq!(f.repo.count().await, 0);
    assert_eq!(f.engine.reload_count().await, 0);
}

#[tokio::test]
async fn test_bulk_create_rejects_an_invalid_comment_before_writing() {
    let f = fixture();

    let result = f
        .use_case
        .execute(BulkNewManagedDomains {
            comment: Some("x".repeat(501)),
            ..allow(&["a.com"])
        })
        .await;

    assert!(matches!(result, Err(DomainError::InvalidManagedDomain(_))));
    assert_eq!(f.repo.count().await, 0);
}
