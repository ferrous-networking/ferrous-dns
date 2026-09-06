use ferrous_dns_application::ports::{
    BlocklistSourceCreator, BlocklistSourceRepository, GroupRepository,
};
use ferrous_dns_application::use_cases::blocklist_sources::{
    CreateBlocklistSourceUseCase, DeleteBlocklistSourceUseCase, GetBlocklistSourcesUseCase,
    SyncBlocklistSourcesUseCase, UpdateBlocklistSourceUseCase,
};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

mod helpers;
use helpers::{MockBlockFilterEngine, MockBlocklistSourceRepository, MockGroupRepository};

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
        vec![1],
        None,
        true,
    )
    .await
    .unwrap();
    repo.create(
        "List B".to_string(),
        None,
        vec![1],
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
        .create("Test List".to_string(), None, vec![1], None, true)
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
            vec![1],
            Some("Main ad block list".to_string()),
            true,
        )
        .await;

    assert!(result.is_ok());
    let source = result.unwrap();
    assert!(source.id.is_some());
    assert_eq!(source.name.as_ref(), "AdGuard List");
    assert_eq!(source.group_ids, vec![1]);
    assert!(source.enabled);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_create_with_multiple_groups() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    group_repo.create("Office".to_string(), None).await.unwrap();
    let use_case = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo);

    let result = use_case
        .execute("Multi-Group List".to_string(), None, vec![1, 2], None, true)
        .await;

    assert!(result.is_ok());
    let source = result.unwrap();
    assert_eq!(source.group_ids, vec![1, 2]);
}

#[tokio::test]
async fn test_create_without_url_succeeds() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo, group_repo);

    let result = use_case
        .execute("Manual List".to_string(), None, vec![1], None, true)
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

    let result = use_case
        .execute("".to_string(), None, vec![1], None, true)
        .await;

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
            vec![1],
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
        .execute("Test List".to_string(), None, vec![999], None, true)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::GroupNotFound(_) => {}
        other => panic!("Expected GroupNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn test_create_one_invalid_group_in_multi_group_fails() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let use_case = CreateBlocklistSourceUseCase::new(repo, group_repo);

    // group 1 exists (default), group 999 does not
    let result = use_case
        .execute("Multi List".to_string(), None, vec![1, 999], None, true)
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
        .execute("Duplicate".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let result = use_case
        .execute("Duplicate".to_string(), None, vec![1], None, true)
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
        .execute("Toggle List".to_string(), None, vec![1], None, true)
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
async fn test_update_change_groups() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    group_repo.create("Office".to_string(), None).await.unwrap();

    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo.clone());
    let update_uc = UpdateBlocklistSourceUseCase::new(repo, group_repo);

    let source = create_uc
        .execute("Group Change List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    let result = update_uc
        .execute(id, None, None, Some(vec![2]), None, None)
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().group_ids, vec![2]);
}

#[tokio::test]
async fn test_update_assign_multiple_groups() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    group_repo.create("Office".to_string(), None).await.unwrap();

    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo.clone());
    let update_uc = UpdateBlocklistSourceUseCase::new(repo, group_repo);

    let source = create_uc
        .execute("Shared List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();
    let id = source.id.unwrap();

    let result = update_uc
        .execute(id, None, None, Some(vec![1, 2]), None, None)
        .await;

    assert!(result.is_ok());
    let updated = result.unwrap();
    assert_eq!(updated.group_ids.len(), 2);
    assert!(updated.group_ids.contains(&1));
    assert!(updated.group_ids.contains(&2));
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
        .execute("List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let result = update_uc
        .execute(source.id.unwrap(), None, None, Some(vec![999]), None, None)
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
            vec![1],
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
        .execute("To Delete".to_string(), None, vec![1], None, true)
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

// ── Block filter reload ───────────────────────────────────────────────────────

/// Polls until the spawned reload has run at least `expected` times. The sync
/// use case reloads in a background task, so the count is not visible until
/// this task yields to the scheduler.
async fn wait_for_reload_count(engine: &MockBlockFilterEngine, expected: u32) {
    for _ in 0..1_000 {
        if engine.reload_count().await >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for reload_count to reach {}", expected);
}

/// Polls until a sync is accepted again, which only happens once the in-flight
/// guard has been released by the spawned reload.
async fn wait_until_sync_accepted(use_case: &SyncBlocklistSourcesUseCase) -> bool {
    for _ in 0..1_000 {
        if use_case.execute().await.unwrap() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    false
}

#[tokio::test]
async fn test_create_reloads_block_filter() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case =
        CreateBlocklistSourceUseCase::new(repo, group_repo).with_block_filter(engine.clone());

    let result = use_case
        .execute(
            "HaGeZi Pro".to_string(),
            Some("https://example.com/pro.txt".to_string()),
            vec![1],
            None,
            true,
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(
        engine.reload_count().await,
        1,
        "a new source must take effect without waiting for the daily sync job"
    );
}

#[tokio::test]
async fn test_update_reloads_block_filter() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo.clone());
    let update_uc =
        UpdateBlocklistSourceUseCase::new(repo, group_repo).with_block_filter(engine.clone());

    let source = create_uc
        .execute("Toggle List".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let result = update_uc
        .execute(source.id.unwrap(), None, None, None, None, Some(false))
        .await;

    assert!(result.is_ok());
    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_delete_reloads_block_filter() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let create_uc = CreateBlocklistSourceUseCase::new(repo.clone(), group_repo);
    let delete_uc = DeleteBlocklistSourceUseCase::new(repo).with_block_filter(engine.clone());

    let source = create_uc
        .execute("To Delete".to_string(), None, vec![1], None, true)
        .await
        .unwrap();

    let result = delete_uc.execute(source.id.unwrap()).await;

    assert!(result.is_ok());
    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_create_group_not_found_does_not_reload() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case =
        CreateBlocklistSourceUseCase::new(repo, group_repo).with_block_filter(engine.clone());

    let result = use_case
        .execute("Unknown Group".to_string(), None, vec![999], None, true)
        .await;

    assert!(result.is_err());
    assert_eq!(
        engine.reload_count().await,
        0,
        "the reload must sit after the fallible work, not before it"
    );
}

#[tokio::test]
async fn test_batch_creator_does_not_reload_block_filter() {
    let repo = Arc::new(MockBlocklistSourceRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case =
        CreateBlocklistSourceUseCase::new(repo, group_repo).with_block_filter(engine.clone());

    // Backup import drives this port in a loop over every source in the
    // snapshot and reloads once at the end. Reloading here would re-download
    // every list once per imported source.
    let result = use_case
        .create_blocklist_source("Imported".to_string(), None, vec![1], None, true)
        .await;

    assert!(result.is_ok());
    assert_eq!(engine.reload_count().await, 0);
}

// ── Manual sync ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_sync_starts_a_reload() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = SyncBlocklistSourcesUseCase::new(engine.clone());

    let started = use_case.execute().await;

    assert!(started.is_ok());
    assert!(started.unwrap(), "the first sync must start");
    wait_for_reload_count(&engine, 1).await;
    assert_eq!(engine.reload_count().await, 1);
}

#[tokio::test]
async fn test_sync_while_running_is_rejected() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = SyncBlocklistSourcesUseCase::new(engine.clone());

    // `#[tokio::test]` runs on a current-thread runtime and neither call
    // reaches an await that pends, so the spawned reload cannot start before
    // the second call lands — both hit the guard in the same state it would be
    // in for two clicks in a row.
    let first = use_case.execute().await.unwrap();
    let second = use_case.execute().await.unwrap();

    assert!(first, "the first sync must start");
    assert!(
        !second,
        "a second sync must be rejected while one is running"
    );

    wait_for_reload_count(&engine, 1).await;
    assert_eq!(
        engine.reload_count().await,
        1,
        "a rejected sync must not duplicate the download"
    );
}

#[tokio::test]
async fn test_sync_runs_again_after_the_previous_one_finishes() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    let use_case = SyncBlocklistSourcesUseCase::new(engine.clone());

    assert!(use_case.execute().await.unwrap());
    wait_for_reload_count(&engine, 1).await;

    assert!(
        wait_until_sync_accepted(&use_case).await,
        "the guard must be released once the reload completes"
    );
    wait_for_reload_count(&engine, 2).await;
}

#[tokio::test]
async fn test_sync_releases_the_guard_when_the_reload_fails() {
    let engine = Arc::new(MockBlockFilterEngine::new());
    engine.set_should_fail_reload(true).await;
    let use_case = SyncBlocklistSourcesUseCase::new(engine.clone());

    assert!(use_case.execute().await.unwrap());

    assert!(
        wait_until_sync_accepted(&use_case).await,
        "a failed sync must release the guard instead of wedging every later one"
    );
    assert_eq!(
        engine.reload_count().await,
        0,
        "no reload succeeded, so the count must stay at zero"
    );
}
