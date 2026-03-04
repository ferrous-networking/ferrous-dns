use ferrous_dns_application::ports::ScheduleProfileRepository;
use ferrous_dns_domain::ScheduleAction;
use ferrous_dns_infrastructure::repositories::schedule_profile_repository::SqliteScheduleProfileRepository;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

async fn create_test_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS groups (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            enabled    INTEGER NOT NULL DEFAULT 1,
            comment    TEXT,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO groups (id, name, enabled, is_default) VALUES (1, 'Default', 1, 1)")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schedule_profiles (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            timezone   TEXT    NOT NULL DEFAULT 'UTC',
            comment    TEXT,
            created_at TEXT    NOT NULL,
            updated_at TEXT    NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS time_slots (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES schedule_profiles(id) ON DELETE CASCADE,
            days       INTEGER NOT NULL DEFAULT 127 CHECK(days >= 1 AND days <= 127),
            start_time TEXT    NOT NULL,
            end_time   TEXT    NOT NULL,
            action     TEXT    NOT NULL DEFAULT 'block_all' CHECK(action IN ('block_all', 'allow_all')),
            created_at TEXT    NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS group_schedule_profiles (
            group_id   INTEGER NOT NULL PRIMARY KEY REFERENCES groups(id)            ON DELETE CASCADE,
            profile_id INTEGER NOT NULL             REFERENCES schedule_profiles(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

#[tokio::test]
async fn test_create_profile_returns_profile_with_id() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let profile = repo
        .create("Test".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    assert!(profile.id.is_some());
    assert_eq!(profile.name.as_ref(), "Test");
    assert_eq!(profile.timezone.as_ref(), "UTC");
}

#[tokio::test]
async fn test_create_profile_duplicate_name_returns_error() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    repo.create("Dup".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let result = repo
        .create("Dup".to_string(), "UTC".to_string(), None)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_all_returns_empty_initially() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let profiles = repo.get_all().await.unwrap();
    assert!(profiles.is_empty());
}

#[tokio::test]
async fn test_get_by_id_nonexistent_returns_none() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let result = repo.get_by_id(999).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_profile_name_and_timezone() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let created = repo
        .create("Old".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let id = created.id.unwrap();
    let updated = repo
        .update(
            id,
            Some("New".to_string()),
            Some("Europe/Lisbon".to_string()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(updated.name.as_ref(), "New");
    assert_eq!(updated.timezone.as_ref(), "Europe/Lisbon");
}

#[tokio::test]
async fn test_delete_profile_removes_slots_cascade() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let profile = repo
        .create("Del".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let id = profile.id.unwrap();
    repo.add_slot(
        id,
        31,
        "08:00".to_string(),
        "17:00".to_string(),
        ScheduleAction::BlockAll,
    )
    .await
    .unwrap();
    repo.delete(id).await.unwrap();
    // Profile is gone
    let found = repo.get_by_id(id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_add_slot_and_get_slots_for_profile() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let profile = repo
        .create("Slots".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let pid = profile.id.unwrap();
    let slot = repo
        .add_slot(
            pid,
            31,
            "09:00".to_string(),
            "18:00".to_string(),
            ScheduleAction::BlockAll,
        )
        .await
        .unwrap();
    assert!(slot.id.is_some());
    assert_eq!(slot.days, 31);
    let slots = repo.get_slots(pid).await.unwrap();
    assert_eq!(slots.len(), 1);
}

#[tokio::test]
async fn test_delete_slot_removes_only_that_slot() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let profile = repo
        .create("TwoSlots".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let pid = profile.id.unwrap();
    let s1 = repo
        .add_slot(
            pid,
            31,
            "08:00".to_string(),
            "12:00".to_string(),
            ScheduleAction::BlockAll,
        )
        .await
        .unwrap();
    let _s2 = repo
        .add_slot(
            pid,
            31,
            "13:00".to_string(),
            "17:00".to_string(),
            ScheduleAction::AllowAll,
        )
        .await
        .unwrap();
    repo.delete_slot(s1.id.unwrap()).await.unwrap();
    let slots = repo.get_slots(pid).await.unwrap();
    assert_eq!(slots.len(), 1);
}

#[tokio::test]
async fn test_assign_profile_to_group() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let profile = repo
        .create("Assign".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let pid = profile.id.unwrap();
    repo.assign_to_group(1, pid).await.unwrap();
    let assignment = repo.get_group_assignment(1).await.unwrap();
    assert_eq!(assignment, Some(pid));
}

#[tokio::test]
async fn test_unassign_profile_from_group_leaves_profile_intact() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let profile = repo
        .create("Unassign".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let pid = profile.id.unwrap();
    repo.assign_to_group(1, pid).await.unwrap();
    repo.unassign_from_group(1).await.unwrap();
    let assignment = repo.get_group_assignment(1).await.unwrap();
    assert!(assignment.is_none());
    // Profile still exists
    let found = repo.get_by_id(pid).await.unwrap();
    assert!(found.is_some());
}

#[tokio::test]
async fn test_get_group_assignment_returns_none_when_unassigned() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let result = repo.get_group_assignment(1).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_all_group_assignments_returns_all_pairs() {
    let pool = create_test_db().await;
    let repo = SqliteScheduleProfileRepository::new(pool);
    let p = repo
        .create("Multi".to_string(), "UTC".to_string(), None)
        .await
        .unwrap();
    let pid = p.id.unwrap();
    repo.assign_to_group(1, pid).await.unwrap();
    let pairs = repo.get_all_group_assignments().await.unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0], (1, pid));
}
