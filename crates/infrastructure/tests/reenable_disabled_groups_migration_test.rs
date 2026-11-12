//! `20261112000001_reenable_disabled_groups`, run over a database migrated to
//! the schema before it. Earlier releases ignored a group's `enabled` flag, so
//! the migration switches every disabled group back on and an upgrade keeps
//! filtering every client as before (#382).

use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::borrow::Cow;

const VERSION: i64 = 20261112000001;
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

async fn pool_before_the_migration() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let earlier = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < VERSION)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    earlier.run(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn test_migration_re_enables_every_disabled_group() {
    let pool = pool_before_the_migration().await;
    sqlx::query(
        "INSERT INTO groups (name, enabled, comment, malware_detection_enabled) VALUES
         ('Kids', 0, 'tablets', 0),
         ('Adults', 1, NULL, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();

    MIGRATOR.run(&pool).await.unwrap();

    let groups: Vec<(String, bool, Option<String>, bool)> = sqlx::query(
        "SELECT name, enabled, comment, malware_detection_enabled FROM groups
         WHERE is_default = 0 ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
    .collect();
    assert_eq!(
        groups,
        vec![
            ("Kids".to_string(), true, Some("tablets".to_string()), false),
            ("Adults".to_string(), true, None, true),
        ]
    );
}
