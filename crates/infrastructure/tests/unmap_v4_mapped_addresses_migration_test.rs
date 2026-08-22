//! Exercises the `20260822000001_unmap_v4_mapped_client_addresses` migration
//! against hand-seeded rows in the shape earlier releases left behind.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Row;

const MIGRATION: &str =
    include_str!("../../../migrations/20260822000001_unmap_v4_mapped_client_addresses.sql");

async fn seeded_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::raw_sql(
        r#"
        CREATE TABLE groups (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE clients (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            ip_address    TEXT     NOT NULL UNIQUE,
            mac_address   TEXT,
            hostname      TEXT,
            first_seen    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            query_count   INTEGER  NOT NULL DEFAULT 0,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            group_id      INTEGER  REFERENCES groups(id) ON DELETE SET NULL
        );
        CREATE TABLE client_subnets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet_cidr TEXT NOT NULL UNIQUE,
            group_id    INTEGER NOT NULL,
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE query_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL
        );
        INSERT INTO groups (id, name) VALUES (2, 'kids'), (3, 'servers');
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

async fn run_migration(pool: &sqlx::SqlitePool) {
    sqlx::raw_sql(MIGRATION).execute(pool).await.unwrap();
}

async fn client_addresses(pool: &sqlx::SqlitePool) -> Vec<String> {
    sqlx::query("SELECT ip_address FROM clients ORDER BY ip_address")
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<String, _>("ip_address"))
        .collect()
}

#[tokio::test]
async fn a_mapped_row_without_a_plain_twin_is_renamed_in_place() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO clients (ip_address, hostname, query_count, group_id)
         VALUES ('::ffff:10.0.0.7', 'laptop', 12, 2)",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;

    let row = sqlx::query("SELECT ip_address, hostname, query_count, group_id FROM clients")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("ip_address"), "10.0.0.7");
    assert_eq!(row.get::<String, _>("hostname"), "laptop");
    assert_eq!(row.get::<i64, _>("query_count"), 12);
    assert_eq!(row.get::<i64, _>("group_id"), 2);
}

#[tokio::test]
async fn a_mapped_row_is_merged_into_its_plain_twin() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO clients (ip_address, hostname, query_count, first_seen, last_seen, group_id)
         VALUES ('10.0.0.7', NULL, 10, '2026-01-01 00:00:00', '2026-06-01 00:00:00', NULL),
                ('::ffff:10.0.0.7', 'laptop', 5, '2025-12-01 00:00:00', '2026-07-01 00:00:00', 2)",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;

    assert_eq!(client_addresses(&pool).await, vec!["10.0.0.7"]);
    let row =
        sqlx::query("SELECT hostname, query_count, first_seen, last_seen, group_id FROM clients")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.get::<i64, _>("query_count"), 15);
    // The mapped row fills in what the plain row was missing.
    assert_eq!(row.get::<String, _>("hostname"), "laptop");
    assert_eq!(row.get::<i64, _>("group_id"), 2);
    // The merged row spans both rows' activity.
    assert_eq!(row.get::<String, _>("first_seen"), "2025-12-01 00:00:00");
    assert_eq!(row.get::<String, _>("last_seen"), "2026-07-01 00:00:00");
}

#[tokio::test]
async fn an_explicit_group_on_the_plain_row_is_not_overwritten() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO clients (ip_address, group_id)
         VALUES ('10.0.0.7', 3), ('::ffff:10.0.0.7', 2)",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;

    let group_id: i64 = sqlx::query_scalar("SELECT group_id FROM clients")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(group_id, 3);
}

#[tokio::test]
async fn a_genuine_ipv6_client_is_left_alone() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO clients (ip_address) VALUES ('2001:db8::1'), ('::1'), ('192.168.1.5')",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;

    assert_eq!(
        client_addresses(&pool).await,
        vec!["192.168.1.5", "2001:db8::1", "::1"]
    );
}

#[tokio::test]
async fn query_log_entries_follow_the_client_rows() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO query_log (client_ip)
         VALUES ('::ffff:10.0.0.7'), ('10.0.0.7'), ('2001:db8::1')",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;

    let addresses: Vec<String> = sqlx::query_scalar("SELECT client_ip FROM query_log ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(addresses, vec!["10.0.0.7", "10.0.0.7", "2001:db8::1"]);
}

#[tokio::test]
async fn a_mapped_subnet_loses_both_the_prefix_and_the_96_mask_bits() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO client_subnets (subnet_cidr, group_id)
         VALUES ('::ffff:10.0.0.0/104', 2),
                ('::ffff:192.168.1.0/120', 3),
                ('2001:db8::/32', 2),
                ('172.16.0.0/12', 3)",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;

    let subnets: Vec<String> =
        sqlx::query_scalar("SELECT subnet_cidr FROM client_subnets ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        subnets,
        vec![
            "10.0.0.0/8",
            "192.168.1.0/24",
            "2001:db8::/32",
            "172.16.0.0/12"
        ]
    );
}

#[tokio::test]
async fn a_mapped_subnet_duplicating_a_plain_one_is_dropped() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO client_subnets (subnet_cidr, group_id)
         VALUES ('10.0.0.0/8', 3), ('::ffff:10.0.0.0/104', 2)",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;

    let subnets: Vec<String> = sqlx::query_scalar("SELECT subnet_cidr FROM client_subnets")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(subnets, vec!["10.0.0.0/8"]);
}

#[tokio::test]
async fn running_the_migration_twice_changes_nothing_the_second_time() {
    let pool = seeded_db().await;
    sqlx::query(
        "INSERT INTO clients (ip_address, query_count)
         VALUES ('10.0.0.7', 10), ('::ffff:10.0.0.7', 5)",
    )
    .execute(&pool)
    .await
    .unwrap();

    run_migration(&pool).await;
    let after_first: i64 = sqlx::query_scalar("SELECT query_count FROM clients")
        .fetch_one(&pool)
        .await
        .unwrap();

    run_migration(&pool).await;
    let after_second: i64 = sqlx::query_scalar("SELECT query_count FROM clients")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(after_first, 15);
    assert_eq!(after_second, 15);
}
