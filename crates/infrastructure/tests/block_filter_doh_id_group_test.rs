//! Integration tests for DoH Client ID group resolution and registration lookup
//! in `BlockFilterEngine` against a real migrated SQLite database.

use ferrous_dns_application::ports::BlockFilterEnginePort;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use std::net::IpAddr;
use std::sync::Arc;

const DEFAULT_GROUP_ID: i64 = 1;

#[tokio::test]
async fn doh_id_precedence_and_reload_on_real_engine() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");

    // Seed three additional groups: Adults (2, enabled), Subnet (3, enabled), Kids (4, disabled).
    sqlx::query(
        "INSERT INTO groups (id, name, enabled, is_default) VALUES
         (2, 'Adults', 1, 0),
         (3, 'SubnetGroup', 1, 0),
         (4, 'Kids', 0, 0)",
    )
    .execute(&pool)
    .await
    .expect("seed groups");

    // Assign 10.0.0.50 to Adults (2) and 10.0.0.0/24 to SubnetGroup (3).
    sqlx::query("INSERT INTO clients (ip_address, group_id) VALUES ('10.0.0.50', 2)")
        .execute(&pool)
        .await
        .expect("seed IP client");
    sqlx::query("INSERT INTO client_subnets (subnet_cidr, group_id) VALUES ('10.0.0.0/24', 3)")
        .execute(&pool)
        .await
        .expect("seed subnet");

    // Register 'kids-tablet' in Kids (group 4, which has enabled = 0).
    sqlx::query(
        "INSERT INTO doh_ids (name, client_id, group_id) VALUES ('Kids Tablet', 'kids-tablet', 4)",
    )
    .execute(&pool)
    .await
    .expect("seed doh_id");

    let engine = BlockFilterEngine::new(
        pool.clone(),
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .expect("build engine");

    let client_ip: IpAddr = "10.0.0.50".parse().unwrap();
    let subnet_ip: IpAddr = "10.0.0.99".parse().unwrap();
    let other_ip: IpAddr = "192.168.1.10".parse().unwrap();

    // Registration checks.
    assert!(engine.is_doh_id_registered("kids-tablet"));
    assert!(!engine.is_doh_id_registered("unknown-device"));

    // 1. Registered DoH ID wins over explicit IP group, subnet group, and default group,
    //    even when its assigned group has `enabled = 0`.
    assert_eq!(
        engine.resolve_group_for_request(client_ip, Some("kids-tablet")),
        4
    );
    assert_eq!(
        engine.resolve_group_for_request(subnet_ip, Some("kids-tablet")),
        4
    );
    assert_eq!(
        engine.resolve_group_for_request(other_ip, Some("kids-tablet")),
        4
    );

    // 2. Unregistered DoH ID falls back to IP -> Subnet -> Default.
    assert_eq!(
        engine.resolve_group_for_request(client_ip, Some("unknown-device")),
        2
    );
    assert_eq!(
        engine.resolve_group_for_request(subnet_ip, Some("unknown-device")),
        3
    );
    assert_eq!(
        engine.resolve_group_for_request(other_ip, Some("unknown-device")),
        DEFAULT_GROUP_ID
    );

    // 3. No DoH ID uses IP -> Subnet -> Default.
    assert_eq!(engine.resolve_group_for_request(client_ip, None), 2);
    assert_eq!(engine.resolve_group_for_request(subnet_ip, None), 3);
    assert_eq!(
        engine.resolve_group_for_request(other_ip, None),
        DEFAULT_GROUP_ID
    );

    // 4. Reload swaps in updated DoH ID mappings atomically.
    sqlx::query("UPDATE doh_ids SET group_id = 3 WHERE client_id = 'kids-tablet'")
        .execute(&pool)
        .await
        .expect("update doh_id group");
    engine
        .load_client_groups()
        .await
        .expect("reload client groups");
    assert_eq!(
        engine.resolve_group_for_request(client_ip, Some("kids-tablet")),
        3
    );
}
