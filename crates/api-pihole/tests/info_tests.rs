mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn version_matches_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/version")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoVersion>(&json);
}

#[tokio::test]
async fn version_contains_valid_semver() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/version")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");

    let version = json["version"]["core"]["local"]["version"]
        .as_str()
        .expect("version must be a string");
    assert!(
        version.contains('.'),
        "version '{version}' must contain a dot (basic semver check)"
    );
}

#[tokio::test]
async fn client_info_is_public_and_echoes_the_request() {
    // api.c: /api/info/client is one of the few routes without require_auth.
    let app =
        helpers::create_pihole_test_app_with_auth(helpers::create_test_db().await, false).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/info/client")
                .header("x-probe", "ferrous")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");
    let client = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoClient>(&json);
    assert_eq!(client.method, "GET");
    assert_eq!(client.http_version, "1.1");
    assert!(
        client
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("x-probe") && h.value == "ferrous"),
        "headers: {:?}",
        client.headers
    );
}

#[tokio::test]
async fn sensors_match_the_ftl_schema() {
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

    let (status, json) = helpers::send(app, "GET", "/info/sensors").await;

    assert_eq!(status, StatusCode::OK);
    let sensors = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoSensors>(&json).sensors;
    // FTL's defaults for webserver.api.temp.limit and .unit.
    assert_eq!(sensors.hot_limit, 60.0);
    assert_eq!(sensors.unit, "C");
}

#[tokio::test]
async fn messages_list_is_empty() {
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

    let (status, json) = helpers::send(app, "GET", "/info/messages").await;

    assert_eq!(status, StatusCode::OK);
    let messages = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoMessages>(&json);
    assert!(messages.messages.is_empty());
}

#[tokio::test]
async fn metrics_report_the_cache_counters() {
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

    let (status, json) = helpers::send(app, "GET", "/info/metrics").await;

    assert_eq!(status, StatusCode::OK);
    let metrics = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoMetrics>(&json).metrics;
    let cache = metrics.dns.cache;
    // dnsmasq's cache-size is the capacity, as /padd reports it.
    assert_eq!(
        cache.size,
        ferrous_dns_domain::Config::default().dns.cache_max_entries as u64
    );
    assert_eq!(cache.inserted, helpers::STUB_CACHE_INSERTIONS);
    assert_eq!(cache.evicted, helpers::STUB_CACHE_EVICTIONS);
    assert_eq!(cache.expired, helpers::STUB_CACHE_EXPIRED);
    assert_eq!(metrics.dns.replies.sum, 0);
    assert_eq!(metrics.dhcp.ack, 0);
}

#[tokio::test]
async fn ftl_info_reports_cache_insertions_and_evictions_as_dnsmasq_counters() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/ftl").await;

    let dnsmasq = &json["ftl"]["dnsmasq"];
    assert_eq!(dnsmasq["dns_cache_inserted"], helpers::STUB_CACHE_INSERTIONS);
    assert_eq!(dnsmasq["dns_cache_live_freed"], helpers::STUB_CACHE_EVICTIONS);
}

#[tokio::test]
async fn messages_count_is_zero() {
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

    let (status, json) = helpers::send(app, "GET", "/info/messages/count").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        helpers::ftl::assert_ftl_shape::<helpers::ftl::Count>(&json).count,
        0
    );
}

#[tokio::test]
async fn deleting_messages_that_do_not_exist_is_an_empty_not_found() {
    // info.c api_info_messages DELETE: nothing deleted → 404 with `{}`.
    for ids in ["7", "1,2,3"] {
        let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

        let (status, json) = helpers::send(app, "DELETE", &format!("/info/messages/{ids}")).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "ids {ids}");
        helpers::ftl::assert_ftl_shape::<helpers::ftl::Empty>(&json);
    }
}

/// GETs `uri` from a fresh app over `pool`, asserting 200 and returning the JSON body.
async fn get_json(pool: sqlx::SqlitePool, uri: &str) -> Value {
    let app = helpers::create_pihole_test_app(pool).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("invalid JSON")
}

/// Reads one `kB` field of `/proc/meminfo`.
#[cfg(target_os = "linux")]
fn meminfo_kb(key: &str) -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .expect("failed to read /proc/meminfo")
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .expect("meminfo key missing")
}

#[tokio::test]
async fn ftl_info_matches_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/ftl").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoFtl>(&json);
}

#[tokio::test]
async fn ftl_info_reports_uptime_in_milliseconds() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/ftl").await;

    let info = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoFtl>(&json);
    assert!(
        info.ftl.uptime >= helpers::PROCESS_AGE.as_millis() as f64,
        "uptime {} must be milliseconds since the process started",
        info.ftl.uptime
    );
    assert_eq!(info.ftl.pid, i64::from(std::process::id()));
}

#[tokio::test]
async fn ftl_info_counts_the_configured_domains_lists_groups_and_clients() {
    let pool = helpers::create_test_db().await;
    sqlx::raw_sql(
        "INSERT INTO groups (name) VALUES ('Kids');
         INSERT INTO managed_domains (name, domain, action, enabled) VALUES
             ('a1', 'allow-on.test', 'allow', 1),
             ('d1', 'deny-on.test', 'deny', 1),
             ('d2', 'deny-off.test', 'deny', 0),
             ('d3', 'deny-on2.test', 'deny', 1);
         INSERT INTO regex_filters (name, pattern, action, enabled) VALUES
             ('ra1', '^allow', 'allow', 0),
             ('rd1', '^deny', 'deny', 1);
         INSERT INTO blocklist_sources (name, url) VALUES ('block', 'https://block.test/list');
         INSERT INTO whitelist_sources (name, url) VALUES ('allow', 'https://allow.test/list');",
    )
    .execute(&pool)
    .await
    .expect("failed to seed the configuration");
    helpers::insert_client(&pool, "10.0.0.1").await;
    helpers::insert_client(&pool, "10.0.0.2").await;

    let json = get_json(pool, "/info/ftl").await;
    let info = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoFtl>(&json);
    let db = &info.ftl.database;

    assert_eq!(db.groups, 2, "the default group and Kids");
    assert_eq!(db.lists, 2, "block and allow lists both count");
    assert_eq!(db.clients, 2);
    assert_eq!(
        (db.domains.allowed.total, db.domains.allowed.enabled),
        (1, 1)
    );
    assert_eq!((db.domains.denied.total, db.domains.denied.enabled), (3, 2));
    assert_eq!((db.regex.allowed.total, db.regex.allowed.enabled), (1, 0));
    assert_eq!((db.regex.denied.total, db.regex.denied.enabled), (1, 1));
    assert_eq!((info.ftl.clients.total, info.ftl.clients.active), (2, 2));
}

#[tokio::test]
async fn system_info_matches_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/system").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoSystem>(&json);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_info_reports_memory_in_kilobytes_and_three_loads() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/system").await;

    let info = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoSystem>(&json);
    let system = &info.system;
    assert_eq!(system.memory.ram.total, meminfo_kb("MemTotal:"));
    assert_eq!(system.memory.swap.total, meminfo_kb("SwapTotal:"));
    assert!(system.uptime > 0, "host uptime in seconds");
    assert!(system.procs > 0);
    assert!(system.cpu.nprocs > 0);
    assert_eq!(system.cpu.load.raw.len(), 3);
    assert_eq!(system.cpu.load.percent.len(), 3);
}

#[tokio::test]
async fn host_info_matches_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/host").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoHost>(&json);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_info_reports_the_kernel_uname() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/host").await;

    let info = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoHost>(&json);
    let hostname =
        std::fs::read_to_string("/proc/sys/kernel/hostname").expect("failed to read the hostname");
    assert_eq!(info.host.uname.sysname, "Linux");
    assert_eq!(info.host.uname.nodename, hostname.trim());
    assert!(!info.host.uname.release.is_empty());
}

#[tokio::test]
async fn database_info_matches_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    let json = get_json(pool, "/info/database").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoDatabase>(&json);
}

#[tokio::test]
async fn database_info_counts_recent_and_stored_queries() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "a.test", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "b.test", "10.0.0.1", false, false, None).await;
    sqlx::query(
        "INSERT INTO query_log (domain, client_ip, created_at)
         VALUES ('old.test', '10.0.0.1', datetime('now', '-3 days'))",
    )
    .execute(&pool)
    .await
    .expect("failed to insert an old query");

    let json = get_json(pool, "/info/database").await;
    let info = helpers::ftl::assert_ftl_shape::<helpers::ftl::InfoDatabase>(&json);

    let now = chrono::Utc::now().timestamp() as f64;
    assert_eq!(info.queries, 2, "queries of the last 24 hours");
    assert_eq!(info.queries_disk, 3, "every stored query");
    assert!(
        (info.earliest_timestamp_disk - (now - 3.0 * 86_400.0)).abs() < 120.0,
        "earliest stored query is three days old, got {}",
        info.earliest_timestamp_disk
    );
    assert!(
        (info.earliest_timestamp - now).abs() < 120.0,
        "earliest recent query is now, got {}",
        info.earliest_timestamp
    );
    assert!(
        info.sqlite_version.contains('.'),
        "sqlite_version must be the library version, got {:?}",
        info.sqlite_version
    );
}
