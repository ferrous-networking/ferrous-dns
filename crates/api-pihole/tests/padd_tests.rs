mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use helpers::ftl::{assert_ftl_shape, BlockingStatus, Padd};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

/// GETs `uri` from `app`, asserting 200 and returning the JSON body.
async fn get_json(app: &Router, uri: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("invalid JSON")
}

/// Three allowed queries for `popular.test` and two blocked ones for
/// `ads.test`, all from one known client.
async fn seed_queries(pool: &sqlx::SqlitePool) {
    helpers::insert_client(pool, "10.0.0.1").await;
    for _ in 0..3 {
        helpers::insert_query(pool, "popular.test", "10.0.0.1", false, false, None).await;
    }
    for _ in 0..2 {
        helpers::insert_query(pool, "ads.test", "10.0.0.1", true, false, Some("blocklist")).await;
    }
}

#[tokio::test]
async fn padd_matches_the_ftl_schema() {
    let pool = helpers::create_test_db().await;
    seed_queries(&pool).await;
    let app = helpers::create_pihole_test_app(pool).await;

    let json = get_json(&app, "/padd").await;

    let padd = assert_ftl_shape::<Padd>(&json);
    // padd.c defaults `full` to true, which adds `iface` and `version`.
    assert!(padd.iface.is_some(), "full reply must carry iface: {json}");
    assert!(
        padd.version.is_some(),
        "full reply must carry version: {json}"
    );
}

#[tokio::test]
async fn padd_without_full_leaves_out_iface_and_version() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let json = get_json(&app, "/padd?full=false").await;

    assert_ftl_shape::<Padd>(&json);
    assert!(json.get("iface").is_none(), "iface must be absent: {json}");
    assert!(
        json.get("version").is_none(),
        "version must be absent: {json}"
    );
}

#[tokio::test]
async fn padd_reports_null_tops_without_queries() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let json = get_json(&app, "/padd").await;

    let padd = assert_ftl_shape::<Padd>(&json);
    assert_eq!(padd.recent_blocked, None);
    assert_eq!(padd.top_domain, None);
    assert_eq!(padd.top_blocked, None);
    assert_eq!(padd.top_client, None);
    assert_eq!(padd.queries.total, 0);
    assert_eq!(padd.queries.percent_blocked, 0.0);
}

#[tokio::test]
async fn padd_agrees_with_the_summary_and_the_tops() {
    let pool = helpers::create_test_db().await;
    seed_queries(&pool).await;
    let app = helpers::create_pihole_test_app(pool).await;

    let padd_json = get_json(&app, "/padd").await;
    let summary = get_json(&app, "/stats/summary").await;
    let padd = assert_ftl_shape::<Padd>(&padd_json);

    assert_eq!(
        Some(padd.queries.total),
        summary["queries"]["total"].as_u64()
    );
    assert_eq!(padd.queries.total, 5);
    assert_eq!(
        Some(padd.queries.blocked),
        summary["queries"]["blocked"].as_u64()
    );
    assert_eq!(padd.queries.blocked, 2);
    assert_eq!(
        Some(padd.queries.percent_blocked),
        summary["queries"]["percent_blocked"].as_f64()
    );
    assert_eq!(
        Some(padd.queries.query_frequency),
        summary["queries"]["frequency"].as_f64()
    );
    assert_eq!(
        Some(padd.active_clients),
        summary["clients"]["active"].as_u64()
    );
    assert_eq!(
        Some(padd.gravity_size),
        summary["gravity"]["domains_being_blocked"].as_u64()
    );

    assert_eq!(padd.recent_blocked.as_deref(), Some("ads.test"));
    assert_eq!(padd.top_domain.as_deref(), Some("popular.test"));
    assert_eq!(padd.top_blocked.as_deref(), Some("ads.test"));
    // stats.c get_top_clients: the name, or the IP when there is none.
    assert_eq!(padd.top_client.as_deref(), Some("10.0.0.1"));
}

#[tokio::test]
async fn padd_reports_blocking_host_and_process_like_the_other_routes() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let padd_json = get_json(&app, "/padd").await;
    let host = get_json(&app, "/info/host").await;
    let blocking = get_json(&app, "/dns/blocking").await;
    let padd = assert_ftl_shape::<Padd>(&padd_json);

    assert_eq!(padd.blocking, BlockingStatus::Enabled);
    assert_eq!(blocking["blocking"], "enabled");
    assert_eq!(
        Some(padd.node_name.as_str()),
        host["host"]["uname"]["nodename"].as_str()
    );
    assert_eq!(padd_json["host_model"], host["host"]["model"]);
    assert_eq!(padd.pid, i64::from(std::process::id()));
    assert_eq!(padd.sensors.unit, "C");
}

#[tokio::test]
async fn padd_config_reflects_ferrous_settings() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app_with_config(pool, |config| {
        config.server.dns_port = 5353;
        config.dns.local_domain = Some("home.arpa".to_string());
        config.dns.local_dns_server = Some("192.168.1.1:53".to_string());
    })
    .await;

    let json = get_json(&app, "/padd").await;

    let padd = assert_ftl_shape::<Padd>(&json);
    // Ferrous serves no DHCP.
    assert!(!padd.config.dhcp_active);
    assert!(!padd.config.dhcp_ipv6);
    assert_eq!(padd.config.dns_port, 5353);
    assert_eq!(padd.config.dns_domain, "home.arpa");
    // Conditional forwarding is FTL's revServer.
    assert!(padd.config.dns_rev_server_active);
    assert!(padd.config.dns_dnssec);
    // The default config's two `upstream_servers`.
    assert_eq!(padd.config.dns_num_upstreams, 2);
    assert_eq!(padd.config.privacy_level, 0);
}
