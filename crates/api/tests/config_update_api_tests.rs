use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::create_api_router_with_openapi;
use ferrous_dns_application::ports::{ConfigFilePersistence, UpstreamReloadPort};
use ferrous_dns_application::use_cases::{ConfigOverrides, ReloadConfigUseCase};
use ferrous_dns_domain::{Config, DomainError, UpstreamPool};
use ferrous_dns_infrastructure::repositories::TomlConfigFilePersistence;
use helpers::{create_test_db, TestApp};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock, RwLockWriteGuard};
use tower::ServiceExt;

mod helpers;

/// The update handler resolves a config path up front and refuses to run
/// without one, so each app gets a unique writable temp file (returned too).
async fn test_app(pool: SqlitePool) -> (TestApp, String) {
    let config_path = std::env::temp_dir()
        .join(format!(
            "ferrous_cfg_update_test_{}_{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&config_path, "").unwrap();
    let app = TestApp::builder()
        .pool(pool)
        .config_path(&config_path)
        .build()
        .await;
    (app, config_path)
}

async fn post_config(app: Router, body: serde_json::Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn get_config(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

fn live_servers(pm: &ferrous_dns_infrastructure::dns::PoolManager) -> Vec<String> {
    pm.get_all_servers().iter().map(|a| a.to_string()).collect()
}

#[tokio::test]
async fn test_update_config_rejects_invalid_server() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["not-a-valid-endpoint"] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["success"], false);
    assert!(
        json["error"].as_str().unwrap().contains("Invalid server"),
        "error should name the bad server, got: {}",
        json["error"]
    );
    // A rejected save must not touch the live pools.
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_explains_a_quic_scheme_upstream() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["quic://abc.d.adguard-dns.com"] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json["error"],
        "Pool 'p1': Invalid server 'quic://abc.d.adguard-dns.com': 'quic://' is not a supported scheme — write DNS-over-QUIC as doq://abc.d.adguard-dns.com:853"
    );
}

#[tokio::test]
async fn test_update_config_rejects_pool_with_only_blank_servers() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["", "   "] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("At least one pool"),
        "blank-only servers should leave zero valid pools, got: {}",
        json["error"]
    );
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_hot_applies_valid_pools_without_restart() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    // Pool-only changes are hot-applied; no restart banner.
    assert_eq!(json["restart_required"], false);

    // The live pool manager must already serve the new upstream.
    let servers = live_servers(&pm);
    assert!(
        servers.iter().any(|s| s == "9.9.9.9:53"),
        "new upstream should be live after save: {servers:?}"
    );
    assert!(
        !servers.iter().any(|s| s == "8.8.8.8:53"),
        "old upstream should be gone after hot reload: {servers:?}"
    );
}

/// Blocks `reload_pools` until released, holding a save mid-flight.
struct GatedReload {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait::async_trait]
impl UpstreamReloadPort for GatedReload {
    async fn reload_pools(&self, _pools: Vec<UpstreamPool>) -> Result<(), DomainError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(())
    }
}

#[tokio::test]
async fn test_update_config_does_not_overwrite_a_concurrent_config_write() {
    let pool = create_test_db().await;
    let (TestApp { mut state, .. }, _path) = test_app(pool).await;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    state.dns.reload_upstream = Arc::new(GatedReload {
        started: started.clone(),
        release: release.clone(),
    });
    let config = state.config.clone();
    let app = create_api_router_with_openapi(state).0;

    let save = tokio::spawn(post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    ));
    started.notified().await;

    // Stands in for any other config writer, e.g. a local-record or password change.
    let writer_config = config.clone();
    let mut writer = tokio::spawn(async move {
        writer_config.write().await.dns.local_domain = Some("lan".to_string());
    });
    let writer_done = tokio::time::timeout(Duration::from_millis(100), &mut writer)
        .await
        .is_ok();
    release.notify_one();

    let (_, json) = save.await.unwrap();
    assert_eq!(json["success"], true);
    if !writer_done {
        writer.await.unwrap();
    }

    let config = config.read().await;
    assert_eq!(config.dns.local_domain.as_deref(), Some("lan"));
    assert_eq!(config.dns.pools[0].servers, ["udp://9.9.9.9:53"]);
}

#[tokio::test]
async fn test_update_config_non_pool_change_requires_restart() {
    let pool = create_test_db().await;
    let TestApp {
        router: app,
        pool_manager: pm,
        ..
    } = test_app(pool).await.0;

    // pihole_compat defaults to false; flipping it is a non-hot-applied change.
    let (status, json) = post_config(
        app,
        serde_json::json!({ "server": { "pihole_compat": true } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(
        json["restart_required"], true,
        "a non-pool field change must ask for a restart"
    );
    // No pools were sent, so the live pool set is untouched.
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_rejects_invalid_sinkhole_ipv4() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_config(
        app,
        serde_json::json!({ "blocking": { "sinkhole_ipv4": "10.0.0.300" } }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("Invalid IPv4 sinkhole address"),
        "error should name the bad sinkhole, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn test_update_config_rejects_invalid_sinkhole_ipv6() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_config(
        app,
        serde_json::json!({ "blocking": { "sinkhole_ipv6": "fd00::zz" } }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("Invalid IPv6 sinkhole address"),
        "error should name the bad sinkhole, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn test_update_config_persists_then_clears_sinkhole() {
    let pool = create_test_db().await;
    let (TestApp { router: app, .. }, path) = test_app(pool).await;

    // A valid custom sinkhole is accepted and written to the config file.
    let (status, json) = post_config(
        app.clone(),
        serde_json::json!({ "blocking": { "sinkhole_ipv4": "192.168.50.50" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("192.168.50.50"),
        "config file should carry the custom sinkhole, got:\n{written}"
    );

    // An empty string clears it: the key must disappear from the file.
    let (status, json) = post_config(
        app,
        serde_json::json!({ "blocking": { "sinkhole_ipv4": "" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    let cleared = std::fs::read_to_string(&path).unwrap();
    assert!(
        !cleared.contains("sinkhole_ipv4") && !cleared.contains("192.168.50.50"),
        "cleared sinkhole key must be removed from the file, got:\n{cleared}"
    );
}

#[tokio::test]
async fn test_update_config_persists_mdns_enabled() {
    let pool = create_test_db().await;
    let (TestApp { router: app, .. }, path) = test_app(pool).await;

    let (status, json) =
        post_config(app, serde_json::json!({ "dns": { "mdns_enabled": true } })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);

    // The flag must be written through to the config file under [dns].
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("mdns_enabled = true"),
        "config file should carry mdns_enabled = true, got:\n{written}"
    );
}

#[tokio::test]
async fn test_get_config_reports_mdns_enabled() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    // Default config: GET reports the flag as false.
    let (status, json) = get_config(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["dns"]["mdns_enabled"], false);

    // After enabling it, GET reflects the new value — covers the response DTO mapping.
    let (status, _) = post_config(
        app.clone(),
        serde_json::json!({ "dns": { "mdns_enabled": true } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, json) = get_config(app).await;
    assert_eq!(json["dns"]["mdns_enabled"], true);
}

async fn post_settings(app: Router, body: serde_json::Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/settings")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

#[tokio::test]
async fn test_get_config_reports_dns64_defaults() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = get_config(app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["dns64"]["enabled"], false);
    assert_eq!(json["dns64"]["prefix"], "64:ff9b::/96");
}

#[tokio::test]
async fn test_update_settings_enables_dns64_and_persists() {
    let pool = create_test_db().await;
    let (TestApp { router: app, .. }, path) = test_app(pool).await;

    let (status, json) = post_settings(
        app.clone(),
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "dns64_enabled": true,
            "nat64_prefix": "64:ff9b::/96"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);

    // Persisted to the config file under [dns64].
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("[dns64]") && written.contains("prefix = \"64:ff9b::/96\""),
        "config file should carry the [dns64] section, got:\n{written}"
    );

    // And reflected back through GET /config (response DTO mapping).
    let (_, json) = get_config(app).await;
    assert_eq!(json["dns64"]["enabled"], true);
}

#[tokio::test]
async fn test_update_settings_rejects_invalid_dns64_prefix() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_settings(
        app,
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "dns64_enabled": true,
            "nat64_prefix": "64:ff9b::/64"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Invalid DNS64 prefix"),
        "error should name the bad prefix, got: {}",
        json["error"]
    );
}

async fn get_settings(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn post_tls_generate(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tls/generate?force=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

#[tokio::test]
async fn test_restart_required_is_pending_until_the_server_restarts() {
    let pool = create_test_db().await;
    let app = test_app(pool.clone()).await.0.router;

    let (status, json) = get_config(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["restart_required"], false,
        "a freshly started server has no restart pending"
    );

    let (status, json) = post_config(
        app.clone(),
        serde_json::json!({ "server": { "pihole_compat": true } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["restart_required"], true);

    // Every page asks the server, so any browser — not only the one that
    // saved — must learn that a restart is pending.
    let (_, json) = get_config(app).await;
    assert_eq!(
        json["restart_required"], true,
        "GET /config must report the pending restart after the save"
    );

    // A restart is a new process with fresh in-memory state.
    let restarted = test_app(pool).await.0.router;
    let (_, json) = get_config(restarted).await;
    assert_eq!(
        json["restart_required"], false,
        "the pending restart must not outlive the restart itself"
    );
}

#[tokio::test]
async fn test_get_config_reports_no_restart_after_pool_only_change() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_config(
        app.clone(),
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);

    let (_, json) = get_config(app).await;
    assert_eq!(
        json["restart_required"], false,
        "hot-applied pools must not leave a restart pending"
    );
}

#[tokio::test]
async fn test_update_settings_change_requires_restart() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_settings(
        app.clone(),
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "dns64_enabled": true,
            "nat64_prefix": "64:ff9b::/96"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(
        json["restart_required"], true,
        "changing a DNS setting must ask for a restart"
    );

    let (_, json) = get_config(app).await;
    assert_eq!(json["restart_required"], true);
}

#[tokio::test]
async fn test_update_settings_without_changes_requires_no_restart() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    // Saving the form exactly as loaded changes nothing.
    let (status, current) = get_settings(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, json) = post_settings(app.clone(), current).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(
        json["restart_required"], false,
        "an unchanged save must not ask for a restart"
    );

    let (_, json) = get_config(app).await;
    assert_eq!(json["restart_required"], false);
}

#[tokio::test]
async fn test_tls_certificate_generation_leaves_restart_pending() {
    let pool = create_test_db().await;
    let app = test_app(pool).await.0.router;

    let (status, json) = post_tls_generate(app.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["restart_required"], true);

    let (_, json) = get_config(app).await;
    assert_eq!(
        json["restart_required"], true,
        "a new certificate is only served after a restart"
    );
}

#[tokio::test]
async fn test_update_config_keeps_config_readable_during_pool_reload() {
    let pool = create_test_db().await;
    let (TestApp { mut state, .. }, _path) = test_app(pool).await;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    state.dns.reload_upstream = Arc::new(GatedReload {
        started: started.clone(),
        release: release.clone(),
    });
    let config = state.config.clone();
    let app = create_api_router_with_openapi(state).0;

    let save = tokio::spawn(post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    ));
    started.notified().await;

    // Upstream hostname resolution can take seconds; readers must not queue behind it.
    let reader = tokio::time::timeout(Duration::from_secs(1), config.read()).await;
    assert!(reader.is_ok(), "a reader waited for the pool hot-reload");
    drop(reader);

    release.notify_one();
    let (status, json) = save.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
}

#[tokio::test]
async fn test_update_config_rejects_a_zero_compaction_interval() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, path) = test_app(pool).await;
    let before = config.read().await.dns.cache_compaction_interval;

    let (status, json) = post_config(
        router,
        serde_json::json!({ "dns": { "cache_compaction_interval": 0 } }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("dns.cache_compaction_interval"),
        "error should name the key, got: {}",
        json["error"]
    );
    assert_eq!(config.read().await.dns.cache_compaction_interval, before);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
}

/// A config file with any of these loads with the default instead, but the
/// API rejects them.
#[tokio::test]
async fn test_update_config_rejects_zeros_a_config_file_loads_as_the_default() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, path) = test_app(pool).await;
    let before = config.read().await.clone();

    for (key, body) in [
        (
            "dns.cache_max_entries",
            serde_json::json!({ "dns": { "cache_max_entries": 0 } }),
        ),
        (
            "auth.session_ttl_hours",
            serde_json::json!({ "auth": { "session_ttl_hours": 0 } }),
        ),
        (
            "auth.remember_me_days",
            serde_json::json!({ "auth": { "remember_me_days": 3_000_000 } }),
        ),
        (
            "auth.login_rate_limit_window_secs",
            serde_json::json!({ "auth": { "login_rate_limit_window_secs": 0 } }),
        ),
    ] {
        let (status, json) = post_config(router.clone(), body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{key}");
        assert!(
            json["error"].as_str().unwrap_or_default().contains(key),
            "error should name {key}, got: {}",
            json["error"]
        );
    }
    let after = config.read().await;
    assert_eq!(after.dns.cache_max_entries, before.dns.cache_max_entries);
    assert_eq!(
        (
            after.auth.session_ttl_hours,
            after.auth.remember_me_days,
            after.auth.login_rate_limit_window_secs
        ),
        (
            before.auth.session_ttl_hours,
            before.auth.remember_me_days,
            before.auth.login_rate_limit_window_secs
        )
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
}

#[tokio::test]
async fn test_update_config_rejects_session_ttls_past_the_representable_date() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, path) = test_app(pool).await;
    let before = config.read().await.auth.clone();

    for (key, body) in [
        (
            "auth.session_ttl_hours",
            serde_json::json!({ "auth": { "session_ttl_hours": u32::MAX } }),
        ),
        (
            "auth.remember_me_days",
            serde_json::json!({ "auth": { "remember_me_days": u32::MAX } }),
        ),
    ] {
        let (status, json) = post_config(router.clone(), body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{key}");
        assert!(
            json["error"].as_str().unwrap_or_default().contains(key),
            "error should name {key}, got: {}",
            json["error"]
        );
    }
    let after = config.read().await.auth.clone();
    assert_eq!(
        (after.session_ttl_hours, after.remember_me_days),
        (before.session_ttl_hours, before.remember_me_days)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
}

#[tokio::test]
async fn test_update_config_rejects_an_unknown_block_mode() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, _path) = test_app(pool).await;

    let (status, json) = post_config(
        router,
        serde_json::json!({ "blocking": { "block_mode": "bogus" } }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("block_mode"),
        "error should name the key, got: {}",
        json["error"]
    );
    assert_eq!(
        config.read().await.blocking.block_mode,
        ferrous_dns_domain::BlockResponseMode::NullIp
    );
}

/// A config file with this spelling loads as hit_rate, but the API only takes
/// a known name.
#[tokio::test]
async fn test_update_config_rejects_an_unknown_cache_eviction_strategy() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, _path) = test_app(pool).await;
    config.write().await.dns.cache_eviction_strategy =
        ferrous_dns_domain::config::CacheEvictionStrategy::Lfu;

    let (status, json) = post_config(
        router,
        serde_json::json!({ "dns": { "cache_eviction_strategy": "hit-rate" } }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("cache_eviction_strategy"),
        "error should name the key, got: {}",
        json["error"]
    );
    assert_eq!(
        config.read().await.dns.cache_eviction_strategy,
        ferrous_dns_domain::config::CacheEvictionStrategy::Lfu
    );
}

#[tokio::test]
async fn test_update_settings_rejects_an_unknown_block_mode() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, _path) = test_app(pool).await;
    config.write().await.blocking.block_mode = ferrous_dns_domain::BlockResponseMode::NxDomain;

    let (status, json) = post_settings(
        router,
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "block_mode": "bogus"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["success"], false);
    // An unknown value must not silently reset the mode to null_ip.
    assert_eq!(
        config.read().await.blocking.block_mode,
        ferrous_dns_domain::BlockResponseMode::NxDomain
    );
}

#[tokio::test]
async fn test_update_settings_rejects_a_local_dns_server_that_is_not_an_ip() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, _path) = test_app(pool).await;

    let (status, json) = post_settings(
        router,
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "local_domain": "lan",
            "local_dns_server": "router.lan:53"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("dns.local_dns_server"),
        "error should name the key, got: {}",
        json["error"]
    );
    assert_eq!(config.read().await.dns.local_dns_server, None);
}

/// A bare router IP means port 53, and is saved with the port spelled out.
#[tokio::test]
async fn test_a_local_dns_server_without_a_port_is_saved_with_port_53() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, path) = test_app(pool).await;

    let (status, json) = post_settings(
        router.clone(),
        serde_json::json!({
            "never_forward_non_fqdn": false,
            "never_forward_reverse_lookups": false,
            "local_domain": "lan",
            "local_dns_server": "192.168.1.1"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true, "{json}");
    assert_eq!(
        config.read().await.dns.local_dns_server.as_deref(),
        Some("192.168.1.1:53")
    );
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("local_dns_server = \"192.168.1.1:53\""));

    let (_, json) = post_config(
        router,
        serde_json::json!({ "dns": { "local_dns_server": "fe80::1" } }),
    )
    .await;
    assert_eq!(json["success"], true, "{json}");
    assert_eq!(
        config.read().await.dns.local_dns_server.as_deref(),
        Some("[fe80::1]:53")
    );
}

#[tokio::test]
async fn test_reload_keeps_the_running_config_when_the_file_fails_validation() {
    let pool = create_test_db().await;
    let (TestApp { router, config, .. }, path) = test_app(pool).await;
    std::fs::write(
        &path,
        "[server]\ndns_port = 53\nweb_port = 8080\nbind_address = \"0.0.0.0\"\n\
         [dns]\nupstream_servers = [\"1.1.1.1:53\"]\n[blocking]\nenabled = true\n\
         [logging]\nlevel = \"info\"\n[database]\nwal_checkpoint_interval_secs = 0\n",
    )
    .unwrap();
    let before = config.read().await.database.wal_checkpoint_interval_secs;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("database.wal_checkpoint_interval_secs"),
        "error should name the key, got: {}",
        json["error"]
    );
    assert_eq!(
        config.read().await.database.wal_checkpoint_interval_secs,
        before
    );
}

async fn post_reload(app: Router) -> Value {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

const RELOADED_FILE: &str = "[server]\ndns_port = 53\nweb_port = 8080\nbind_address = \"0.0.0.0\"\n\
     [dns]\nupstream_servers = []\n\
     [[dns.pools]]\nname = \"p1\"\nstrategy = \"Parallel\"\npriority = 1\nservers = [\"udp://9.9.9.9:53\"]\n\
     [blocking]\nenabled = true\n[logging]\nlevel = \"info\"\n[database]\n";

/// A reload loads the file the way startup does: the command-line overrides
/// still win, and changed upstream pools go live without a restart.
#[tokio::test]
async fn test_reload_hot_applies_pools_and_keeps_command_line_overrides() {
    let (_, path) = test_app(create_test_db().await).await;
    std::fs::write(&path, RELOADED_FILE).unwrap();
    let TestApp {
        router,
        config,
        pool_manager,
        ..
    } = TestApp::builder()
        .config_path(&path)
        .overrides(ferrous_dns_application::use_cases::ConfigOverrides {
            dns_port: Some(5353),
            ..Default::default()
        })
        .build()
        .await;

    let json = post_reload(router).await;

    assert_eq!(json["success"], true, "{json}");
    assert_eq!(config.read().await.server.dns_port, 5353);
    let servers = live_servers(&pool_manager);
    assert!(
        servers.iter().any(|s| s == "9.9.9.9:53") && !servers.iter().any(|s| s == "8.8.8.8:53"),
        "the reloaded pools must be live: {servers:?}"
    );
}

#[tokio::test]
async fn test_reload_waits_for_an_in_flight_config_save() {
    let (
        TestApp {
            router,
            state,
            config,
            ..
        },
        path,
    ) = test_app(create_test_db().await).await;
    std::fs::write(&path, RELOADED_FILE).unwrap();

    let save_in_flight = state.config_writer.lock().await;
    let mut reload = tokio::spawn(post_reload(router));
    let finished_early = tokio::time::timeout(Duration::from_millis(100), &mut reload)
        .await
        .is_ok();
    assert!(!finished_early, "a reload must not interleave with a save");
    assert_ne!(
        config.read().await.dns.pools[0].servers,
        ["udp://9.9.9.9:53"]
    );
    drop(save_in_flight);

    assert_eq!(reload.await.unwrap()["success"], true);
    assert_eq!(
        config.read().await.dns.pools[0].servers,
        ["udp://9.9.9.9:53"]
    );
}

/// Holds a hot-reload until released, then applies it to the live pools.
struct GatedLiveReload {
    live: Arc<dyn UpstreamReloadPort>,
    started: Arc<Notify>,
    release: Arc<Notify>,
    applied: Arc<Notify>,
}

#[async_trait::async_trait]
impl UpstreamReloadPort for GatedLiveReload {
    async fn reload_pools(&self, pools: Vec<UpstreamPool>) -> Result<(), DomainError> {
        self.started.notify_one();
        self.release.notified().await;
        self.live.reload_pools(pools).await?;
        self.applied.notify_one();
        Ok(())
    }
}

impl GatedLiveReload {
    fn wrap(live: Arc<dyn UpstreamReloadPort>) -> Arc<Self> {
        Arc::new(Self {
            live,
            started: Arc::default(),
            release: Arc::default(),
            applied: Arc::default(),
        })
    }

    /// Drives `request` until its pools are live and it waits on the config
    /// held by another writer, then drops it like a disconnected client.
    async fn drop_once_applied<'c>(
        &self,
        config: &'c RwLock<Config>,
        request: impl std::future::Future,
    ) -> RwLockWriteGuard<'c, Config> {
        let mut request = std::pin::pin!(request);
        tokio::select! {
            _ = &mut request => panic!("the request finished before its pool reload"),
            () = self.started.notified() => {}
        }
        // Stands in for a local-record or password writer holding the config across its save.
        let held = config.write().await;
        self.release.notify_one();
        tokio::select! {
            _ = &mut request => panic!("the request finished while the config was held"),
            () = self.applied.notified() => {}
        }
        held
    }
}

fn persisted_pools(path: &str) -> Vec<UpstreamPool> {
    TomlConfigFilePersistence
        .load_config_from_file(path)
        .unwrap()
        .dns
        .pools
}

#[tokio::test]
async fn test_a_dropped_config_update_still_saves_the_pools_it_applied() {
    let (
        TestApp {
            mut state,
            config,
            pool_manager,
            ..
        },
        path,
    ) = test_app(create_test_db().await).await;
    let gate = GatedLiveReload::wrap(state.dns.reload_upstream.clone());
    state.dns.reload_upstream = gate.clone();
    let writer = state.config_writer.clone();
    let router = create_api_router_with_openapi(state).0;

    let request = post_config(
        router,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    );
    let held = gate.drop_once_applied(&config, request).await;
    drop(held);
    // The save keeps the writer lock until it has finished.
    drop(writer.lock().await);

    let memory = config.read().await.dns.pools.clone();
    assert_eq!(memory[0].servers, ["udp://9.9.9.9:53"]);
    assert_eq!(persisted_pools(&path), memory);
    let live = live_servers(&pool_manager);
    assert!(
        live.iter().any(|s| s == "9.9.9.9:53") && !live.iter().any(|s| s == "8.8.8.8:53"),
        "{live:?}"
    );
}

#[tokio::test]
async fn test_a_dropped_reload_still_swaps_in_the_pools_it_applied() {
    let (
        TestApp {
            mut state,
            config,
            pool_manager,
            ..
        },
        path,
    ) = test_app(create_test_db().await).await;
    std::fs::write(&path, RELOADED_FILE).unwrap();
    let gate = GatedLiveReload::wrap(state.dns.reload_upstream.clone());
    state.reload_config = Some(Arc::new(ReloadConfigUseCase::new(
        config.clone(),
        state.config_writer.clone(),
        Arc::new(TomlConfigFilePersistence),
        Arc::from(path.as_str()),
        gate.clone(),
        ConfigOverrides::default(),
    )));
    let writer = state.config_writer.clone();
    let router = create_api_router_with_openapi(state).0;

    let held = gate.drop_once_applied(&config, post_reload(router)).await;
    drop(held);
    // The reload keeps the writer lock until it has finished.
    drop(writer.lock().await);

    let memory = config.read().await.dns.pools.clone();
    assert_eq!(memory, persisted_pools(&path));
    let live = live_servers(&pool_manager);
    assert!(
        live.iter().any(|s| s == "9.9.9.9:53") && !live.iter().any(|s| s == "8.8.8.8:53"),
        "{live:?}"
    );
}
