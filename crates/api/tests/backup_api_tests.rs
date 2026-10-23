use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_domain::{Config, LocalDnsRecord, LocalRecordType, UpstreamPool, UpstreamStrategy};
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder().sqlite_backup().build().await
}

fn build_multipart_body(boundary: &str, json_bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"backup.json\"\r\nContent-Type: application/json\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(json_bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn import_request(json_bytes: &[u8]) -> Request<Body> {
    let boundary = "testboundary";
    let body = build_multipart_body(boundary, json_bytes);
    Request::builder()
        .uri("/config/import")
        .method("POST")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

fn minimal_backup_json() -> Value {
    json!({
        "version": "1",
        "ferrous_version": "0.8.2",
        "exported_at": "2026-04-20T10:00:00Z",
        "config": {
            "server": { "dns_port": 53, "web_port": 8080, "bind_address": "0.0.0.0", "pihole_compat": false, "tls_cert_path": "", "tls_key_path": "", "tls_enabled": false },
            "dns": {
                "upstream_servers": [], "cache_enabled": true, "dnssec_enabled": false,
                "cache_eviction_strategy": "hit_rate", "cache_max_entries": 10000,
                "cache_min_hit_rate": 2.0, "cache_min_frequency": 10, "cache_min_lfuk_score": 1.5,
                "cache_compaction_interval": 600, "cache_refresh_threshold": 0.75,
                "cache_optimistic_refresh": true, "cache_adaptive_thresholds": false,
                "cache_access_window_secs": 43200, "cache_min_ttl": 60, "cache_max_ttl": 86400,
                "block_non_fqdn": true, "block_private_ptr": true,
                "local_domain": null, "local_dns_server": null
            },
            "blocking": { "enabled": false, "custom_blocked": [], "whitelist": [] },
            "logging": { "level": "info" },
            "auth": { "enabled": false, "session_ttl_hours": 24, "remember_me_days": 30, "login_rate_limit_attempts": 5, "login_rate_limit_window_secs": 900 }
        },
        "data": {
            "groups": [],
            "blocklist_sources": [],
            "local_records": []
        }
    })
}

async fn do_export(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

#[tokio::test]
async fn test_export_returns_200() {
    let app = test_app().await.router;
    let (status, _) = do_export(app).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_export_response_is_valid_json() {
    let app = test_app().await.router;
    let (_, json) = do_export(app).await;
    assert!(json.is_object());
    assert!(json.get("version").is_some());
    assert!(json.get("ferrous_version").is_some());
    assert!(json.get("exported_at").is_some());
    assert!(json.get("config").is_some());
    assert!(json.get("data").is_some());
}

#[tokio::test]
async fn test_export_version_is_one() {
    let app = test_app().await.router;
    let (_, json) = do_export(app).await;
    assert_eq!(json["version"], "1");
}

#[tokio::test]
async fn test_export_does_not_expose_password_hash() {
    let app = test_app().await.router;
    let (_, json) = do_export(app).await;
    let raw = serde_json::to_string(&json).unwrap();
    assert!(
        !raw.contains("password_hash"),
        "password_hash must never appear in the export"
    );
}

#[tokio::test]
async fn test_export_local_records_empty_when_config_has_none() {
    let app = test_app().await.router;
    let (_, json) = do_export(app).await;
    let records = json["data"]["local_records"].as_array().unwrap();
    assert_eq!(records.len(), 0);
}

#[tokio::test]
async fn test_export_includes_local_records_from_config() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "nas".to_string(),
            domain: Some("home".to_string()),
            ip: "192.168.1.100".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(300),
        });
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "pi".to_string(),
            domain: Some("home".to_string()),
            ip: "192.168.1.5".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(60),
        });
    }

    let (_, json) = do_export(app).await;
    let records = json["data"]["local_records"].as_array().unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["hostname"], "nas");
    assert_eq!(records[0]["ip"], "192.168.1.100");
    assert_eq!(records[1]["hostname"], "pi");
}

#[tokio::test]
async fn test_export_includes_block_response_config() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.blocking.block_mode = ferrous_dns_domain::BlockResponseMode::NxDomain;
        cfg.blocking.sinkhole_ipv4 = Some(std::net::Ipv4Addr::new(192, 168, 1, 2));
        cfg.blocking.sinkhole_ipv6 = Some("fd00::2".parse().unwrap());
    }

    let (_, json) = do_export(app).await;
    let blocking = &json["config"]["blocking"];
    assert_eq!(blocking["block_mode"], "nxdomain");
    assert_eq!(blocking["sinkhole_ipv4"], "192.168.1.2");
    assert_eq!(blocking["sinkhole_ipv6"], "fd00::2");
}

#[tokio::test]
async fn test_export_includes_groups_from_database() {
    let app = test_app().await.router;
    let (_, json) = do_export(app).await;

    let groups = json["data"]["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "Protected");
}

#[tokio::test]
async fn test_export_content_disposition_header_present() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        disposition.contains("attachment"),
        "Content-Disposition must be attachment, got: {disposition}"
    );
    assert!(
        disposition.contains("ferrous-backup"),
        "Filename must contain ferrous-backup, got: {disposition}"
    );
}

#[tokio::test]
async fn test_import_valid_backup_returns_success_true() {
    let app = test_app().await.router;
    let payload = serde_json::to_vec(&minimal_backup_json()).unwrap();

    let response = app.oneshot(import_request(&payload)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert!(json.get("summary").is_some());
}

#[tokio::test]
async fn test_dns64_config_survives_export_import_roundtrip() {
    // App A: enable DNS64 with a non-default prefix, then export — exercises the
    // real `export.rs` dns64 mapping.
    let TestApp {
        router: app_a,
        config: config_a,
        ..
    } = test_app().await;
    {
        let mut cfg = config_a.write().await;
        cfg.dns64.enabled = true;
        cfg.dns64.prefix = "2001:db8:64::/96".to_string();
    }
    let (status, exported) = do_export(app_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(exported["config"]["dns64"]["enabled"], true);
    assert_eq!(exported["config"]["dns64"]["prefix"], "2001:db8:64::/96");

    // App B (fresh, DNS64 default-disabled with the well-known prefix): import the
    // exported backup — exercises the real `import.rs` dns64 mapping. Both fields
    // must land in the live config, proving the round-trip is not just defaults.
    let TestApp {
        router: app_b,
        config: config_b,
        ..
    } = test_app().await;
    {
        let cfg = config_b.read().await;
        assert!(
            !cfg.dns64.enabled,
            "fresh app must start with DNS64 disabled"
        );
        assert_ne!(cfg.dns64.prefix, "2001:db8:64::/96");
    }

    let payload = serde_json::to_vec(&exported).unwrap();
    let response = app_b.oneshot(import_request(&payload)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);

    let cfg = config_b.read().await;
    assert!(
        cfg.dns64.enabled,
        "imported DNS64 enabled flag must survive"
    );
    assert_eq!(cfg.dns64.prefix, "2001:db8:64::/96");
}

#[tokio::test]
async fn test_import_new_local_record_is_added_to_config() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([{
        "hostname": "printer",
        "domain": "home",
        "ip": "10.0.0.50",
        "record_type": "A",
        "ttl": 300
    }]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 1);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert!(cfg
        .dns
        .local_records
        .iter()
        .any(|r| r.hostname == "printer"));
}

#[tokio::test]
async fn test_import_existing_local_record_is_skipped() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "server".to_string(),
            domain: Some("local".to_string()),
            ip: "10.0.0.1".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(300),
        });
    }

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([{
        "hostname": "server",
        "domain": "local",
        "ip": "10.0.0.1",
        "record_type": "A",
        "ttl": 300
    }]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 0);
    assert_eq!(json["summary"]["local_records_skipped"], 1);
}

#[tokio::test]
async fn test_import_aaaa_beside_existing_a_for_same_name_is_added() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "nas".to_string(),
            domain: Some("lan".to_string()),
            ip: "10.0.0.2".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(300),
        });
    }

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([{
        "hostname": "nas",
        "domain": "lan",
        "ip": "fd00::2",
        "record_type": "AAAA",
        "ttl": 300
    }]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 1);
    assert_eq!(json["summary"]["local_records_skipped"], 0);
    let cfg = config.read().await;
    let mut types: Vec<_> = cfg
        .dns
        .local_records
        .iter()
        .filter(|r| r.hostname == "nas")
        .map(|r| r.record_type.as_str())
        .collect();
    types.sort_unstable();
    assert_eq!(types, ["A", "AAAA"]);
}

#[tokio::test]
async fn test_import_is_idempotent() {
    let import_uc = test_app().await.state.backup.import;

    let mut backup = minimal_backup_json();
    backup["data"]["groups"] = json!([{ "name": "Protected", "comment": null }]);

    let payload = serde_json::to_vec(&backup).unwrap();

    // Protected already exists in the DB, so it is skipped.
    let snapshot: ferrous_dns_application::use_cases::BackupSnapshot =
        serde_json::from_slice(&payload).unwrap();
    let summary1 = import_uc.execute(snapshot.clone()).await.unwrap();
    assert_eq!(summary1.groups_skipped, 1);
    assert_eq!(summary1.groups_imported, 0);

    // A second import yields the same result.
    let summary2 = import_uc.execute(snapshot).await.unwrap();
    assert_eq!(summary2.groups_skipped, 1);
    assert_eq!(summary2.groups_imported, 0);
}

#[tokio::test]
async fn test_import_new_group_is_created() {
    let app = test_app().await.router;

    let mut backup = minimal_backup_json();
    backup["data"]["groups"] = json!([{ "name": "HomeDevices", "comment": "IoT group" }]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["groups_imported"], 1);
    assert_eq!(json["summary"]["groups_skipped"], 0);
}

#[tokio::test]
async fn test_import_without_file_returns_bad_request() {
    let app = test_app().await.router;

    let boundary = "testboundary";
    let body = format!("--{boundary}--\r\n");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/import")
                .method("POST")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_corrupt_json_returns_bad_request() {
    let app = test_app().await.router;
    let response = app
        .oneshot(import_request(b"not valid json {{{"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_wrong_version_returns_error() {
    let app = test_app().await.router;

    let mut backup = minimal_backup_json();
    backup["version"] = json!("99");

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Expected error status for incompatible version, got: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_import_summary_errors_empty_on_success() {
    let app = test_app().await.router;
    let payload = serde_json::to_vec(&minimal_backup_json()).unwrap();

    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(
        json["errors"].as_array().unwrap().len(),
        0,
        "errors must be empty on clean import"
    );
}

#[tokio::test]
async fn test_import_multiple_records_counted_correctly() {
    let app = test_app().await.router;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "alpha", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
        { "hostname": "beta",  "domain": "lan", "ip": "10.0.0.2", "record_type": "A", "ttl": 300 },
        { "hostname": "gamma", "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
    ]);
    backup["data"]["groups"] = json!([
        { "name": "Guests",  "comment": null },
        { "name": "Protected", "comment": null },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 3);
    assert_eq!(json["summary"]["local_records_skipped"], 0);
    assert_eq!(json["summary"]["groups_imported"], 1);
    assert_eq!(json["summary"]["groups_skipped"], 1);
}

#[tokio::test]
async fn test_import_partial_overlap_counts_each_correctly() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    // Two of the records already exist in the config.
    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "existing-a".to_string(),
            domain: Some("lan".to_string()),
            ip: "10.0.0.1".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(300),
        });
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "existing-b".to_string(),
            domain: Some("lan".to_string()),
            ip: "10.0.0.2".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(300),
        });
    }

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "existing-a", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
        { "hostname": "existing-b", "domain": "lan", "ip": "10.0.0.2", "record_type": "A", "ttl": 300 },
        { "hostname": "new-c",      "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
        { "hostname": "new-d",      "domain": "lan", "ip": "10.0.0.4", "record_type": "A", "ttl": 300 },
        { "hostname": "new-e",      "domain": "lan", "ip": "10.0.0.5", "record_type": "A", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 3);
    assert_eq!(json["summary"]["local_records_skipped"], 2);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 5);
}

#[tokio::test]
async fn test_import_ipv6_aaaa_records() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "v6host",  "domain": "lan", "ip": "2001:db8::1", "record_type": "AAAA", "ttl": 300 },
        { "hostname": "v6host2", "domain": "lan", "ip": "2001:db8::2", "record_type": "AAAA", "ttl": null },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 2);

    let cfg = config.read().await;
    assert!(cfg
        .dns
        .local_records
        .iter()
        .any(|r| r.hostname == "v6host" && r.record_type == LocalRecordType::AAAA));
}

#[tokio::test]
async fn test_import_record_without_domain_is_distinct_from_record_with_domain() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "server".to_string(),
            domain: None,
            ip: "10.0.0.1".parse().unwrap(),
            record_type: LocalRecordType::A,
            ttl: Some(300),
        });
    }

    // "server" with domain "lan" must be treated as distinct from the bare "server".
    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "server", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 1);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 2);
}

#[tokio::test]
async fn test_import_same_hostname_different_domain_are_distinct_records() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "pi", "domain": "home",   "ip": "192.168.1.10", "record_type": "A", "ttl": 300 },
        { "hostname": "pi", "domain": "office", "ip": "10.0.0.10",    "record_type": "A", "ttl": 300 },
        { "hostname": "pi", "domain": "lab",    "ip": "172.16.0.10",  "record_type": "A", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 3);

    let cfg = config.read().await;
    assert_eq!(
        cfg.dns
            .local_records
            .iter()
            .filter(|r| r.hostname == "pi")
            .count(),
        3
    );
}

#[tokio::test]
async fn test_sequential_imports_accumulate_distinct_records() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    let mut backup1 = minimal_backup_json();
    backup1["data"]["local_records"] = json!([
        { "hostname": "alpha", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
        { "hostname": "beta",  "domain": "lan", "ip": "10.0.0.2", "record_type": "A", "ttl": 300 },
        { "hostname": "gamma", "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
    ]);

    let r1 = app
        .clone()
        .oneshot(import_request(&serde_json::to_vec(&backup1).unwrap()))
        .await
        .unwrap();
    let b1: Value =
        serde_json::from_slice(&r1.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(b1["summary"]["local_records_imported"], 3);
    assert_eq!(b1["summary"]["local_records_skipped"], 0);

    // gamma was already imported; the other two are new.
    let mut backup2 = minimal_backup_json();
    backup2["data"]["local_records"] = json!([
        { "hostname": "gamma", "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
        { "hostname": "delta", "domain": "lan", "ip": "10.0.0.4", "record_type": "A", "ttl": 300 },
        { "hostname": "epsilon","domain": "lan", "ip": "10.0.0.5", "record_type": "A", "ttl": 300 },
    ]);

    let r2 = app
        .oneshot(import_request(&serde_json::to_vec(&backup2).unwrap()))
        .await
        .unwrap();
    let b2: Value =
        serde_json::from_slice(&r2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(b2["summary"]["local_records_imported"], 2);
    assert_eq!(b2["summary"]["local_records_skipped"], 1);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 5);
}

#[tokio::test]
async fn test_import_large_batch_of_records() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    let records: Vec<Value> = (1..=20)
        .map(|i| {
            json!({
                "hostname": format!("host-{i:02}"),
                "domain": "corp",
                "ip": format!("10.1.0.{i}"),
                "record_type": "A",
                "ttl": 300
            })
        })
        .collect();

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!(records);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 20);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 20);
}

#[tokio::test]
async fn test_import_large_batch_second_run_skips_all() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    let records: Vec<Value> = (1..=10)
        .map(|i| {
            json!({
                "hostname": format!("srv-{i:02}"),
                "domain": "prod",
                "ip": format!("172.16.0.{i}"),
                "record_type": "A",
                "ttl": 60
            })
        })
        .collect();

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!(records);
    let payload = serde_json::to_vec(&backup).unwrap();

    app.clone().oneshot(import_request(&payload)).await.unwrap();

    assert_eq!(config.read().await.dns.local_records.len(), 10);

    // Everything already exists on the second run.
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 0);
    assert_eq!(json["summary"]["local_records_skipped"], 10);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 10);
}

#[tokio::test]
async fn test_export_then_import_is_a_complete_round_trip() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    {
        let mut cfg = config.write().await;
        for i in 1..=5 {
            cfg.dns.local_records.push(LocalDnsRecord {
                hostname: format!("node-{i}"),
                domain: Some("cluster".to_string()),
                ip: format!("192.168.10.{i}").parse().unwrap(),
                record_type: LocalRecordType::A,
                ttl: Some(120),
            });
        }
    }

    let export_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/config/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(export_response.status(), StatusCode::OK);
    let export_bytes = export_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let export_json: Value = serde_json::from_slice(&export_bytes).unwrap();

    let exported_records = export_json["data"]["local_records"].as_array().unwrap();
    assert_eq!(exported_records.len(), 5);
    assert!(exported_records.iter().any(|r| r["hostname"] == "node-1"));
    assert!(exported_records.iter().any(|r| r["hostname"] == "node-5"));

    // Re-importing the export must skip every record since all already exist.
    let import_response = app.oneshot(import_request(&export_bytes)).await.unwrap();

    let body = import_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let import_json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(import_json["success"], true);
    assert_eq!(import_json["summary"]["local_records_imported"], 0);
    assert_eq!(import_json["summary"]["local_records_skipped"], 5);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 5);
}

#[tokio::test]
async fn test_import_mixed_ipv4_and_ipv6_records() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    let mut backup = minimal_backup_json();
    // Each hostname is unique — the duplicate key is hostname+domain, not record_type,
    // so all four records must be imported independently.
    backup["data"]["local_records"] = json!([
        { "hostname": "srv-v4a", "domain": "lan", "ip": "10.0.0.1",    "record_type": "A",    "ttl": 300 },
        { "hostname": "srv-v6a", "domain": "lan", "ip": "::1",          "record_type": "AAAA", "ttl": 300 },
        { "hostname": "srv-v4b", "domain": "lan", "ip": "10.0.0.2",    "record_type": "A",    "ttl": 300 },
        { "hostname": "srv-v6b", "domain": "lan", "ip": "2001:db8::1", "record_type": "AAAA", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 4);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 4);
    let a_count = cfg
        .dns
        .local_records
        .iter()
        .filter(|r| r.record_type == LocalRecordType::A)
        .count();
    let aaaa_count = cfg
        .dns
        .local_records
        .iter()
        .filter(|r| r.record_type == LocalRecordType::AAAA)
        .count();
    assert_eq!(a_count, 2);
    assert_eq!(aaaa_count, 2);
}

#[tokio::test]
async fn test_mdns_enabled_survives_export_import_round_trip() {
    let TestApp {
        router: app,
        config,
        ..
    } = test_app().await;

    // Enable mDNS in the live config, then export.
    config.write().await.dns.mdns_enabled = true;

    let export_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/config/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export_response.status(), StatusCode::OK);
    let export_bytes = export_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let export_json: Value = serde_json::from_slice(&export_bytes).unwrap();
    // Export must carry the flag — covers build_snapshot_config in export.rs.
    assert_eq!(export_json["config"]["dns"]["mdns_enabled"], true);

    // Flip it back off, then import the snapshot. Import must restore it to true,
    // which exercises the apply_config field mapping in import.rs (not just serde).
    config.write().await.dns.mdns_enabled = false;

    let import_response = app.oneshot(import_request(&export_bytes)).await.unwrap();
    let body = import_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let import_json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(import_json["success"], true);
    assert_eq!(import_json["summary"]["config_updated"], true);

    assert!(config.read().await.dns.mdns_enabled);
}

#[tokio::test]
async fn test_import_does_not_restore_a_config_section_that_fails_validation() {
    let TestApp { router, config, .. } = test_app().await;
    let before = config.read().await.dns.cache_compaction_interval;
    let mut backup = minimal_backup_json();
    backup["config"]["dns"]["cache_compaction_interval"] = json!(0);
    let payload = serde_json::to_vec(&backup).unwrap();

    let response = router.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["summary"]["config_updated"], false);
    let errors = json["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|e| e
            .as_str()
            .unwrap_or_default()
            .contains("dns.cache_compaction_interval")),
        "the error should name the key, got: {errors:?}"
    );
    assert_eq!(config.read().await.dns.cache_compaction_interval, before);
}

async fn import(app: Router, payload: &[u8]) -> Value {
    let response = app.oneshot(import_request(payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn json_of<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

/// What the round trip below sets: pools with a conditional route, rate
/// limiting, and every malware setting away from its default.
fn customize_pools_rate_limit_and_malware(cfg: &mut Config, office_group: i64) {
    cfg.dns.pools = vec![
        UpstreamPool {
            name: "main".into(),
            strategy: UpstreamStrategy::Parallel,
            servers: vec!["udp://9.9.9.9:53".into()],
            ..Default::default()
        },
        UpstreamPool {
            name: "office".into(),
            strategy: UpstreamStrategy::Failover,
            priority: 2,
            servers: vec!["udp://10.0.0.53:53".into()],
            domains: vec!["corp.example".into()],
            groups: vec![office_group],
            internal: true,
            ..Default::default()
        },
    ];
    cfg.dns.rate_limit.enabled = true;
    cfg.dns.rate_limit.queries_per_second = 77;
    cfg.dns.rate_limit.whitelist = vec!["192.0.2.0/24".into()];
    cfg.dns.malware_detection_enabled = !cfg.dns.malware_detection_enabled;
    cfg.dns.rebinding_protection_enabled = !cfg.dns.rebinding_protection_enabled;
    cfg.dns.rebinding_allowlist = vec!["nas.example".into()];
    cfg.dns.tunneling_detection.max_fqdn_length = 199;
    cfg.dns.dga_detection.sld_max_length = 33;
    cfg.dns.nxdomain_hijack.probe_interval_secs = 1234;
    cfg.dns.response_ip_filter.ip_list_urls = vec!["https://example.com/c2.txt".into()];
}

/// Every setting the round trip covers, as JSON, for one comparison.
fn pools_rate_limit_and_malware(cfg: &Config) -> Value {
    json!({
        "pools": json_of(&cfg.dns.pools),
        "rate_limit": json_of(&cfg.dns.rate_limit),
        "malware_detection_enabled": cfg.dns.malware_detection_enabled,
        "rebinding_protection_enabled": cfg.dns.rebinding_protection_enabled,
        "rebinding_allowlist": json_of(&cfg.dns.rebinding_allowlist),
        "tunneling_detection": json_of(&cfg.dns.tunneling_detection),
        "dga_detection": json_of(&cfg.dns.dga_detection),
        "nxdomain_hijack": json_of(&cfg.dns.nxdomain_hijack),
        "response_ip_filter": json_of(&cfg.dns.response_ip_filter),
    })
}

#[tokio::test]
async fn test_pools_rate_limit_and_malware_settings_survive_export_import_round_trip() {
    let TestApp { router, config, .. } = TestApp::builder()
        .sqlite_backup()
        .groups(&["office"])
        .build()
        .await;
    customize_pools_rate_limit_and_malware(&mut *config.write().await, 2);
    let expected = pools_rate_limit_and_malware(&*config.read().await);

    let (status, exported) = do_export(router.clone()).await;
    assert_eq!(status, StatusCode::OK);
    {
        let defaults = Config::default();
        let mut cfg = config.write().await;
        cfg.dns.pools = vec![UpstreamPool {
            name: "other".into(),
            servers: vec!["udp://1.1.1.1:53".into()],
            ..Default::default()
        }];
        cfg.dns.rate_limit = defaults.dns.rate_limit;
        cfg.dns.malware_detection_enabled = defaults.dns.malware_detection_enabled;
        cfg.dns.rebinding_protection_enabled = defaults.dns.rebinding_protection_enabled;
        cfg.dns.rebinding_allowlist = defaults.dns.rebinding_allowlist;
        cfg.dns.tunneling_detection = defaults.dns.tunneling_detection;
        cfg.dns.dga_detection = defaults.dns.dga_detection;
        cfg.dns.nxdomain_hijack = defaults.dns.nxdomain_hijack;
        cfg.dns.response_ip_filter = defaults.dns.response_ip_filter;
    }

    let json = import(router, &serde_json::to_vec(&exported).unwrap()).await;

    assert_eq!(json["summary"]["config_updated"], true, "{json}");
    assert_eq!(
        pools_rate_limit_and_malware(&*config.read().await),
        expected
    );
}

/// A backup from another server names groups by that server's ids, so a
/// pool's route and a blocklist source follow each group by its name.
#[tokio::test]
async fn test_import_maps_pool_and_blocklist_source_groups_by_name() {
    // "office" is group 2 here; "kids" does not exist yet and becomes group 3.
    let TestApp { router, config, .. } = TestApp::builder()
        .sqlite_backup()
        .groups(&["office"])
        .build()
        .await;
    let mut backup = minimal_backup_json();
    backup["data"]["groups"] = json!([
        { "id": 1, "name": "Protected", "comment": null },
        { "id": 7, "name": "kids", "comment": null },
        { "id": 9, "name": "office", "comment": null }
    ]);
    backup["config"]["dns"]["pools"] = json!([
        {
            "name": "main", "strategy": "Parallel", "priority": 1,
            "servers": ["udp://9.9.9.9:53"], "weight": null,
            "domains": [], "groups": [], "internal": false
        },
        {
            "name": "office", "strategy": "Failover", "priority": 2,
            "servers": ["udp://10.0.0.53:53"], "weight": null,
            "domains": ["corp.example"], "groups": [9, 7], "internal": true
        }
    ]);
    backup["data"]["blocklist_sources"] = json!([{
        "name": "kids-list", "url": "https://example.com/kids.txt",
        "group_ids": [1, 7], "comment": null, "enabled": true
    }]);

    let json = import(router.clone(), &serde_json::to_vec(&backup).unwrap()).await;

    assert_eq!(json["errors"], json!([]), "{json}");
    let pools = config.read().await.dns.pools.clone();
    assert_eq!(pools.len(), 2, "{pools:?}");
    assert_eq!(pools[1].groups, vec![2, 3]);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/blocklist-sources")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sources: Value = serde_json::from_slice(&body).unwrap();
    let kids = sources
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "kids-list")
        .unwrap_or_else(|| panic!("kids-list was not imported: {sources}"));
    assert_eq!(kids["group_ids"], json!([1, 3]));
}

/// A group the backup lists but this server cannot create leaves a route to
/// it untranslatable; the error must say so rather than blame the backup.
#[tokio::test]
async fn test_import_names_a_route_to_a_group_that_could_not_be_created() {
    let TestApp { router, config, .. } = test_app().await;
    let pools_before = config.read().await.dns.pools.clone();
    let mut backup = minimal_backup_json();
    backup["data"]["groups"] = json!([
        { "id": 7, "name": "kids", "comment": "x".repeat(501) }
    ]);
    backup["config"]["dns"]["pools"] = json!([
        {
            "name": "main", "strategy": "Parallel", "priority": 1,
            "servers": ["udp://9.9.9.9:53"]
        },
        {
            "name": "kids-filter", "strategy": "Failover", "priority": 2,
            "servers": ["udp://1.1.1.3:53"], "domains": ["example.org"], "groups": [7]
        }
    ]);

    let json = import(router, &serde_json::to_vec(&backup).unwrap()).await;

    assert_eq!(json["summary"]["config_updated"], false, "{json}");
    let errors = json["errors"].as_array().unwrap();
    assert!(
        errors.iter().any(|e| e
            .as_str()
            .unwrap_or_default()
            .contains("pool 'kids-filter' is routed for client group 7, which is not in the backup or could not be created here")),
        "got {errors:?}"
    );
    assert_eq!(config.read().await.dns.pools, pools_before);
}

/// Guard: a backup from before these settings were exported keeps the
/// target's own.
#[tokio::test]
async fn test_import_of_an_older_backup_keeps_pools_rate_limit_and_malware_settings() {
    let TestApp { router, config, .. } = TestApp::builder()
        .sqlite_backup()
        .groups(&["office"])
        .build()
        .await;
    customize_pools_rate_limit_and_malware(&mut *config.write().await, 2);
    let before = pools_rate_limit_and_malware(&*config.read().await);

    let json = import(router, &serde_json::to_vec(&minimal_backup_json()).unwrap()).await;

    assert_eq!(json["summary"]["config_updated"], true, "{json}");
    assert_eq!(pools_rate_limit_and_malware(&*config.read().await), before);
}

#[tokio::test]
async fn test_import_that_changes_the_config_asks_for_a_restart() {
    let TestApp { router, state, .. } = test_app().await;
    let mut backup = minimal_backup_json();
    backup["config"]["server"]["dns_port"] = json!(5353);
    backup["config"]["dns"]["upstream_servers"] = json!(["udp://1.1.1.1:53"]);

    let json = import(router, &serde_json::to_vec(&backup).unwrap()).await;

    assert_eq!(json["summary"]["config_updated"], true, "{json}");
    assert_eq!(json["restart_required"], true);
    assert!(
        state.is_restart_pending(),
        "the restart banner must be raised"
    );
}

/// Guard: restoring the backup just taken changes nothing to restart for.
#[tokio::test]
async fn test_import_of_an_unchanged_config_asks_for_no_restart() {
    let TestApp { router, state, .. } = test_app().await;
    let (_, exported) = do_export(router.clone()).await;

    let json = import(router, &serde_json::to_vec(&exported).unwrap()).await;

    assert_eq!(json["summary"]["config_updated"], true, "{json}");
    assert_ne!(json["restart_required"], true);
    assert!(!state.is_restart_pending());
}
