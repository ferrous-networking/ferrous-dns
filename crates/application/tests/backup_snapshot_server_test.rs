//! Backward/forward compatibility of the backup `[server]` snapshot fields:
//! backups made before `web_bind_address` existed carry no such key, and the
//! field must round-trip when present.

use ferrous_dns_application::use_cases::backup::snapshot::SnapshotServerConfig;

fn server_json(extra: serde_json::Value) -> serde_json::Value {
    let mut json = serde_json::json!({
        "dns_port": 53,
        "web_port": 8080,
        "bind_address": "0.0.0.0",
        "pihole_compat": false,
        "tls_cert_path": "/data/cert.pem",
        "tls_key_path": "/data/key.pem",
        "tls_enabled": false
    });
    json.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json
}

#[test]
fn an_older_backup_without_web_bind_address_parses_to_none() {
    let parsed: SnapshotServerConfig =
        serde_json::from_value(server_json(serde_json::json!({}))).unwrap();
    assert_eq!(parsed.web_bind_address, None);
}

#[test]
fn web_bind_address_round_trips() {
    let parsed: SnapshotServerConfig = serde_json::from_value(server_json(
        serde_json::json!({"web_bind_address": "127.0.0.1"}),
    ))
    .unwrap();
    assert_eq!(parsed.web_bind_address.as_deref(), Some("127.0.0.1"));

    let reserialized = serde_json::to_value(&parsed).unwrap();
    assert_eq!(reserialized["web_bind_address"], "127.0.0.1");
}
