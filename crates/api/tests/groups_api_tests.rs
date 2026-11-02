use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use helpers::{get_json, TestApp};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn send_json(app: axum::Router, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .method(method)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn test_create_group_keeps_malware_detection_on_unless_told_otherwise() {
    let app = TestApp::new().await.router;

    let (status, kids) = send_json(app.clone(), "POST", "/groups", json!({"name": "Kids"})).await;
    assert_eq!(status, StatusCode::CREATED, "{kids}");
    assert_eq!(kids["malware_detection_enabled"], true);

    let (status, servers) = send_json(
        app.clone(),
        "POST",
        "/groups",
        json!({"name": "Servers", "malware_detection_enabled": false}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{servers}");
    assert_eq!(servers["malware_detection_enabled"], false);

    let listed = get_json(app, "/groups").await;
    let flags: Vec<(&str, &Value)> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (g["name"].as_str().unwrap(), &g["malware_detection_enabled"]))
        .collect();
    assert_eq!(
        flags,
        [
            ("Protected", &Value::Bool(true)),
            ("Kids", &Value::Bool(true)),
            ("Servers", &Value::Bool(false)),
        ]
    );
}

#[tokio::test]
async fn test_update_group_switches_malware_detection_and_keeps_it_when_omitted() {
    let app = TestApp::builder().groups(&["Servers"]).build().await.router;

    let (status, updated) = send_json(
        app.clone(),
        "PUT",
        "/groups/2",
        json!({"malware_detection_enabled": false}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["malware_detection_enabled"], false);
    assert_eq!(updated["name"], "Servers");

    let (_, renamed) = send_json(
        app.clone(),
        "PUT",
        "/groups/2",
        json!({"name": "Monitoring"}),
    )
    .await;
    assert_eq!(
        renamed["malware_detection_enabled"], false,
        "an omitted flag is kept"
    );

    let fetched = get_json(app, "/groups/2").await;
    assert_eq!(fetched["malware_detection_enabled"], false);
}

/// Unlike `enabled`, the default group may switch the detectors off.
#[tokio::test]
async fn test_default_group_can_switch_malware_detection_off() {
    let app = TestApp::new().await.router;

    let (status, updated) = send_json(
        app,
        "PUT",
        "/groups/1",
        json!({"malware_detection_enabled": false}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["malware_detection_enabled"], false);
}
