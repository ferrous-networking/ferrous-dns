//! A client name typed in by hand must survive the hostname sync, which
//! names clients from PTR records every five minutes and re-checks a client
//! an hour after its name last changed. Names the sync set itself keep
//! following the PTR record.

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_application::ports::{ClientRepository, HostnameResolver};
use ferrous_dns_application::use_cases::SyncHostnamesUseCase;
use ferrous_dns_domain::DomainError;
use helpers::TestApp;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use tower::ServiceExt;

mod helpers;

const DEVICE: &str = "192.168.1.50";
const MANUAL_NAME: &str = "Living room TV";

/// The router's PTR answer for every address.
struct RouterPtr(&'static str);

#[async_trait]
impl HostnameResolver for RouterPtr {
    async fn resolve_hostname(&self, _ip: IpAddr) -> Result<Option<String>, DomainError> {
        Ok(Some(self.0.to_string()))
    }
}

fn device() -> IpAddr {
    DEVICE.parse().unwrap()
}

async fn send(app: &TestApp, method: &str, uri: &str, body: Value) -> StatusCode {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The device keeps sending queries, so the sync keeps looking at it.
async fn device_is_active(app: &TestApp) -> i64 {
    app.client_repo.update_last_seen(device()).await.unwrap();
    app.client_repo.flush_writes().await;
    app.client_repo
        .get_or_create(device())
        .await
        .unwrap()
        .id
        .unwrap()
}

/// Runs the sync after its one-hour re-check interval has passed.
async fn sync_an_hour_later(app: &TestApp, ptr: &'static str) {
    sqlx::query("UPDATE clients SET last_hostname_update = datetime('now', '-2 hours')")
        .execute(&app.pool)
        .await
        .unwrap();
    SyncHostnamesUseCase::new(app.client_repo.clone(), Arc::new(RouterPtr(ptr)))
        .execute(50)
        .await
        .unwrap();
}

async fn hostname(app: &TestApp) -> Option<String> {
    app.client_repo
        .get_or_create(device())
        .await
        .unwrap()
        .hostname
        .map(|h| h.to_string())
}

#[tokio::test]
async fn a_name_given_when_adding_the_client_survives_the_sync() {
    let app = TestApp::new().await;
    device_is_active(&app).await;

    let status = send(
        &app,
        "POST",
        "/clients",
        json!({ "ip_address": DEVICE, "hostname": MANUAL_NAME }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    sync_an_hour_later(&app, "android-3f2a.lan").await;

    assert_eq!(hostname(&app).await.as_deref(), Some(MANUAL_NAME));
}

#[tokio::test]
async fn a_rename_survives_the_sync() {
    let app = TestApp::new().await;
    let id = device_is_active(&app).await;
    sync_an_hour_later(&app, "android-3f2a.lan").await;

    let status = send(
        &app,
        "PATCH",
        &format!("/clients/{id}"),
        json!({ "hostname": MANUAL_NAME }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    sync_an_hour_later(&app, "android-3f2a.lan").await;

    assert_eq!(hostname(&app).await.as_deref(), Some(MANUAL_NAME));
}

/// Guard: a name the sync set is replaced when the PTR record changes.
#[tokio::test]
async fn a_name_from_the_sync_follows_the_ptr_record() {
    let app = TestApp::new().await;
    device_is_active(&app).await;

    sync_an_hour_later(&app, "android-3f2a.lan").await;
    assert_eq!(hostname(&app).await.as_deref(), Some("android-3f2a.lan"));

    sync_an_hour_later(&app, "living-room-tv.lan").await;
    assert_eq!(hostname(&app).await.as_deref(), Some("living-room-tv.lan"));
}
