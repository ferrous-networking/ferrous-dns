use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use helpers::{get_json, TestApp};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder().groups(&["Office"]).build().await
}

#[tokio::test]
async fn test_get_all_managed_domains_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["data"].is_array());
    assert_eq!(json["data"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"], 0);
}

#[tokio::test]
async fn test_create_managed_domain_deny_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Block Ads",
        "domain": "ads.example.com",
        "action": "deny",
        "group_id": 1,
        "comment": "Block ads domain",
        "enabled": true
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["id"].is_number());
    assert_eq!(json["name"], "Block Ads");
    assert_eq!(json["domain"], "ads.example.com");
    assert_eq!(json["action"], "deny");
    assert_eq!(json["group_id"], 1);
    assert_eq!(json["comment"], "Block ads domain");
    assert_eq!(json["enabled"], true);
    assert!(json["created_at"].is_string());
}

#[tokio::test]
async fn test_create_managed_domain_allow_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Allow Company",
        "domain": "mycompany.com",
        "action": "allow",
        "group_id": 1
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["action"], "allow");
    assert_eq!(json["enabled"], true);
    assert!(json["comment"].is_null());
}

#[tokio::test]
async fn test_create_managed_domain_invalid_action() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad Action",
        "domain": "ads.example.com",
        "action": "block"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_managed_domain_duplicate_name() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Duplicate",
        "domain": "ads.example.com",
        "action": "deny"
    });

    app.clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_create_managed_domain_invalid_group() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Bad Group",
        "domain": "ads.example.com",
        "action": "deny",
        "group_id": 999
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_managed_domain_by_id() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Get By ID",
        "domain": "ads.example.com",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/managed-domains/{}", id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], id);
    assert_eq!(json["name"], "Get By ID");
}

#[tokio::test]
async fn test_get_managed_domain_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_managed_domain_toggle_enabled() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Toggle Domain",
        "domain": "ads.example.com",
        "action": "deny",
        "enabled": true
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/managed-domains/{}", id))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["enabled"], false);
}

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
async fn test_update_managed_domain_null_comment_clears_it_and_absent_keeps_it() {
    let app = test_app().await.router;
    let (_, created) = send_json(
        app.clone(),
        "POST",
        "/managed-domains",
        json!({ "name": "Commented", "domain": "ads.example.com", "action": "deny",
                "comment": "temporary" }),
    )
    .await;
    let uri = format!("/managed-domains/{}", created["id"].as_i64().unwrap());

    let (status, kept) = send_json(app.clone(), "PUT", &uri, json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kept["comment"], "temporary");

    let (status, cleared) = send_json(app, "PUT", &uri, json!({ "comment": null })).await;
    assert_eq!(status, StatusCode::OK);
    assert!(cleared["comment"].is_null(), "got {}", cleared["comment"]);
}

#[tokio::test]
async fn test_update_managed_domain_not_found() {
    let app = test_app().await.router;

    let update_payload = json!({ "enabled": false });
    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains/999")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_managed_domain_success() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "To Delete",
        "domain": "ads.example.com",
        "action": "deny"
    });

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let created: Value = serde_json::from_slice(&create_body).unwrap();
    let id = created["id"].as_i64().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/managed-domains/{}", id))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_managed_domain_not_found() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains/999")
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_all_managed_domains_after_create() {
    let app = test_app().await.router;

    let domains = vec![
        json!({"name": "Domain A", "domain": "a.example.com", "action": "deny"}),
        json!({"name": "Domain B", "domain": "b.example.com", "action": "allow", "group_id": 2}),
    ];

    for domain in &domains {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/managed-domains")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(domain).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/managed-domains")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["data"].is_array());
    assert_eq!(json["data"].as_array().unwrap().len(), 2);
}

async fn create_domain(app: &axum::Router, name: &str, domain: &str, group_id: i64) {
    let (status, created) = send_json(
        app.clone(),
        "POST",
        "/managed-domains",
        json!({ "name": name, "domain": domain, "action": "deny", "group_id": group_id }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
}

fn names(json: &Value) -> Vec<&str> {
    json["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect()
}

async fn app_with_three_domains() -> axum::Router {
    let app = test_app().await.router;
    create_domain(&app, "Popup ads", "ads.example.com", 1).await;
    create_domain(&app, "Work tracker", "metrics.corp.example", 1).await;
    create_domain(&app, "Video", "cdn.videos.example.net", 1).await;
    app
}

#[tokio::test]
async fn test_list_search_matches_domain_or_name() {
    let app = app_with_three_domains().await;

    let by_domain = get_json(app.clone(), "/managed-domains?search=corp").await;
    assert_eq!(by_domain["total"], 1);
    assert_eq!(names(&by_domain), vec!["Work tracker"]);

    let by_name = get_json(app, "/managed-domains?search=Video").await;
    assert_eq!(by_name["total"], 1);
    assert_eq!(names(&by_name), vec!["Video"]);
}

#[tokio::test]
async fn test_list_search_is_case_insensitive() {
    let app = app_with_three_domains().await;

    let json = get_json(app, "/managed-domains?search=TRACKER").await;

    assert_eq!(json["total"], 1);
    assert_eq!(names(&json), vec!["Work tracker"]);
}

#[tokio::test]
async fn test_list_search_pages_within_the_matches() {
    let app = app_with_three_domains().await;

    let json = get_json(app, "/managed-domains?search=example.&limit=1&offset=1").await;

    assert_eq!(json["total"], 2);
    assert_eq!(names(&json), vec!["Video"]);
}

#[tokio::test]
async fn test_list_blank_search_returns_everything() {
    let app = app_with_three_domains().await;

    let json = get_json(app, "/managed-domains?search=%20%20").await;

    assert_eq!(json["total"], 3);
}

#[tokio::test]
async fn test_list_search_matches_like_wildcards_literally() {
    let app = app_with_three_domains().await;
    create_domain(&app, "100% blocked", "percent.example.org", 1).await;
    create_domain(&app, "snake_case", "underscore.example.org", 1).await;

    let percent = get_json(app.clone(), "/managed-domains?search=%25").await;
    assert_eq!(names(&percent), vec!["100% blocked"]);

    let underscore = get_json(app, "/managed-domains?search=_").await;
    assert_eq!(names(&underscore), vec!["snake_case"]);
}
