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
    if bytes.is_empty() {
        return (status, Value::Null);
    }
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn test_create_managed_domain_with_expiry_reports_expires_at() {
    let app = test_app().await.router;

    let (status, temporary) = send_json(
        app.clone(),
        "POST",
        "/managed-domains",
        json!({
            "name": "Allow for an hour",
            "domain": "ads.example.com",
            "action": "allow",
            "expires_in_secs": 3600
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{temporary}");
    assert!(temporary["expires_at"].is_string(), "{temporary}");

    let (status, permanent) = send_json(
        app,
        "POST",
        "/managed-domains",
        json!({
            "name": "Allow for good",
            "domain": "ads.example.com",
            "action": "allow"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{permanent}");
    assert!(permanent["expires_at"].is_null(), "{permanent}");
}

#[tokio::test]
async fn test_create_managed_domain_rejects_expiry_outside_bounds() {
    let app = test_app().await.router;

    for secs in [30, 3_000_000] {
        let (status, json) = send_json(
            app.clone(),
            "POST",
            "/managed-domains",
            json!({
                "name": format!("Expiry {secs}"),
                "domain": "ads.example.com",
                "action": "allow",
                "expires_in_secs": secs
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{secs} s: {json}");
    }
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

#[tokio::test]
async fn test_bulk_create_answers_a_result_per_entry_in_order() {
    let app = test_app().await.router;
    let (status, existing) = send_json(
        app.clone(),
        "POST",
        "/managed-domains",
        json!({ "name": "Shop", "domain": "shop.example.com", "action": "allow" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{existing}");

    let (status, json) = send_json(
        app.clone(),
        "POST",
        "/managed-domains/bulk",
        json!({
            "domains": [" Ads.Example.COM ", "x..com", "shop.example.com", "ads.example.com", "*.cdn.example.net"],
            "action": "allow",
            "comment": "bulk import"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(
        json,
        json!({ "results": [
            { "domain": "ads.example.com", "status": "added" },
            { "domain": "x..com", "status": "invalid",
              "error": "Invalid managed domain: Domain cannot contain an empty label" },
            { "domain": "shop.example.com", "status": "existing" },
            { "domain": "ads.example.com", "status": "existing" },
            { "domain": "*.cdn.example.net", "status": "added" },
        ]})
    );
    let listed = get_json(app, "/managed-domains?search=ads.example.com").await;
    assert_eq!(listed["total"], 1, "{listed}");
    let rule = &listed["data"][0];
    assert_eq!(rule["name"], "ads.example.com");
    assert_eq!(rule["action"], "allow");
    assert_eq!(rule["group_id"], 1);
    assert_eq!(rule["comment"], "bulk import");
    assert_eq!(rule["enabled"], true);
}

async fn post_bulk(app: &axum::Router, body: Value) -> (StatusCode, Value) {
    send_json(app.clone(), "POST", "/managed-domains/bulk", body).await
}

#[tokio::test]
async fn test_bulk_create_gives_an_allow_beside_a_same_named_deny_the_fallback_name() {
    let app = test_app().await.router;
    let (status, json) = post_bulk(
        &app,
        json!({ "domains": ["both.example.com"], "action": "deny" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");

    let (status, json) = post_bulk(
        &app,
        json!({ "domains": ["both.example.com"], "action": "allow" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["results"][0]["status"], "added", "{json}");
    let listed = get_json(app, "/managed-domains?search=both").await;
    assert_eq!(
        names(&listed),
        vec!["both.example.com", "both.example.com (allow)"]
    );
}

#[tokio::test]
async fn test_bulk_create_rejects_empty_and_oversized_lists() {
    let app = test_app().await.router;
    let too_many: Vec<String> = (0..10_001).map(|i| format!("d{i}.example.com")).collect();

    for domains in [json!([]), json!(too_many)] {
        let (status, json) = post_bulk(&app, json!({ "domains": domains, "action": "deny" })).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
        assert_eq!(
            json["error"],
            "Invalid input: domains must list 1 to 10000 entries"
        );
    }
    let listed = get_json(app, "/managed-domains").await;
    assert_eq!(listed["total"], 0);
}

#[tokio::test]
async fn test_bulk_create_accepts_the_maximum_list() {
    let app = test_app().await.router;
    let domains: Vec<String> = (0..10_000).map(|i| format!("d{i}.example.com")).collect();

    let (status, json) = post_bulk(&app, json!({ "domains": domains, "action": "deny" })).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["results"].as_array().unwrap().len(), 10_000);
    let listed = get_json(app, "/managed-domains?limit=1").await;
    assert_eq!(listed["total"], 10_000);
}

#[tokio::test]
async fn test_bulk_create_rejects_bad_action_or_comment() {
    let app = test_app().await.router;

    let (status, json) = post_bulk(&app, json!({ "domains": ["a.com"], "action": "block" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");

    let (status, json) = post_bulk(
        &app,
        json!({ "domains": ["a.com"], "action": "deny", "comment": "x".repeat(501) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    assert_eq!(
        json["error"],
        "Invalid managed domain: Comment cannot exceed 500 characters"
    );

    let listed = get_json(app, "/managed-domains").await;
    assert_eq!(listed["total"], 0);
}

#[tokio::test]
async fn test_bulk_create_unknown_group_is_404() {
    let app = test_app().await.router;

    let (status, json) = post_bulk(
        &app,
        json!({ "domains": ["a.com"], "action": "deny", "group_id": 999 }),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{json}");
}

#[tokio::test]
async fn test_bulk_route_is_not_taken_for_an_id() {
    let app = test_app().await.router;
    let (_, json) = post_bulk(&app, json!({ "domains": ["a.com"], "action": "deny" })).await;
    assert_eq!(json["results"][0]["status"], "added", "{json}");
    let listed = get_json(app.clone(), "/managed-domains").await;
    let id = listed["data"][0]["id"].as_i64().unwrap();

    let by_id = get_json(app.clone(), &format!("/managed-domains/{id}")).await;
    assert_eq!(by_id["domain"], "a.com");
    let (status, _) = send_json(app, "GET", "/managed-domains/bulk", Value::Null).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_bulk_create_needs_auth() {
    let helpers::TestApp { mut state, .. } = test_app().await;
    let mut config = ferrous_dns_domain::Config::default();
    config.auth.enabled = true;
    state.auth.get_auth_status = std::sync::Arc::new(
        ferrous_dns_application::use_cases::GetAuthStatusUseCase::new(std::sync::Arc::new(
            tokio::sync::RwLock::new(config),
        )),
    );
    let app = ferrous_dns_api::create_api_router_with_openapi(state).0;

    let (status, _) = post_bulk(&app, json!({ "domains": ["a.com"], "action": "deny" })).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_openapi_lists_bulk_route() {
    let helpers::TestApp { state, .. } = test_app().await;
    let openapi = ferrous_dns_api::create_api_router_with_openapi(state).1;

    let path = openapi
        .paths
        .paths
        .get("/managed-domains/bulk")
        .expect("bulk route documented");
    assert!(path.post.is_some());
}
