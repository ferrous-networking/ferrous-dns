mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn get_json(app: axum::Router, uri: &str) -> Value {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("json")
}

#[tokio::test]
async fn history_clients_matches_ftl_when_no_queries_logged() {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let json = get_json(app, "/history/clients").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::HistoryClients>(&json);
    assert_eq!(json["clients"], json!({}));
    let history = json["history"].as_array().expect("history array");
    assert_eq!(history.len(), 145);
    // FTL always reports the "others" series, 0 when nothing was folded.
    assert!(history.iter().all(|b| b["data"] == json!({ "others": 0 })));
}

#[tokio::test]
async fn history_clients_keys_clients_by_ip_with_per_bucket_counts() {
    let pool = helpers::create_test_db().await;
    helpers::insert_query(&pool, "one.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "two.com", "10.0.0.1", false, false, None).await;
    helpers::insert_query(&pool, "three.com", "10.0.0.1", true, false, Some("Exact")).await;
    helpers::insert_query(&pool, "four.com", "10.0.0.2", false, false, None).await;

    let app = helpers::create_pihole_test_app(pool).await;
    let json = get_json(app, "/history/clients").await;

    helpers::ftl::assert_ftl_shape::<helpers::ftl::HistoryClients>(&json);
    // A client with no known name is null, not "".
    assert_eq!(
        json["clients"],
        json!({
            "10.0.0.1": { "name": null, "total": 3 },
            "10.0.0.2": { "name": null, "total": 1 },
        })
    );
    let history = json["history"].as_array().expect("history array");
    assert_eq!(history.len(), 145);
    let bucket = history
        .iter()
        .find(|b| b["data"]["10.0.0.1"] != 0)
        .expect("a bucket with the queries");
    assert_eq!(
        bucket["data"],
        json!({ "10.0.0.1": 3, "10.0.0.2": 1, "others": 0 })
    );
    for bucket in history {
        let ts = bucket["timestamp"].as_i64().expect("integer timestamp");
        assert_eq!(ts % 600, 300, "timestamp {ts} is not a bucket centre");
    }
}

#[tokio::test]
async fn history_clients_folds_clients_beyond_n_into_others() {
    let pool = helpers::create_test_db().await;
    for (ip, queries) in [("10.0.0.1", 3), ("10.0.0.2", 2), ("10.0.0.3", 1)] {
        for _ in 0..queries {
            helpers::insert_query(&pool, "example.com", ip, false, false, None).await;
        }
    }

    let app = helpers::create_pihole_test_app(pool).await;

    // As in history.c: N slots, the last of them taken by "others".
    let json = get_json(app.clone(), "/history/clients?N=2").await;
    helpers::ftl::assert_ftl_shape::<helpers::ftl::HistoryClients>(&json);
    assert_eq!(
        json["clients"],
        json!({
            "10.0.0.1": { "name": null, "total": 3 },
            "others": { "name": "other clients", "total": 3 },
        })
    );
    let bucket = json["history"]
        .as_array()
        .expect("history array")
        .iter()
        .find(|b| b["data"]["others"] != 0)
        .expect("a bucket with the queries");
    assert_eq!(bucket["data"], json!({ "10.0.0.1": 3, "others": 3 }));

    // When every client fits, nothing is folded.
    let json = get_json(app, "/history/clients?N=3").await;
    let clients = json["clients"].as_object().expect("clients object");
    assert_eq!(clients.len(), 3);
    assert!(!clients.contains_key("others"));
}
