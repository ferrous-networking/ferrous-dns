mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use helpers::ftl::{self, assert_ftl_shape};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Status and body; an empty body comes back as `null`.
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("request failed");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("invalid JSON")
    };
    (status, body)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("failed to build request")
}

fn with_body(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("failed to build request")
}

fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .expect("failed to build request")
}

async fn app_and_pool() -> (Router, sqlx::SqlitePool) {
    let pool = helpers::create_test_db().await;
    (helpers::create_pihole_test_app(pool.clone()).await, pool)
}

async fn app() -> Router {
    app_and_pool().await.0
}

async fn create(app: &Router, body: Value) -> ftl::ClientsWriteReply {
    let (status, reply) = send(app, with_body("POST", "/clients", body)).await;
    assert_eq!(status, StatusCode::CREATED, "{reply}");
    assert_ftl_shape(&reply)
}

async fn list(app: &Router, uri: &str) -> Vec<ftl::ClientEntry> {
    let (status, reply) = send(app, get(uri)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_ftl_shape::<ftl::ClientsReply>(&reply).clients
}

fn addresses(clients: &[ftl::ClientEntry]) -> Vec<&str> {
    clients.iter().map(|c| c.client.as_str()).collect()
}

#[tokio::test]
async fn list_clients_returns_empty_array_on_fresh_database() {
    let app = app().await;

    assert!(list(&app, "/clients").await.is_empty());
}

#[tokio::test]
async fn list_clients_returns_entries_in_ftl_shape() {
    let (app, pool) = app_and_pool().await;
    helpers::insert_client(&pool, "192.168.1.99").await;

    let clients = list(&app, "/clients").await;

    assert_eq!(addresses(&clients), ["192.168.1.99"]);
    let entry = &clients[0];
    assert_eq!(
        entry.name.as_deref(),
        Some(""),
        "no hostname is \"\" in FTL"
    );
    assert_eq!(entry.comment, None);
    assert!(entry.date_added > 1_600_000_000, "unix seconds");
    assert!(entry.date_modified >= entry.date_added);
}

#[tokio::test]
async fn create_client_takes_a_string_or_an_array_and_reports_what_was_processed() {
    let app = app().await;

    let one = create(&app, json!({ "client": "10.0.0.1" })).await;
    assert_eq!(addresses(&one.clients), ["10.0.0.1"]);
    assert_eq!(one.processed.success[0].item, "10.0.0.1");

    let many = create(&app, json!({ "client": ["10.0.0.2", "10.0.0.3"] })).await;
    assert_eq!(
        addresses(&many.clients),
        ["10.0.0.3"],
        "FTL reads back the last item"
    );
    let written: Vec<&str> = many
        .processed
        .success
        .iter()
        .map(|s| s.item.as_str())
        .collect();
    assert_eq!(written, ["10.0.0.2", "10.0.0.3"]);
    assert!(many.processed.errors.is_empty());
}

#[tokio::test]
async fn clients_that_are_not_addresses_or_subnets_land_in_processed_errors() {
    let app = app().await;

    let reply = create(
        &app,
        json!({ "client": ["10.0.0.4", "10.0.0.0/24", "12:34:56:78:9a:bc", ":eth0"] }),
    )
    .await;

    assert_eq!(reply.processed.success.len(), 2);
    let failed: Vec<&str> = reply
        .processed
        .errors
        .iter()
        .map(|e| e.item.as_str())
        .collect();
    assert_eq!(failed, ["12:34:56:78:9a:bc", ":eth0"]);
    assert_eq!(
        addresses(&list(&app, "/clients").await),
        ["10.0.0.4", "10.0.0.0/24"]
    );
}

#[tokio::test]
async fn a_subnet_client_is_stored_with_its_group_and_comment() {
    let app = app().await;
    let (_, kids) = send(
        &app,
        with_body("POST", "/groups", json!({ "name": "Kids" })),
    )
    .await;
    let kids_id = kids["groups"][0]["id"].as_i64().expect("group id");

    let created = create(
        &app,
        json!({ "client": "10.9.0.0/24", "comment": "lab", "groups": [kids_id] }),
    )
    .await;

    assert_eq!(addresses(&created.clients), ["10.9.0.0/24"]);
    let subnet = &created.clients[0];
    assert_eq!(subnet.comment.as_deref(), Some("lab"));
    assert_eq!(subnet.groups, [kids_id]);
    assert_eq!(
        subnet.name.as_deref(),
        Some(""),
        "only addresses have names"
    );
    assert!(subnet.date_added > 1_600_000_000);

    let listed = list(&app, "/clients/10.9.0.0/24").await;
    assert_eq!(addresses(&listed), ["10.9.0.0/24"]);
    assert_eq!(listed[0].comment.as_deref(), Some("lab"));
}

#[tokio::test]
async fn an_address_client_keeps_its_comment() {
    let app = app().await;

    let created = create(&app, json!({ "client": "10.0.0.30", "comment": "printer" })).await;
    assert_eq!(created.clients[0].comment.as_deref(), Some("printer"));
    assert_eq!(
        list(&app, "/clients/10.0.0.30").await[0].comment.as_deref(),
        Some("printer")
    );

    // api_list.c: a write without a comment stores none.
    let (status, reply) = send(
        &app,
        with_body("PUT", "/clients/10.0.0.30", json!({ "groups": [0] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::ClientsWriteReply>(&reply);
    assert_eq!(reply.clients[0].comment, None);
}

#[tokio::test]
async fn put_updates_a_subnet_and_delete_removes_it() {
    let app = app().await;
    create(&app, json!({ "client": "10.9.0.0/24", "comment": "lab" })).await;

    let (status, reply) = send(
        &app,
        with_body(
            "PUT",
            "/clients/10.9.0.0/24",
            json!({ "comment": "lab v2" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::ClientsWriteReply>(&reply);
    assert_eq!(reply.clients[0].comment.as_deref(), Some("lab v2"));
    assert_eq!(reply.clients[0].groups, [0], "the group stays as it was");

    let (status, _) = send(&app, delete("/clients/10.9.0.0/24")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = send(&app, delete("/clients/10.9.0.0/24")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn a_post_where_every_client_fails_is_a_database_error() {
    let app = app().await;

    let (status, reply) = send(
        &app,
        with_body("POST", "/clients", json!({ "client": "printer.lan" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error = assert_ftl_shape::<ftl::ErrorReply>(&reply).error;
    assert_eq!(error.key, "database_error");
    assert_eq!(error.message, "Could not add to gravity database");
}

#[tokio::test]
async fn a_post_without_a_client_is_a_bad_request() {
    let app = app().await;

    for body in [json!({}), json!({ "client": "" }), json!({ "client": [] })] {
        let (status, reply) = send(&app, with_body("POST", "/clients", body.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let error = assert_ftl_shape::<ftl::ErrorReply>(&reply).error;
        assert_eq!(error.key, "bad_request", "{body}");
        assert_eq!(
            error.message,
            "Invalid request: No valid \"client\" in payload (must be either string or array)"
        );
    }
}

#[tokio::test]
async fn client_groups_are_ftl_group_ids() {
    let app = app().await;
    let (status, kids) = send(
        &app,
        with_body("POST", "/groups", json!({ "name": "Kids" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{kids}");
    let kids_id = kids["groups"][0]["id"].as_i64().expect("group id");

    let default = create(&app, json!({ "client": "10.0.0.5", "groups": [0] })).await;
    assert_eq!(default.clients[0].groups, [0], "Ferrous group 1 is FTL's 0");

    let other = create(&app, json!({ "client": "10.0.0.6", "groups": [kids_id] })).await;
    assert_eq!(other.clients[0].groups, [kids_id]);
}

#[tokio::test]
async fn put_client_creates_a_missing_client_and_replies_with_what_was_processed() {
    let app = app().await;

    let (status, reply) = send(
        &app,
        with_body("PUT", "/clients/10.0.0.10", json!({ "groups": [0] })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::ClientsWriteReply>(&reply);
    assert_eq!(addresses(&reply.clients), ["10.0.0.10"]);
    assert_eq!(reply.clients[0].groups, [0]);
    assert_eq!(reply.processed.success[0].item, "10.0.0.10");
}

#[tokio::test]
async fn put_client_moves_an_existing_client_to_other_groups() {
    let (app, pool) = app_and_pool().await;
    let (_, kids) = send(
        &app,
        with_body("POST", "/groups", json!({ "name": "Kids" })),
    )
    .await;
    let kids_id = kids["groups"][0]["id"].as_i64().expect("group id");
    helpers::insert_client(&pool, "10.0.0.11").await;

    let (status, reply) = send(
        &app,
        with_body("PUT", "/clients/10.0.0.11", json!({ "groups": [kids_id] })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::ClientsWriteReply>(&reply);
    assert_eq!(reply.clients[0].groups, [kids_id]);
}

#[tokio::test]
async fn get_client_returns_the_entry_or_an_empty_list() {
    let (app, pool) = app_and_pool().await;
    helpers::insert_client(&pool, "10.0.0.12").await;

    assert_eq!(
        addresses(&list(&app, "/clients/10.0.0.12").await),
        ["10.0.0.12"]
    );
    assert!(list(&app, "/clients/10.9.9.9").await.is_empty());
    assert!(list(&app, "/clients/printer.lan").await.is_empty());
}

#[tokio::test]
async fn a_client_subnet_in_the_path_reaches_the_handler() {
    let app = app().await;

    assert!(list(&app, "/clients/10.0.0.0/24").await.is_empty());
    let (status, body) = send(&app, delete("/clients/10.0.0.0/24")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn delete_client_answers_204_then_404_with_an_empty_object() {
    let (app, pool) = app_and_pool().await;
    helpers::insert_client(&pool, "10.0.0.20").await;

    let (status, _) = send(&app, delete("/clients/10.0.0.20")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = send(&app, delete("/clients/10.0.0.20")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}), "api_list_remove sends an empty object");
}

#[tokio::test]
async fn non_canonical_ipv6_path_addresses_the_same_client() {
    let (app, pool) = app_and_pool().await;
    helpers::insert_client(&pool, "2001:db8::a").await;

    let (status, _) = send(
        &app,
        with_body("PUT", "/clients/2001:DB8:0:0::A", json!({ "groups": [0] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(addresses(&list(&app, "/clients").await), ["2001:db8::a"]);

    let (status, _) = send(&app, delete("/clients/2001:0db8::000a")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, delete("/clients/2001:db8::a")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn batch_delete_takes_ftl_item_objects() {
    let (app, pool) = app_and_pool().await;
    for ip in ["10.0.0.40", "10.0.0.41", "10.0.0.42"] {
        helpers::insert_client(&pool, ip).await;
    }

    let (status, _) = send(
        &app,
        with_body(
            "POST",
            "/clients:batchDelete",
            json!([{ "item": "10.0.0.40" }, { "item": "10.0.0.41" }]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(addresses(&list(&app, "/clients").await), ["10.0.0.42"]);

    let (status, body) = send(
        &app,
        with_body(
            "POST",
            "/clients:batchDelete",
            json!([{ "item": "10.0.0.40" }]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn suggestions_are_devices_in_ftl_shape() {
    let (app, pool) = app_and_pool().await;
    for ip in ["10.0.0.30", "10.0.0.31", "fd00::31"] {
        helpers::insert_client(&pool, ip).await;
    }
    sqlx::query(
        "UPDATE clients SET mac_address = '12:34:56:78:9a:bc', hostname = 'laptop'
         WHERE ip_address IN ('10.0.0.31', 'fd00::31')",
    )
    .execute(&pool)
    .await
    .expect("set mac");

    let (status, reply) = send(&app, get("/clients/_suggestions")).await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let mut devices = assert_ftl_shape::<ftl::ClientSuggestions>(&reply).clients;
    devices.sort_by(|a, b| a.hwaddr.cmp(&b.hwaddr));
    assert_eq!(devices.len(), 2, "one device per hardware address");

    let laptop = &devices[0];
    assert_eq!(laptop.hwaddr.as_deref(), Some("12:34:56:78:9a:bc"));
    let mut ips: Vec<&str> = laptop
        .addresses
        .as_deref()
        .expect("addresses")
        .split(',')
        .collect();
    ips.sort_unstable();
    assert_eq!(ips, ["10.0.0.31", "fd00::31"]);
    assert_eq!(laptop.names.as_deref(), Some("laptop"));
    assert!(laptop.last_query > 1_600_000_000, "unix seconds");

    let unknown = &devices[1];
    assert_eq!(
        unknown.hwaddr.as_deref(),
        Some("ip-10.0.0.30"),
        "FTL's mock address for a device without a MAC"
    );
    assert_eq!(unknown.addresses.as_deref(), Some("10.0.0.30"));
    assert_eq!(unknown.names, None);
}

#[tokio::test]
async fn suggestions_honour_count() {
    let (app, pool) = app_and_pool().await;
    for ip in ["10.0.0.50", "10.0.0.51", "10.0.0.52"] {
        helpers::insert_client(&pool, ip).await;
    }

    let (status, reply) = send(&app, get("/clients/_suggestions?count=2")).await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        assert_ftl_shape::<ftl::ClientSuggestions>(&reply)
            .clients
            .len(),
        2
    );
}
