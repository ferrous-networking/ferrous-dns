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

async fn app() -> Router {
    helpers::create_pihole_test_app(helpers::create_test_db().await).await
}

async fn create(app: &Router, body: Value) -> ftl::GroupsWriteReply {
    let (status, reply) = send(app, with_body("POST", "/groups", body)).await;
    assert_eq!(status, StatusCode::CREATED, "{reply}");
    assert_ftl_shape(&reply)
}

async fn list(app: &Router, uri: &str) -> Vec<ftl::GroupEntry> {
    let (status, reply) = send(app, get(uri)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_ftl_shape::<ftl::GroupsReply>(&reply).groups
}

fn names(groups: &[ftl::GroupEntry]) -> Vec<&str> {
    groups.iter().map(|g| g.name.as_str()).collect()
}

#[tokio::test]
async fn list_groups_reports_the_default_group_as_ftl_group_zero() {
    let app = app().await;

    let groups = list(&app, "/groups").await;

    let default = &groups[0];
    assert_eq!(default.name, "Protected");
    assert_eq!(default.id, 0, "Ferrous group 1 is FTL's Default (0)");
    assert!(default.enabled);
    assert!(default.date_added > 1_600_000_000, "unix seconds");
}

#[tokio::test]
async fn ids_of_other_groups_pass_through() {
    let app = app().await;

    let created = create(&app, json!({ "name": "Kids" })).await;

    assert!(created.groups[0].id > 1, "{:?}", created.groups);
}

#[tokio::test]
async fn create_group_replies_with_the_entry_and_what_was_processed() {
    let app = app().await;

    let reply = create(&app, json!({ "name": "TestGroup" })).await;

    assert_eq!(names(&reply.groups), ["TestGroup"]);
    assert!(reply.groups[0].enabled);
    assert_eq!(reply.groups[0].comment, None, "no comment is sent as null");
    assert_eq!(reply.processed.success[0].item, "TestGroup");
    assert!(reply.processed.errors.is_empty());
}

#[tokio::test]
async fn create_group_with_comment() {
    let app = app().await;

    let reply = create(
        &app,
        json!({ "name": "WithComment", "comment": "test comment" }),
    )
    .await;

    assert_eq!(reply.groups[0].comment.as_deref(), Some("test comment"));
}

#[tokio::test]
async fn create_accepts_an_array_of_names() {
    let app = app().await;

    let reply = create(&app, json!({ "name": ["G1", "G2"] })).await;

    let success: Vec<&str> = reply
        .processed
        .success
        .iter()
        .map(|s| s.item.as_str())
        .collect();
    assert_eq!(success, ["G1", "G2"]);
    // api_list_write replies with a read of the last item only.
    assert_eq!(names(&reply.groups), ["G2"]);
    assert_eq!(
        names(&list(&app, "/groups").await),
        ["Protected", "G1", "G2"]
    );
}

#[tokio::test]
async fn create_without_a_name_is_a_bad_request() {
    let app = app().await;

    let (status, reply) = send(&app, with_body("POST", "/groups", json!({}))).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert_eq!(
        assert_ftl_shape::<ftl::ErrorReply>(&reply).error.key,
        "bad_request"
    );
}

#[tokio::test]
async fn duplicate_group_is_a_database_error() {
    let app = app().await;
    create(&app, json!({ "name": "Dup" })).await;

    let (status, reply) = send(&app, with_body("POST", "/groups", json!({ "name": "Dup" }))).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    let error = assert_ftl_shape::<ftl::ErrorReply>(&reply).error;
    assert_eq!(error.key, "database_error");
    assert_eq!(error.hint.as_deref(), Some("The item is already present"));
}

#[tokio::test]
async fn get_group_by_name_returns_matching_group() {
    let app = app().await;
    create(&app, json!({ "name": "Lookup" })).await;

    assert_eq!(names(&list(&app, "/groups/Lookup").await), ["Lookup"]);
}

#[tokio::test]
async fn get_nonexistent_group_is_an_empty_list() {
    let app = app().await;

    assert!(list(&app, "/groups/NoSuchGroup").await.is_empty());
}

#[tokio::test]
async fn update_group_changes_comment() {
    let app = app().await;
    create(&app, json!({ "name": "Upd" })).await;

    let (status, reply) = send(
        &app,
        with_body("PUT", "/groups/Upd", json!({ "comment": "updated" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::GroupsWriteReply>(&reply);
    assert_eq!(reply.groups[0].comment.as_deref(), Some("updated"));
    assert_eq!(reply.processed.success[0].item, "Upd");
}

#[tokio::test]
async fn update_group_replaces_omitted_fields_with_their_defaults() {
    let app = app().await;
    create(
        &app,
        json!({ "name": "Upd", "comment": "old", "enabled": false }),
    )
    .await;

    let (status, reply) = send(&app, with_body("PUT", "/groups/Upd", json!({}))).await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let entry = &assert_ftl_shape::<ftl::GroupsWriteReply>(&reply).groups[0];
    assert_eq!(entry.comment, None, "an omitted comment is cleared");
    assert!(entry.enabled, "an omitted enabled defaults to true");
}

#[tokio::test]
async fn update_creates_a_missing_group() {
    let app = app().await;

    let (status, reply) = send(
        &app,
        with_body("PUT", "/groups/Fresh", json!({ "comment": "c" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::GroupsWriteReply>(&reply);
    assert_eq!(names(&reply.groups), ["Fresh"]);
    assert_eq!(reply.groups[0].comment.as_deref(), Some("c"));
}

#[tokio::test]
async fn update_with_a_name_renames_the_group() {
    let app = app().await;
    create(&app, json!({ "name": "Old" })).await;

    let (status, reply) = send(
        &app,
        with_body("PUT", "/groups/Old", json!({ "name": "New" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::GroupsWriteReply>(&reply);
    // api_list_write reads the URI name back, which no longer exists.
    assert!(reply.groups.is_empty());
    assert_eq!(reply.processed.success[0].item, "Old");
    assert_eq!(names(&list(&app, "/groups/New").await), ["New"]);
    assert!(list(&app, "/groups/Old").await.is_empty());
}

#[tokio::test]
async fn delete_group_returns_no_content() {
    let app = app().await;
    create(&app, json!({ "name": "DelMe" })).await;

    let (status, _) = send(&app, delete("/groups/DelMe")).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(list(&app, "/groups/DelMe").await.is_empty());
}

#[tokio::test]
async fn delete_nonexistent_group_is_an_empty_not_found() {
    let app = app().await;

    let (status, body) = send(&app, delete("/groups/Ghost")).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}), "api_list_remove sends an empty object");
}

#[tokio::test]
async fn batch_delete_groups_removes_specified_groups() {
    let app = app().await;
    create(&app, json!({ "name": ["B1", "B2", "B3"] })).await;

    let (status, body) = send(
        &app,
        with_body(
            "POST",
            "/groups:batchDelete",
            json!([{ "item": "B1" }, { "item": "B2" }]),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(names(&list(&app, "/groups").await), ["Protected", "B3"]);
}

#[tokio::test]
async fn batch_delete_of_unknown_groups_is_an_empty_not_found() {
    let app = app().await;

    let (status, body) = send(
        &app,
        with_body("POST", "/groups:batchDelete", json!([{ "item": "Ghost" }])),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}));
}
