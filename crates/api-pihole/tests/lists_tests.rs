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

const SHARED: &str = "https://shared.list/hosts";
const SHARED_ENCODED: &str = "https%3A%2F%2Fshared.list%2Fhosts";

async fn send(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let builder = Request::builder().method(method).uri(uri);
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("failed to build request");

    let response = app.clone().oneshot(request).await.expect("request failed");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("invalid JSON")
    };
    (status, json)
}

async fn create(app: &Router, list_type: &str, address: &str) -> ftl::ListEntry {
    let (status, json) = send(
        app,
        "POST",
        &format!("/lists?type={list_type}"),
        Some(json!({ "address": address })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    let mut reply = assert_ftl_shape::<ftl::ListsWriteReply>(&json);
    assert_eq!(reply.lists.len(), 1, "{json}");
    reply.lists.remove(0)
}

async fn list(app: &Router, uri: &str) -> Vec<ftl::ListEntry> {
    let (status, json) = send(app, "GET", uri, None).await;
    assert_eq!(status, StatusCode::OK, "{uri}: {json}");
    assert_ftl_shape::<ftl::ListsReply>(&json).lists
}

async fn app_and_pool() -> (Router, sqlx::SqlitePool) {
    let pool = helpers::create_test_db().await;
    (helpers::create_pihole_test_app(pool.clone()).await, pool)
}

async fn app() -> Router {
    app_and_pool().await.0
}

/// Creates a blocklist and an allowlist that share both address and id.
async fn app_with_colliding_lists() -> (Router, i64) {
    let app = app().await;
    let block = create(&app, "block", SHARED).await;
    let allow = create(&app, "allow", SHARED).await;
    assert_eq!(block.id, allow.id, "fixture relies on colliding ids");
    (app, block.id)
}

fn types_of(lists: &[ftl::ListEntry]) -> Vec<&ftl::ListType> {
    lists.iter().map(|l| &l.list_type).collect()
}

#[tokio::test]
async fn list_all_returns_empty_array_on_fresh_database() {
    assert!(list(&app().await, "/lists").await.is_empty());
}

#[tokio::test]
async fn list_entries_carry_every_ftl_field() {
    let app = app().await;
    create(&app, "block", "https://block.list/hosts").await;

    let lists = list(&app, "/lists").await;

    let entry = &lists[0];
    assert_eq!(entry.address, "https://block.list/hosts");
    assert_eq!(entry.list_type, ftl::ListType::Block);
    assert_eq!(entry.comment, None, "no comment is sent as null");
    assert_eq!(entry.groups, [0], "Ferrous group 1 is FTL's Default (0)");
    assert!(entry.enabled);
    assert!(entry.date_added > 1_600_000_000, "unix seconds");
    assert_eq!(entry.date_updated, 0, "never downloaded");
    assert_eq!(entry.status, 0, "never downloaded is FTL's unknown status");
    assert_eq!(entry.number, 0);
    assert_eq!(entry.invalid_domains, 0);
    assert_eq!(entry.abp_entries, 0);
}

#[tokio::test]
async fn a_downloaded_list_reports_when_and_that_it_succeeded() {
    let (app, pool) = app_and_pool().await;
    create(&app, "block", "https://block.list/hosts").await;
    sqlx::query("UPDATE blocklist_sources SET last_synced_at = '2024-01-15T12:30:00Z'")
        .execute(&pool)
        .await
        .expect("stamp the sync");

    let lists = list(&app, "/lists?type=block").await;

    assert_eq!(lists[0].date_updated, 1_705_321_800);
    assert_eq!(lists[0].status, 1, "FTL's \"download was successful\"");
}

#[tokio::test]
async fn list_status_reports_how_the_last_download_went() {
    // gravity.sh: 2 unchanged, 3 failed with a copy in use, 4 failed with none.
    for (status, synced) in [(2, true), (3, true), (4, false)] {
        let (app, pool) = app_and_pool().await;
        create(&app, "allow", "https://allow.list/hosts").await;
        sqlx::query("UPDATE whitelist_sources SET last_status = ?, last_synced_at = ?")
            .bind(status)
            .bind(synced.then_some("2024-01-15T12:30:00Z"))
            .execute(&pool)
            .await
            .expect("record the status");

        let lists = list(&app, "/lists?type=allow").await;

        assert_eq!(lists[0].status, status);
    }
}

#[tokio::test]
async fn create_list_takes_its_type_from_the_query() {
    let app = app().await;

    assert_eq!(
        create(&app, "block", "https://block.list/hosts")
            .await
            .list_type,
        ftl::ListType::Block
    );
    assert_eq!(
        create(&app, "ALLOW", "https://allow.list/hosts")
            .await
            .list_type,
        ftl::ListType::Allow
    );

    let all = list(&app, "/lists").await;
    assert_eq!(
        types_of(&all),
        [&ftl::ListType::Block, &ftl::ListType::Allow]
    );
    let allow_only = list(&app, "/lists?type=allow").await;
    assert_eq!(allow_only[0].address, "https://allow.list/hosts");
    assert_eq!(types_of(&allow_only), [&ftl::ListType::Allow]);
}

#[tokio::test]
async fn create_list_takes_a_string_or_an_array_and_reports_what_was_processed() {
    let app = app().await;

    let (status, json) = send(
        &app,
        "POST",
        "/lists?type=block",
        Some(json!({
            "address": ["https://a.list/hosts", "https://b.list/hosts"],
            "comment": "my lists",
            "groups": [0]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{json}");
    let reply = assert_ftl_shape::<ftl::ListsWriteReply>(&json);
    assert_eq!(reply.lists.len(), 1, "FTL reads back the last item");
    assert_eq!(reply.lists[0].address, "https://b.list/hosts");
    assert_eq!(reply.lists[0].comment.as_deref(), Some("my lists"));
    assert_eq!(reply.lists[0].groups, [0]);
    let written: Vec<&str> = reply
        .processed
        .success
        .iter()
        .map(|s| s.item.as_str())
        .collect();
    assert_eq!(written, ["https://a.list/hosts", "https://b.list/hosts"]);
    assert_eq!(list(&app, "/lists").await.len(), 2);
}

#[tokio::test]
async fn a_duplicate_address_is_listed_in_processed_errors() {
    let app = app().await;
    create(&app, "block", SHARED).await;

    let (status, json) = send(
        &app,
        "POST",
        "/lists?type=block",
        Some(json!({ "address": [SHARED, "https://new.list/hosts"] })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{json}");
    let reply = assert_ftl_shape::<ftl::ListsWriteReply>(&json);
    assert_eq!(reply.processed.errors[0].item, SHARED);
    assert_eq!(
        reply.processed.errors[0].error,
        "The item is already present"
    );
    assert_eq!(reply.processed.success[0].item, "https://new.list/hosts");
}

#[tokio::test]
async fn a_post_where_every_list_fails_is_a_database_error() {
    let app = app().await;
    create(&app, "block", SHARED).await;

    for address in [SHARED, "ftp://not.http/list"] {
        let (status, json) = send(
            &app,
            "POST",
            "/lists?type=block",
            Some(json!({ "address": address })),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{address}");
        let error = assert_ftl_shape::<ftl::ErrorReply>(&json).error;
        assert_eq!(error.key, "database_error", "{address}");
        assert_eq!(error.message, "Could not add to gravity database");
    }
    let (_, json) = send(
        &app,
        "POST",
        "/lists?type=block",
        Some(json!({ "address": SHARED })),
    )
    .await;
    assert_eq!(json["error"]["hint"], "The item is already present");
}

#[tokio::test]
async fn a_missing_or_unknown_list_type_is_rejected_without_side_effects() {
    let (app, id) = app_with_colliding_lists().await;
    let body = || Some(json!({ "address": "https://new.list" }));

    for (method, uri, body) in [
        ("POST", "/lists".to_string(), body()),
        ("POST", "/lists?type=deny".to_string(), body()),
        (
            "PUT",
            format!("/lists/{id}"),
            Some(json!({ "enabled": false })),
        ),
        ("DELETE", format!("/lists/{SHARED_ENCODED}"), None),
        ("DELETE", format!("/lists/{id}?type=both"), None),
        ("GET", format!("/lists/{id}?type=both"), None),
        ("GET", "/lists?type=both".to_string(), None),
    ] {
        let (status, json) = send(&app, method, &uri, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
        let error = assert_ftl_shape::<ftl::ErrorReply>(&json).error;
        assert_eq!(error.key, "bad_request", "{method} {uri}");
    }

    let all = list(&app, "/lists").await;
    assert_eq!(
        types_of(&all),
        [&ftl::ListType::Block, &ftl::ListType::Allow]
    );
    assert!(all.iter().all(|l| l.enabled && l.address == SHARED));
}

#[tokio::test]
async fn get_resolves_colliding_lists_by_type() {
    let (app, id) = app_with_colliding_lists().await;

    for (uri, expected) in [
        (
            format!("/lists/{id}?type=block"),
            vec![&ftl::ListType::Block],
        ),
        (
            format!("/lists/{id}?type=allow"),
            vec![&ftl::ListType::Allow],
        ),
        (
            format!("/lists/{SHARED_ENCODED}?type=allow"),
            vec![&ftl::ListType::Allow],
        ),
        (
            format!("/lists/{SHARED_ENCODED}"),
            vec![&ftl::ListType::Block, &ftl::ListType::Allow],
        ),
    ] {
        let lists = list(&app, &uri).await;
        assert_eq!(types_of(&lists), expected, "{uri}");
        assert_eq!(lists[0].address, SHARED, "{uri}");
    }
}

#[tokio::test]
async fn a_list_address_with_raw_slashes_reaches_the_handler() {
    let (app, _) = app_with_colliding_lists().await;

    let lists = list(&app, &format!("/lists/{SHARED}?type=block")).await;
    assert_eq!(types_of(&lists), [&ftl::ListType::Block]);

    let (status, _) = send(&app, "DELETE", &format!("/lists/{SHARED}?type=block"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        types_of(&list(&app, "/lists").await),
        [&ftl::ListType::Allow]
    );
}

#[tokio::test]
async fn put_replaces_only_the_list_of_the_given_type() {
    let (app, id) = app_with_colliding_lists().await;

    let (status, json) = send(
        &app,
        "PUT",
        &format!("/lists/{id}?type=allow"),
        Some(json!({ "comment": "allow side", "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let reply = assert_ftl_shape::<ftl::ListsWriteReply>(&json);
    assert_eq!(types_of(&reply.lists), [&ftl::ListType::Allow]);
    assert_eq!(reply.lists[0].comment.as_deref(), Some("allow side"));
    assert!(!reply.lists[0].enabled);
    assert_eq!(reply.processed.success.len(), 1);

    let block = list(&app, &format!("/lists/{id}?type=block")).await;
    assert!(block[0].enabled);
    assert_eq!(block[0].comment, None);
}

#[tokio::test]
async fn put_clears_what_the_body_omits_and_keeps_groups_unless_given() {
    let app = app().await;
    let (status, json) = send(
        &app,
        "POST",
        "/lists?type=block",
        Some(json!({ "address": SHARED, "comment": "c", "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");

    let (status, json) = send(
        &app,
        "PUT",
        &format!("/lists/{SHARED_ENCODED}?type=block"),
        Some(json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    let entry = &assert_ftl_shape::<ftl::ListsWriteReply>(&json).lists[0];
    assert_eq!(entry.comment, None, "an omitted comment is cleared");
    assert!(entry.enabled, "enabled defaults to true");
    assert_eq!(entry.groups, [0], "groups stay when omitted");
}

#[tokio::test]
async fn put_creates_a_missing_list() {
    let app = app().await;

    let (status, json) = send(
        &app,
        "PUT",
        &format!("/lists/{SHARED_ENCODED}?type=allow"),
        Some(json!({ "comment": "new" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{json}");
    let reply = assert_ftl_shape::<ftl::ListsWriteReply>(&json);
    assert_eq!(reply.lists[0].address, SHARED);
    assert_eq!(reply.lists[0].list_type, ftl::ListType::Allow);
    assert_eq!(reply.processed.success[0].item, SHARED);
}

#[tokio::test]
async fn delete_removes_only_the_list_of_the_given_type() {
    let (app, id) = app_with_colliding_lists().await;

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/lists/{SHARED_ENCODED}?type=block"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert!(list(&app, &format!("/lists/{id}?type=block"))
        .await
        .is_empty());
    let allow = list(&app, &format!("/lists/{id}?type=allow")).await;
    assert_eq!(types_of(&allow), [&ftl::ListType::Allow]);

    let (status, _) = send(&app, "DELETE", &format!("/lists/{id}?type=allow"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(list(&app, "/lists").await.is_empty());
}

#[tokio::test]
async fn unknown_lists_are_empty_reads_and_404_deletes() {
    let app = app().await;

    assert!(list(&app, "/lists/99999").await.is_empty());
    assert!(list(&app, "/lists/https%3A%2F%2Fmissing.list?type=block")
        .await
        .is_empty());

    let (status, body) = send(&app, "DELETE", "/lists/99999?type=block", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}), "api_list_remove sends an empty object");
}

#[tokio::test]
async fn batch_delete_removes_only_the_named_type() {
    let (app, _) = app_with_colliding_lists().await;
    create(&app, "block", "https://other.list/hosts").await;

    let (status, _) = send(
        &app,
        "POST",
        "/lists:batchDelete",
        Some(json!([
            { "item": SHARED, "type": "block" },
            { "item": "https://other.list/hosts", "type": "block" }
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let all = list(&app, "/lists").await;
    assert_eq!(types_of(&all), [&ftl::ListType::Allow]);
    assert_eq!(all[0].address, SHARED);
}

#[tokio::test]
async fn batch_delete_skips_items_without_a_known_type() {
    let (app, _) = app_with_colliding_lists().await;

    let (status, _) = send(
        &app,
        "POST",
        "/lists:batchDelete",
        Some(json!([
            { "item": SHARED, "type": "block" },
            { "item": SHARED, "type": "deny" },
            { "item": SHARED }
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "gravity-db.c binds type -1");
    assert_eq!(
        types_of(&list(&app, "/lists").await),
        [&ftl::ListType::Allow]
    );

    let (status, body) = send(
        &app,
        "POST",
        "/lists:batchDelete",
        Some(json!([{ "item": SHARED, "type": "deny" }])),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn batch_delete_takes_the_type_from_the_query_when_given() {
    let (app, _) = app_with_colliding_lists().await;

    let (status, _) = send(
        &app,
        "POST",
        "/lists:batchDelete?type=allow",
        Some(json!([{ "item": SHARED, "type": "block" }])),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        types_of(&list(&app, "/lists").await),
        [&ftl::ListType::Block]
    );
}
