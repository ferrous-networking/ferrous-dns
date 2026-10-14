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

/// POSTs `body` to `/domains/{type}/{kind}` and requires a 201.
async fn create(app: &Router, list: &str, body: Value) -> ftl::DomainsWriteReply {
    let (status, reply) = send(app, with_body("POST", &format!("/domains/{list}"), body)).await;
    assert_eq!(status, StatusCode::CREATED, "{reply}");
    assert_ftl_shape(&reply)
}

async fn list(app: &Router, uri: &str) -> Vec<ftl::DomainEntry> {
    let (status, reply) = send(app, get(uri)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_ftl_shape::<ftl::DomainsReply>(&reply).domains
}

fn names(entries: &[ftl::DomainEntry]) -> Vec<&str> {
    entries.iter().map(|d| d.domain.as_str()).collect()
}

#[tokio::test]
async fn list_all_domains_returns_empty_array_on_fresh_database() {
    let app = app().await;

    assert!(list(&app, "/domains").await.is_empty());
}

#[tokio::test]
async fn listed_entries_carry_ftl_fields_and_types() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "ads.example.com" })).await;

    let domains = list(&app, "/domains").await;

    assert_eq!(domains.len(), 1);
    let entry = &domains[0];
    assert_eq!(entry.domain, "ads.example.com");
    assert_eq!(entry.unicode, "ads.example.com");
    assert_eq!(entry.domain_type, ftl::DomainType::Deny);
    assert_eq!(entry.kind, ftl::DomainKind::Exact);
    assert_eq!(entry.comment, None, "no comment is sent as null");
    assert!(entry.enabled);
    assert!(entry.date_added > 1_600_000_000, "unix seconds");
    assert!(entry.date_modified >= entry.date_added);
}

#[tokio::test]
async fn entries_of_the_default_group_report_ftl_group_zero() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "ads.example.com" })).await;

    let domains = list(&app, "/domains").await;

    assert_eq!(
        domains[0].groups,
        vec![0],
        "Ferrous group 1 is FTL's Default (0)"
    );
}

#[tokio::test]
async fn create_replies_with_the_entry_and_what_was_processed() {
    let app = app().await;

    let reply = create(&app, "deny/exact", json!({ "domain": "ads.example.com" })).await;

    assert_eq!(names(&reply.domains), ["ads.example.com"]);
    assert_eq!(reply.domains[0].domain_type, ftl::DomainType::Deny);
    let success: Vec<&str> = reply
        .processed
        .success
        .iter()
        .map(|s| s.item.as_str())
        .collect();
    assert_eq!(success, ["ads.example.com"]);
    assert!(reply.processed.errors.is_empty());
}

#[tokio::test]
async fn create_allow_exact_and_deny_regex_land_in_their_lists() {
    let app = app().await;

    let allow = create(&app, "allow/exact", json!({ "domain": "safe.com" })).await;
    let regex = create(&app, "deny/regex", json!({ "domain": ".*\\.ads\\..*" })).await;

    assert_eq!(allow.domains[0].domain_type, ftl::DomainType::Allow);
    assert_eq!(allow.domains[0].kind, ftl::DomainKind::Exact);
    assert_eq!(regex.domains[0].domain_type, ftl::DomainType::Deny);
    assert_eq!(regex.domains[0].kind, ftl::DomainKind::Regex);
}

#[tokio::test]
async fn create_accepts_an_array_of_domains() {
    let app = app().await;

    let reply = create(&app, "deny/exact", json!({ "domain": ["a.com", "b.com"] })).await;

    let success: Vec<&str> = reply
        .processed
        .success
        .iter()
        .map(|s| s.item.as_str())
        .collect();
    assert_eq!(success, ["a.com", "b.com"]);
    // api_list_write replies with a read of the last item only.
    assert_eq!(names(&reply.domains), ["b.com"]);
    assert_eq!(
        names(&list(&app, "/domains/deny/exact").await),
        ["a.com", "b.com"]
    );
}

#[tokio::test]
async fn create_lowercases_exact_domains() {
    let app = app().await;

    let reply = create(&app, "deny/exact", json!({ "domain": "Ads.Example.COM" })).await;

    assert_eq!(names(&reply.domains), ["ads.example.com"]);
}

#[tokio::test]
async fn unicode_is_the_decoded_form_of_a_punycode_domain() {
    // api_list.c: idn2_to_unicode on every entry, falling back to the stored
    // text when it does not decode, as a regex does not.
    let app = app().await;

    let exact = create(
        &app,
        "deny/exact",
        json!({ "domain": "xn--bcher-kva.example" }),
    )
    .await;
    let regex = create(
        &app,
        "deny/regex",
        json!({ "domain": "(\\.|^)xn--bcher-kva\\.example$" }),
    )
    .await;

    assert_eq!(exact.domains[0].unicode, "bücher.example");
    assert_eq!(regex.domains[0].unicode, "(\\.|^)xn--bcher-kva\\.example$");
}

#[tokio::test]
async fn create_stores_an_international_domain_as_punycode() {
    // api_list.c: a non-ASCII exact domain goes through idn2_to_ascii first.
    let app = app().await;

    let reply = create(&app, "allow/exact", json!({ "domain": "Bücher.example" })).await;

    assert_eq!(names(&reply.domains), ["xn--bcher-kva.example"]);
    assert_eq!(reply.domains[0].unicode, "bücher.example");
}

#[tokio::test]
async fn create_without_a_domain_is_a_bad_request() {
    let app = app().await;

    for body in [json!({}), json!({ "domain": "" }), json!({ "domain": [] })] {
        let (status, reply) = send(&app, with_body("POST", "/domains/deny/exact", body)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
        let error = assert_ftl_shape::<ftl::ErrorReply>(&reply).error;
        assert_eq!(error.key, "bad_request");
    }
}

#[tokio::test]
async fn duplicate_create_is_a_database_error() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "dup.com" })).await;

    let (status, reply) = send(
        &app,
        with_body(
            "POST",
            "/domains/deny/exact",
            json!({ "domain": "dup.com" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    let error = assert_ftl_shape::<ftl::ErrorReply>(&reply).error;
    assert_eq!(error.key, "database_error");
    assert_eq!(error.message, "Could not add to gravity database");
    assert_eq!(error.hint.as_deref(), Some("The item is already present"));
}

#[tokio::test]
async fn partly_duplicate_create_reports_the_duplicate_in_processed_errors() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "dup.com" })).await;

    let reply = create(
        &app,
        "deny/exact",
        json!({ "domain": ["dup.com", "new.com"] }),
    )
    .await;

    let success: Vec<&str> = reply
        .processed
        .success
        .iter()
        .map(|s| s.item.as_str())
        .collect();
    assert_eq!(success, ["new.com"]);
    assert_eq!(reply.processed.errors.len(), 1);
    assert_eq!(reply.processed.errors[0].item, "dup.com");
    assert_eq!(
        reply.processed.errors[0].error,
        "The item is already present"
    );
}

#[tokio::test]
async fn create_translates_ftl_group_ids() {
    let app = app().await;
    let (status, group) = send(
        &app,
        with_body("POST", "/groups", json!({ "name": "Kids" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let kids = group["groups"][0]["id"].as_i64().expect("group id");

    let default = create(
        &app,
        "deny/exact",
        json!({ "domain": "a.com", "groups": [0] }),
    )
    .await;
    let custom = create(
        &app,
        "deny/exact",
        json!({ "domain": "b.com", "groups": [kids] }),
    )
    .await;

    assert_eq!(default.domains[0].groups, vec![0]);
    assert_eq!(custom.domains[0].groups, vec![kids]);
}

#[tokio::test]
async fn list_by_type_returns_only_that_type() {
    let app = app().await;
    create(&app, "allow/exact", json!({ "domain": "safe.com" })).await;
    create(&app, "deny/exact", json!({ "domain": "bad.com" })).await;

    assert_eq!(names(&list(&app, "/domains/deny").await), ["bad.com"]);
}

#[tokio::test]
async fn list_by_type_and_kind_returns_only_that_list() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "exact-deny.com" })).await;
    create(&app, "deny/regex", json!({ "domain": ".*\\.tracker\\..*" })).await;

    assert_eq!(
        names(&list(&app, "/domains/deny/exact").await),
        ["exact-deny.com"]
    );
}

#[tokio::test]
async fn list_by_kind_spans_both_types() {
    let app = app().await;
    create(&app, "allow/exact", json!({ "domain": "safe.com" })).await;
    create(&app, "deny/exact", json!({ "domain": "bad.com" })).await;
    create(&app, "deny/regex", json!({ "domain": "^ads" })).await;

    let exact = list(&app, "/domains/exact").await;

    assert_eq!(names(&exact), ["safe.com", "bad.com"]);
    assert_eq!(names(&list(&app, "/domains/regex").await), ["^ads"]);
}

#[tokio::test]
async fn a_single_segment_that_is_not_a_type_or_kind_filters_by_domain() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "bad.com" })).await;
    create(&app, "deny/exact", json!({ "domain": "other.com" })).await;

    assert_eq!(names(&list(&app, "/domains/bad.com").await), ["bad.com"]);
    assert!(list(&app, "/domains/invalid").await.is_empty());
}

#[tokio::test]
async fn type_and_domain_filters_one_type() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "bad.com" })).await;

    assert_eq!(
        names(&list(&app, "/domains/deny/bad.com").await),
        ["bad.com"]
    );
    assert!(list(&app, "/domains/allow/bad.com").await.is_empty());
    assert_eq!(
        names(&list(&app, "/domains/exact/bad.com").await),
        ["bad.com"]
    );
}

#[tokio::test]
async fn get_one_domain_by_type_kind_and_name() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "bad.com" })).await;
    create(&app, "deny/exact", json!({ "domain": "other.com" })).await;

    assert_eq!(
        names(&list(&app, "/domains/deny/exact/bad.com").await),
        ["bad.com"]
    );
    assert!(list(&app, "/domains/allow/exact/bad.com").await.is_empty());
}

#[tokio::test]
async fn create_on_an_unknown_list_is_a_uri_error() {
    let app = app().await;

    let (status, reply) = send(
        &app,
        with_body("POST", "/domains/foo/exact", json!({ "domain": "a.com" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert_eq!(
        assert_ftl_shape::<ftl::ErrorReply>(&reply).error.key,
        "uri_error"
    );
}

#[tokio::test]
async fn update_takes_the_domain_from_the_uri() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "upd.com" })).await;

    let (status, reply) = send(
        &app,
        with_body(
            "PUT",
            "/domains/deny/exact/upd.com",
            json!({ "comment": "updated" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::DomainsWriteReply>(&reply);
    assert_eq!(names(&reply.domains), ["upd.com"]);
    assert_eq!(reply.domains[0].comment.as_deref(), Some("updated"));
    assert_eq!(reply.processed.success[0].item, "upd.com");
}

#[tokio::test]
async fn update_replaces_omitted_fields_with_their_defaults() {
    let app = app().await;
    create(
        &app,
        "deny/exact",
        json!({ "domain": "upd.com", "comment": "old", "enabled": false }),
    )
    .await;

    let (status, reply) = send(
        &app,
        with_body("PUT", "/domains/deny/exact/upd.com", json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let entry = &assert_ftl_shape::<ftl::DomainsWriteReply>(&reply).domains[0];
    assert_eq!(entry.comment, None, "an omitted comment is cleared");
    assert!(entry.enabled, "an omitted enabled defaults to true");
}

#[tokio::test]
async fn update_creates_a_missing_entry() {
    let app = app().await;

    let (status, reply) = send(
        &app,
        with_body(
            "PUT",
            "/domains/allow/exact/new.com",
            json!({ "comment": "c" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::DomainsWriteReply>(&reply);
    assert_eq!(names(&reply.domains), ["new.com"]);
    assert_eq!(
        names(&list(&app, "/domains/allow/exact").await),
        ["new.com"]
    );
}

#[tokio::test]
async fn update_moves_an_entry_from_the_body_list_to_the_uri_list() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "moved.com" })).await;

    // domains.yaml: PUT allow/exact/abc.com with type=deny, kind=exact
    // moves abc.com from exact denied to exact allowed.
    let (status, reply) = send(
        &app,
        with_body(
            "PUT",
            "/domains/allow/exact/moved.com",
            json!({ "type": "deny", "kind": "exact" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    let reply = assert_ftl_shape::<ftl::DomainsWriteReply>(&reply);
    assert_eq!(reply.domains[0].domain_type, ftl::DomainType::Allow);
    assert!(list(&app, "/domains/deny").await.is_empty());
    assert_eq!(
        names(&list(&app, "/domains/allow/exact").await),
        ["moved.com"]
    );
}

#[tokio::test]
async fn update_moves_an_exact_entry_to_the_regex_list() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "moved.com" })).await;

    let (status, reply) = send(
        &app,
        with_body(
            "PUT",
            "/domains/deny/regex/moved.com",
            json!({ "type": "deny", "kind": "exact" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(list(&app, "/domains/exact").await.is_empty());
    assert_eq!(
        names(&list(&app, "/domains/deny/regex").await),
        ["moved.com"]
    );
}

#[tokio::test]
async fn update_on_an_unknown_list_is_a_uri_error() {
    let app = app().await;

    let (status, reply) = send(
        &app,
        with_body("PUT", "/domains/foo/exact/a.com", json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert_eq!(
        assert_ftl_shape::<ftl::ErrorReply>(&reply).error.key,
        "uri_error"
    );
}

#[tokio::test]
async fn delete_domain_returns_no_content() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "del.com" })).await;

    let (status, _) = send(&app, delete("/domains/deny/exact/del.com")).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(list(&app, "/domains").await.is_empty());
}

#[tokio::test]
async fn delete_nonexistent_domain_is_an_empty_not_found() {
    let app = app().await;

    let (status, body) = send(&app, delete("/domains/deny/exact/ghost.com")).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({}), "api_list_remove sends an empty object");
}

#[tokio::test]
async fn batch_delete_removes_the_listed_items() {
    let app = app().await;
    create(
        &app,
        "deny/exact",
        json!({ "domain": ["b1.com", "b2.com"] }),
    )
    .await;
    create(&app, "deny/regex", json!({ "domain": "^b3" })).await;

    let (status, body) = send(
        &app,
        with_body(
            "POST",
            "/domains:batchDelete",
            json!([
                { "item": "b1.com", "type": "deny", "kind": "exact" },
                { "item": "^b3", "type": "deny", "kind": "regex" }
            ]),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(names(&list(&app, "/domains").await), ["b2.com"]);
}

#[tokio::test]
async fn batch_delete_only_matches_the_given_type_and_kind() {
    let app = app().await;
    create(&app, "deny/exact", json!({ "domain": "keep.com" })).await;

    let (status, body) = send(
        &app,
        with_body(
            "POST",
            "/domains:batchDelete",
            json!([{ "item": "keep.com", "type": "allow", "kind": "exact" }]),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, json!({}));
    assert_eq!(names(&list(&app, "/domains").await), ["keep.com"]);
}

#[tokio::test]
async fn batch_delete_without_type_and_kind_is_a_bad_request() {
    let app = app().await;

    let (status, reply) = send(
        &app,
        with_body("POST", "/domains:batchDelete", json!([{ "item": "a.com" }])),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert_eq!(
        assert_ftl_shape::<ftl::ErrorReply>(&reply).error.key,
        "bad_request"
    );
}
