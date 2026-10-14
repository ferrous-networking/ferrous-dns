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

const BLOCKLIST: &str = "https://block.list/hosts";
const GROUP_BLOCKLIST: &str = "https://group.list/hosts";
const ALLOWLIST: &str = "https://allow.list/hosts";

/// Status and body; an empty body comes back as `null`.
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

async fn app() -> Router {
    helpers::create_pihole_test_app(helpers::create_test_db().await).await
}

async fn create(app: &Router, uri: &str, body: Value) {
    let (status, reply) = send(app, "POST", uri, Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{uri}: {reply}");
}

async fn search_for(app: &Router, uri: &str) -> ftl::SearchData {
    let (status, reply) = send(app, "GET", uri, None).await;
    assert_eq!(status, StatusCode::OK, "{uri}: {reply}");
    assert_ftl_shape::<ftl::Search>(&reply).search
}

/// The regex filters the mock engine attributes its regex matches to, with
/// the ids it expects.
async fn app_with_regexes() -> Router {
    let app = app().await;
    create(
        &app,
        "/domains/deny/regex",
        json!({ "domain": "^regex\\.blocked\\.test$" }),
    )
    .await;
    create(
        &app,
        "/domains/allow/regex",
        json!({ "domain": "allowlisted" }),
    )
    .await;
    app
}

/// A blocklist and an allowlist with the mock's blocklist id, and a second
/// blocklist that only [`helpers::MOCK_CLIENT_GROUP`] uses.
async fn app_with_lists() -> Router {
    let app = app().await;
    create(&app, "/groups", json!({ "name": "kids" })).await;
    create(&app, "/lists?type=block", json!({ "address": BLOCKLIST })).await;
    create(
        &app,
        "/lists?type=block",
        json!({ "address": GROUP_BLOCKLIST, "groups": [helpers::MOCK_CLIENT_GROUP] }),
    )
    .await;
    create(&app, "/lists?type=allow", json!({ "address": ALLOWLIST })).await;
    app
}

fn domains_of(search: &ftl::SearchData) -> Vec<&str> {
    search.domains.iter().map(|d| d.domain.as_str()).collect()
}

#[tokio::test]
async fn an_unlisted_domain_answers_ftls_shape_with_nothing_found() {
    let app = app().await;

    let search = search_for(&app, "/search/example.com").await;

    assert!(search.domains.is_empty());
    assert!(search.gravity.is_empty());
    assert_eq!(search.results.total, 0);
    assert_eq!(search.parameters.domain, "example.com");
    assert_eq!(search.parameters.n, 20, "search.c's default limit");
    assert!(!search.parameters.partial);
    assert!(!search.parameters.debug);
}

#[tokio::test]
async fn exact_entries_are_found_by_name_with_their_list_fields() {
    let app = app().await;
    create(
        &app,
        "/domains/deny/exact",
        json!({ "domain": "ads.example.com", "comment": "ads" }),
    )
    .await;
    create(
        &app,
        "/domains/allow/exact",
        json!({ "domain": "cdn.example.com", "enabled": false }),
    )
    .await;

    let search = search_for(&app, "/search/ads.example.com").await;

    assert_eq!(domains_of(&search), ["ads.example.com"]);
    let entry = &search.domains[0];
    assert_eq!(entry.domain_type, ftl::DomainType::Deny);
    assert_eq!(entry.kind, ftl::DomainKind::Exact);
    assert_eq!(entry.comment.as_deref(), Some("ads"));
    assert_eq!(
        entry.groups,
        vec![0],
        "Ferrous group 1 is FTL's Default (0)"
    );
    assert!(entry.date_added > 1_600_000_000, "unix seconds");
    assert_eq!(search.results.domains.exact, 1);
    assert_eq!(search.results.domains.regex, 0);
    assert_eq!(search.results.total, 1);

    let disabled = search_for(&app, "/search/cdn.example.com").await;
    assert_eq!(domains_of(&disabled), ["cdn.example.com"]);
    assert!(
        !disabled.domains[0].enabled,
        "disabled entries are listed too"
    );
}

#[tokio::test]
async fn regex_filters_matching_the_domain_are_listed_allow_first() {
    let app = app_with_regexes().await;

    let blocked = search_for(&app, "/search/regex.blocked.test").await;
    assert_eq!(domains_of(&blocked), ["^regex\\.blocked\\.test$"]);
    assert_eq!(blocked.domains[0].domain_type, ftl::DomainType::Deny);
    assert_eq!(blocked.domains[0].kind, ftl::DomainKind::Regex);
    assert_eq!(blocked.domains[0].id, helpers::MOCK_DENY_REGEX_ID);
    assert_eq!(blocked.results.domains.regex, 1);
    assert_eq!(blocked.results.domains.exact, 0);

    let allowed = search_for(&app, "/search/allowlisted.test").await;
    assert_eq!(domains_of(&allowed), ["allowlisted"]);
    assert_eq!(allowed.domains[0].domain_type, ftl::DomainType::Allow);
    assert_eq!(allowed.domains[0].id, helpers::MOCK_ALLOW_REGEX_ID);
    assert!(
        allowed.gravity.is_empty(),
        "an allowlist match without a list id names no list"
    );
}

#[tokio::test]
async fn partial_search_matches_exact_entries_and_regex_text_by_substring() {
    let app = app().await;
    for domain in ["ads.example.com", "tracker.example.org"] {
        create(&app, "/domains/deny/exact", json!({ "domain": domain })).await;
    }
    create(
        &app,
        "/domains/deny/regex",
        json!({ "domain": "^ads.example.com$" }),
    )
    .await;

    let search = search_for(&app, "/search/example.com?partial=true").await;

    assert_eq!(
        domains_of(&search),
        ["ads.example.com", "^ads.example.com$"]
    );
    assert_eq!(search.results.domains.exact, 1);
    assert_eq!(search.results.domains.regex, 1);
    assert!(search.parameters.partial);
}

#[tokio::test]
async fn blocklists_holding_the_domain_are_listed_in_gravity() {
    let app = app_with_lists().await;

    let search = search_for(&app, "/search/list.blocked.test").await;

    assert_eq!(search.gravity.len(), 1, "the manual blocklist has no list");
    let list = &search.gravity[0];
    assert_eq!(list.domain, "list.blocked.test");
    assert_eq!(list.address, BLOCKLIST);
    assert_eq!(list.list_type, ftl::ListType::Block);
    assert_eq!(list.id, helpers::MOCK_BLOCKLIST_ID);
    assert_eq!(list.groups, vec![0]);
    assert_eq!(search.results.gravity.block, 1);
    assert_eq!(search.results.gravity.allow, 0);
    assert_eq!(search.results.total, 1);
}

#[tokio::test]
async fn lists_of_every_group_are_searched() {
    let app = app_with_lists().await;

    let search = search_for(&app, "/search/group.blocked.test").await;

    let addresses: Vec<&str> = search.gravity.iter().map(|l| l.address.as_str()).collect();
    assert_eq!(addresses, [GROUP_BLOCKLIST]);
    assert_eq!(search.gravity[0].groups, vec![helpers::MOCK_CLIENT_GROUP]);
}

#[tokio::test]
async fn allowlists_holding_the_domain_are_listed_in_gravity() {
    // search.c: antigravity rows join the gravity array after the blocklists
    // and are counted as `results.gravity.allow`.
    let app = app_with_lists().await;

    let search = search_for(&app, "/search/allowlisted.test").await;

    assert_eq!(search.gravity.len(), 1, "the manual allowlist has no list");
    let list = &search.gravity[0];
    assert_eq!(list.domain, "allowlisted.test");
    assert_eq!(list.address, ALLOWLIST);
    assert_eq!(list.list_type, ftl::ListType::Allow);
    assert_eq!(list.id, helpers::MOCK_ALLOWLIST_ID);
    assert_eq!(search.results.gravity.allow, 1);
    assert_eq!(search.results.gravity.block, 0);
    assert_eq!(search.results.total, 1);
}

#[tokio::test]
async fn n_caps_the_rows_but_not_the_counts() {
    let app = app().await;
    for domain in ["a.example.com", "b.example.com", "c.example.com"] {
        create(&app, "/domains/deny/exact", json!({ "domain": domain })).await;
    }

    let search = search_for(&app, "/search/example.com?partial=true&N=2").await;

    assert_eq!(domains_of(&search), ["a.example.com", "b.example.com"]);
    assert_eq!(search.results.domains.exact, 3);
    assert_eq!(search.results.total, 3);
    assert_eq!(search.parameters.n, 2);
}

#[tokio::test]
async fn more_than_ten_thousand_results_is_a_bad_request() {
    let app = app().await;

    let (status, reply) = send(&app, "GET", "/search/example.com?N=10001", None).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert_eq!(reply["error"]["key"], "bad_request");
    assert_eq!(
        reply["error"]["message"],
        "Invalid request: Requested too many results"
    );
    assert_eq!(
        reply["error"]["hint"],
        "Requested 10001 number of results but hard upper limit is 10000"
    );
}

#[tokio::test]
async fn unparsable_parameters_keep_their_defaults() {
    let app = app().await;

    let search = search_for(&app, "/search/example.com?partial=yes&N=many&debug=TRUE").await;

    assert!(!search.parameters.partial);
    assert_eq!(search.parameters.n, 20);
    assert!(search.parameters.debug, "booleans are case-insensitive");
}

#[tokio::test]
async fn domain_is_matched_case_insensitively_without_root_dot() {
    let app = app_with_lists().await;

    let search = search_for(&app, "/search/LIST.Blocked.Test.").await;

    assert_eq!(search.gravity.len(), 1);
    assert_eq!(search.gravity[0].domain, "list.blocked.test");
    assert_eq!(
        search.parameters.domain, "LIST.Blocked.Test.",
        "parameters echo the domain as requested"
    );
}
