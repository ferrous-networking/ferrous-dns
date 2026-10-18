//! Tests for the `GET`/`DELETE /cache/entries` admin endpoints.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    BorrowedKey, CachedAddresses, CachedData, DnsCache, DnsCacheAccess,
};
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    // `max_entries` must be non-zero: with 0 every insert immediately flags the
    // cache for eviction and the seeded entries would not survive.
    TestApp::builder().cache_max_entries(1000).build().await
}

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
}

fn seed(cache: &DnsCache, domains: &[&str]) {
    coarse_clock::tick();
    for domain in domains {
        cache.insert(domain, RecordType::A, make_ip_data("1.2.3.4"), 300, None);
    }
}

async fn get_json(app: Router, uri: &str) -> Value {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

async fn delete_status(app: Router, uri: &str) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn test_get_cache_entries_returns_seeded_entries() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["a.test", "b.test"]);

    let json = get_json(app, "/cache/entries").await;

    assert_eq!(json["total"], 2);
    assert_eq!(json["records_total"], 2);
    assert_eq!(json["limit"], 25, "limit defaults to 25");
    assert_eq!(json["offset"], 0);

    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0]["type"], "A");
    assert_eq!(data[0]["answers"][0], "1.2.3.4");
    assert_eq!(data[0]["permanent"], false);
    assert_eq!(data[0]["stale"], false);
    assert!(data[0]["remaining_ttl"].is_number());
}

#[tokio::test]
async fn test_get_cache_entries_paginates_with_offset() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["a.page", "b.page", "c.page"]);

    let first = get_json(
        app.clone(),
        "/cache/entries?limit=2&offset=0&sort=domain&order=asc",
    )
    .await;
    let first_domains: Vec<&str> = first["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["domain"].as_str().unwrap())
        .collect();
    assert_eq!(first_domains, vec!["a.page", "b.page"]);
    assert_eq!(first["total"], 3);
    assert_eq!(first["limit"], 2);

    let second = get_json(app, "/cache/entries?limit=2&offset=2&sort=domain&order=asc").await;
    let second_domains: Vec<&str> = second["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["domain"].as_str().unwrap())
        .collect();
    assert_eq!(second_domains, vec!["c.page"]);
    assert_eq!(second["total"], 3);
    assert_eq!(second["offset"], 2);
}

#[tokio::test]
async fn test_get_cache_entries_filters_by_domain() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(
        &cache,
        &["shop.example.com", "api.example.org", "other.test"],
    );

    let json = get_json(app, "/cache/entries?domain=example").await;

    assert_eq!(json["total"], 2, "total counts only filtered entries");
    assert_eq!(
        json["records_total"], 3,
        "records_total ignores the domain filter"
    );
    assert_eq!(json["data"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_get_cache_entries_sorts_by_domain_in_both_directions() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["c.sorted", "a.sorted", "b.sorted"]);

    let asc = get_json(app.clone(), "/cache/entries?sort=domain&order=asc").await;
    let asc_domains: Vec<&str> = asc["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["domain"].as_str().unwrap())
        .collect();
    assert_eq!(asc_domains, vec!["a.sorted", "b.sorted", "c.sorted"]);

    let desc = get_json(app, "/cache/entries?sort=domain&order=desc").await;
    let desc_domains: Vec<&str> = desc["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["domain"].as_str().unwrap())
        .collect();
    assert_eq!(desc_domains, vec!["c.sorted", "b.sorted", "a.sorted"]);
}

#[tokio::test]
async fn test_get_cache_entries_ignores_unknown_sort_and_order() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["a.fallback", "b.fallback"]);

    let json = get_json(app, "/cache/entries?sort=bogus&order=sideways").await;

    assert_eq!(
        json["total"], 2,
        "unparsable sort/order fall back to the defaults instead of failing"
    );
}

#[tokio::test]
async fn test_get_cache_entries_reports_and_sorts_by_refreshes() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["fresh.test", "renewed.test"]);
    for _ in 0..2 {
        assert!(cache.refresh_record(
            "renewed.test",
            &RecordType::A,
            Some(300),
            make_ip_data("1.2.3.4"),
            None,
        ));
    }

    let json = get_json(app, "/cache/entries?sort=refreshes&order=desc").await;

    let data = json["data"].as_array().unwrap();
    assert_eq!(data[0]["domain"], "renewed.test");
    assert_eq!(data[0]["refreshes"], 2);
    assert_eq!(data[1]["domain"], "fresh.test");
    assert_eq!(data[1]["refreshes"], 0);
}

#[tokio::test]
async fn test_get_cache_overview_reports_top_refreshed_and_counts() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["fresh.test", "renewed.test"]);
    cache.insert(
        "soon.test",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        30,
        None,
    );
    for _ in 0..3 {
        assert!(cache.refresh_record(
            "renewed.test",
            &RecordType::A,
            Some(300),
            make_ip_data("1.2.3.4"),
            None,
        ));
    }

    let json = get_json(app, "/cache/overview").await;

    let top = json["top_refreshed"].as_array().unwrap();
    assert_eq!(top.len(), 1, "entries never renewed are left out");
    assert_eq!(top[0]["domain"], "renewed.test");
    assert_eq!(top[0]["type"], "A");
    assert_eq!(top[0]["refreshes"], 3);
    assert_eq!(json["expiring_soon"], 1);
    assert_eq!(json["expiring_window_secs"], 60);
    assert_eq!(json["inserted"], 3);
    assert_eq!(json["expired"], 0);
}

#[tokio::test]
async fn test_get_cache_entries_clamps_limit_to_maximum() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["a.limit"]);

    let json = get_json(app, "/cache/entries?limit=99999").await;

    assert_eq!(json["limit"], 500, "limit is clamped to 500");
}

#[tokio::test]
async fn test_get_cache_entries_clamps_zero_limit_to_one() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["a.zero", "b.zero"]);

    let json = get_json(app, "/cache/entries?limit=0").await;

    assert_eq!(json["limit"], 1);
    assert_eq!(json["data"].as_array().unwrap().len(), 1);
    assert_eq!(json["total"], 2);
}

#[tokio::test]
async fn test_delete_cache_entry_returns_no_content_and_removes_it() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["doomed.test", "kept.test"]);

    let status = delete_status(app.clone(), "/cache/entries?domain=doomed.test&type=A").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let json = get_json(app, "/cache/entries").await;
    assert_eq!(json["total"], 1);
    assert_eq!(json["data"][0]["domain"], "kept.test");
}

#[tokio::test]
async fn test_delete_cache_entry_returns_not_found_for_missing_entry() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["present.test"]);

    let status = delete_status(app, "/cache/entries?domain=absent.test&type=A").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_cache_entry_returns_bad_request_for_unknown_type() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["present.test"]);

    let status = delete_status(app, "/cache/entries?domain=present.test&type=NOPE").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Caches `domain` A in client group `group`'s own view.
fn seed_in_group(cache: &DnsCache, domain: &str, group: u32, ip: &str) {
    coarse_clock::tick();
    DnsCacheAccess::insert(
        cache,
        BorrowedKey::new(domain, RecordType::A).in_view(group),
        make_ip_data(ip),
        300,
        None,
        true,
    );
}

#[tokio::test]
async fn test_get_cache_entries_reports_the_group_of_a_split_horizon_entry() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["corp.test"]);
    seed_in_group(&cache, "corp.test", 3, "10.1.1.1");

    let json = get_json(app, "/cache/entries?domain=corp.test").await;

    assert_eq!(json["total"], 2);
    let data = json["data"].as_array().unwrap();
    let shared = data.iter().find(|e| e["group_id"].is_null()).unwrap();
    let grouped = data.iter().find(|e| e["group_id"] == 3).unwrap();
    assert_eq!(shared["answers"][0], "1.2.3.4");
    assert_eq!(grouped["answers"][0], "10.1.1.1");
}

#[tokio::test]
async fn test_delete_cache_entry_removes_only_the_named_group_view() {
    let TestApp {
        router: app, cache, ..
    } = test_app().await;
    seed(&cache, &["corp.test"]);
    seed_in_group(&cache, "corp.test", 3, "10.1.1.1");

    let status = delete_status(
        app.clone(),
        "/cache/entries?domain=corp.test&type=A&group_id=3",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let json = get_json(app.clone(), "/cache/entries?domain=corp.test").await;
    assert_eq!(json["total"], 1);
    assert!(json["data"][0]["group_id"].is_null());

    let status = delete_status(app, "/cache/entries?domain=corp.test&type=A&group_id=3").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
