//! `docs/api.md` is the reference the v1 API is frozen against: every route
//! the router serves must have an entry there, and every entry must be a
//! route. Entries are the `METHOD /ferrous/api/v1/...` lines of its ```http
//! blocks; path parameters are compared by position, not by name.
use ferrous_dns_api::create_api_router_with_openapi;
use helpers::TestApp;
use std::collections::BTreeSet;

mod helpers;

const BASE: &str = "/ferrous/api/v1";
const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// `/clients/{id}/group` and `/clients/{client_id}/group` are the same route.
fn normalize(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "{}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

async fn routed() -> BTreeSet<String> {
    let app = TestApp::new().await;
    let spec = serde_json::to_value(create_api_router_with_openapi(app.state).1).unwrap();
    let paths = spec["paths"].as_object().expect("spec has paths");
    paths
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .unwrap()
                .keys()
                .map(|method| method.to_ascii_uppercase())
                .filter(|method| METHODS.contains(&method.as_str()))
                .map(move |method| format!("{method} {}", normalize(path)))
        })
        .collect()
}

fn documented() -> BTreeSet<String> {
    let reference =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api.md")).unwrap();
    let mut in_http_block = false;
    let mut entries = BTreeSet::new();
    for line in reference.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_http_block = !in_http_block && trimmed == "```http";
            continue;
        }
        if !in_http_block {
            continue;
        }
        let mut words = trimmed.split_whitespace();
        let (Some(method), Some(path)) = (words.next(), words.next()) else {
            continue;
        };
        if let (true, Some(route)) = (METHODS.contains(&method), path.strip_prefix(BASE)) {
            entries.insert(format!("{method} {}", normalize(route)));
        }
    }
    entries
}

#[tokio::test]
async fn test_every_route_has_an_entry_in_the_api_reference() {
    let documented = documented();
    let missing: Vec<_> = routed().await.difference(&documented).cloned().collect();

    assert!(
        missing.is_empty(),
        "routes with no entry in docs/api.md:\n  {}",
        missing.join("\n  ")
    );
}

#[tokio::test]
async fn test_every_api_reference_entry_is_a_route() {
    let routed = routed().await;
    let documented = documented();
    assert!(
        documented.len() > 100,
        "parsed only {} entries from docs/api.md",
        documented.len()
    );
    let phantom: Vec<_> = documented.difference(&routed).cloned().collect();

    assert!(
        phantom.is_empty(),
        "docs/api.md documents routes that do not exist:\n  {}",
        phantom.join("\n  ")
    );
}
