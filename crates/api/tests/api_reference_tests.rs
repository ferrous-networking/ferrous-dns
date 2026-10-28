//! `docs/api.md` is the reference the v1 API is frozen against: every route
//! the router serves must have an entry there, and every entry must be a
//! route. Entries are the `METHOD /ferrous/api/v1/...` lines of its ```http
//! blocks; path parameters are compared by position, not by name. The JSON
//! request example under an entry must use the fields its request schema has.
use ferrous_dns_api::create_api_router_with_openapi;
use helpers::TestApp;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

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

async fn spec() -> Value {
    let app = TestApp::new().await;
    serde_json::to_value(create_api_router_with_openapi(app.state).1).unwrap()
}

/// Every `METHOD /path` the spec lists, with its operation.
fn operations(spec: &Value) -> impl Iterator<Item = (String, &Value)> {
    let paths = spec["paths"].as_object().expect("spec has paths");
    paths.iter().flat_map(|(path, item)| {
        item.as_object()
            .unwrap()
            .iter()
            .map(|(method, operation)| (method.to_ascii_uppercase(), operation))
            .filter(|(method, _)| METHODS.contains(&method.as_str()))
            .map(move |(method, operation)| (format!("{method} {}", normalize(path)), operation))
    })
}

async fn routed() -> BTreeSet<String> {
    operations(&spec().await).map(|(route, _)| route).collect()
}

fn reference() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api.md")).unwrap()
}

/// The route of each ```http line, or `None` for a line that is not one.
fn entry(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    let (method, path) = (words.next()?, words.next()?);
    let route = path.strip_prefix(BASE)?;
    METHODS
        .contains(&method)
        .then(|| format!("{method} {}", normalize(route)))
}

fn documented() -> BTreeSet<String> {
    let reference = reference();
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
        entries.extend(entry(trimmed));
    }
    entries
}

/// Request schema name of each route that takes a JSON body.
fn request_schemas(spec: &Value) -> BTreeMap<String, String> {
    operations(spec)
        .filter_map(|(route, operation)| {
            let schema = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
                .as_str()?;
            Some((route, schema.rsplit('/').next()?.to_string()))
        })
        .collect()
}

/// The fields a schema accepts and the ones it requires, `allOf` parts included.
fn fields(spec: &Value, schema: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let schema = &spec["components"]["schemas"][schema];
    let mut known: BTreeSet<String> = schema["properties"]
        .as_object()
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default();
    let mut required: BTreeSet<String> = schema["required"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    for part in schema["allOf"].as_array().into_iter().flatten() {
        if let Some(name) = part["$ref"].as_str().and_then(|r| r.rsplit('/').next()) {
            let (more_known, more_required) = fields(spec, name);
            known.extend(more_known);
            required.extend(more_required);
        }
    }
    (known, required)
}

/// A JSON object shown after an ```http block, before the next heading.
struct Example {
    line: usize,
    routes: Vec<String>,
    body: Map<String, Value>,
}

/// The first JSON example under each ```http block.
fn examples(reference: &str) -> Vec<Example> {
    let lines: Vec<&str> = reference.lines().map(str::trim).collect();
    let mut examples = Vec::new();
    let mut routes: Option<Vec<String>> = None;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.starts_with('#') {
            routes = None;
        } else if line == "```http" {
            let end = i + lines[i..].iter().skip(1).position(|l| *l == "```").unwrap() + 1;
            routes = Some(lines[i + 1..end].iter().filter_map(|l| entry(l)).collect());
            i = end;
        } else if line == "```json" {
            let end = i + lines[i..].iter().skip(1).position(|l| *l == "```").unwrap() + 1;
            let body = serde_json::from_str::<Value>(&lines[i + 1..end].join("\n"));
            if let (Some(routes), Ok(Value::Object(body))) = (routes.take(), body) {
                examples.push(Example {
                    line: i + 1,
                    routes,
                    body,
                });
            }
            i = end;
        }
        i += 1;
    }
    examples
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

/// A renamed DTO field leaves an example the API silently ignores.
#[tokio::test]
async fn test_every_request_example_uses_the_fields_of_its_request_schema() {
    let spec = spec().await;
    let schemas = request_schemas(&spec);
    let mut checked = 0;
    let mut wrong = Vec::new();
    for example in examples(&reference()) {
        // Under a block of several routes, the example is for the one that takes a body.
        let with_body: Vec<_> = example
            .routes
            .iter()
            .filter_map(|route| Some((route, schemas.get(route)?)))
            .collect();
        let [(route, schema)] = with_body[..] else {
            continue;
        };
        checked += 1;
        let (known, required) = fields(&spec, schema);
        let keys: BTreeSet<String> = example.body.keys().cloned().collect();
        let unknown: Vec<_> = keys.difference(&known).collect();
        let missing: Vec<_> = required.difference(&keys).collect();
        if !unknown.is_empty() || !missing.is_empty() {
            wrong.push(format!(
                "docs/api.md:{}: {route} ({schema}) unknown {unknown:?}, missing {missing:?}",
                example.line
            ));
        }
    }

    assert!(checked > 20, "checked only {checked} request examples");
    assert!(
        wrong.is_empty(),
        "request examples that do not match their schema:\n  {}",
        wrong.join("\n  ")
    );
}
