mod helpers;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use helpers::ftl::{assert_ftl_shape, Endpoint, Endpoints};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

async fn get_endpoints() -> Endpoints {
    let pool = helpers::create_test_db().await;
    let app = helpers::create_pihole_test_app(pool).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/endpoints")
                .body(Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let json: Value = serde_json::from_slice(&bytes).expect("invalid JSON");
    assert_ftl_shape::<Endpoints>(&json)
}

fn lists(endpoints: &[Endpoint], uri: &str, parameters: &str) -> bool {
    endpoints
        .iter()
        .any(|e| e.uri == uri && e.parameters == parameters)
}

#[tokio::test]
async fn endpoints_matches_the_ftl_schema() {
    get_endpoints().await;
}

#[tokio::test]
async fn endpoints_lists_routes_under_their_methods() {
    let endpoints = get_endpoints().await.endpoints;

    for uri in [
        "/api/padd",
        "/api/endpoints",
        "/api/info/login",
        "/api/auth",
    ] {
        assert!(lists(&endpoints.get, uri, ""), "GET {uri} missing");
    }
    assert!(lists(&endpoints.post, "/api/auth", ""), "POST /api/auth");
    assert!(
        lists(&endpoints.delete, "/api/auth", ""),
        "DELETE /api/auth"
    );
    assert!(
        !lists(&endpoints.post, "/api/padd", ""),
        "/api/padd is GET only"
    );
}

#[tokio::test]
async fn endpoints_split_path_parameters_off_the_uri_as_ftl_does() {
    let endpoints = get_endpoints().await.endpoints;

    // api.c: `{ "/api/domains", "/{type}/{kind}/{domain}", ... HTTP_GET | HTTP_PUT | HTTP_DELETE }`
    for method in [&endpoints.get, &endpoints.put, &endpoints.delete] {
        assert!(lists(method, "/api/domains", "/{type}/{kind}/{domain}"));
    }
    assert!(lists(&endpoints.post, "/api/domains", "/{type}/{kind}"));
    assert!(lists(&endpoints.get, "/api/search", "/{domain}"));
    assert!(lists(&endpoints.post, "/api/domains:batchDelete", ""));
}

#[tokio::test]
async fn endpoints_carry_the_api_prefix_and_bare_uris() {
    let endpoints = get_endpoints().await.endpoints;
    let all = [
        &endpoints.get,
        &endpoints.post,
        &endpoints.put,
        &endpoints.patch,
        &endpoints.delete,
    ];

    for endpoint in all.iter().flat_map(|method| method.iter()) {
        assert!(
            endpoint.uri.starts_with("/api/"),
            "{} lacks the /api prefix",
            endpoint.uri
        );
        assert!(
            !endpoint.uri.contains('{'),
            "{} keeps a parameter in the uri",
            endpoint.uri
        );
    }
}
