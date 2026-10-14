mod helpers;

use axum::http::StatusCode;
use helpers::ftl::{assert_ftl_shape, NetworkGateway, NetworkInterfaces, NetworkRoutes};

async fn get(uri: &str) -> serde_json::Value {
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;
    let (status, json) = helpers::send(app, "GET", uri).await;
    assert_eq!(status, StatusCode::OK, "GET {uri}: {json}");
    json
}

#[tokio::test]
async fn gateway_matches_the_ftl_schema() {
    let gateway = assert_ftl_shape::<NetworkGateway>(&get("/network/gateway").await).gateway;

    for entry in gateway {
        assert!(matches!(entry.family.as_str(), "inet" | "inet6"));
    }
}

#[tokio::test]
async fn routes_match_the_ftl_schema() {
    let routes = assert_ftl_shape::<NetworkRoutes>(&get("/network/routes").await).routes;

    for route in routes {
        assert!(matches!(route.family.as_str(), "inet" | "inet6"));
        assert!(!route.dst.is_empty());
    }
}

#[tokio::test]
async fn interfaces_match_the_ftl_schema() {
    let interfaces =
        assert_ftl_shape::<NetworkInterfaces>(&get("/network/interfaces").await).interfaces;

    if std::path::Path::new("/sys/class/net/lo").exists() {
        let lo = interfaces
            .iter()
            .find(|i| i.name == "lo")
            .expect("lo is listed");
        assert_eq!(lo.link_type.as_deref(), Some("loopback"));
    }
}
