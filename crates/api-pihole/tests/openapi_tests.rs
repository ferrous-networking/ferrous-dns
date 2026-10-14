mod helpers;

#[tokio::test]
async fn served_spec_documents_routes_but_not_aliases() {
    let pool = helpers::create_test_db().await;
    let spec = helpers::create_pihole_test_openapi(pool).await;
    let paths = &spec.paths.paths;

    for documented in [
        "/auth",
        "/info/login",
        "/stats/summary",
        "/stats/database/summary",
        "/dns/blocking",
        "/domains/{type}/{kind}",
        // FTL's route; /stats/history is only a Ferrous alias.
        "/history",
    ] {
        assert!(paths.contains_key(documented), "missing path {documented}");
    }
    assert!(
        !paths.contains_key("/stats/history"),
        "alias /stats/history must stay undocumented"
    );
}

#[tokio::test]
async fn served_spec_declares_session_header_scheme() {
    let pool = helpers::create_test_db().await;
    let spec = helpers::create_pihole_test_openapi(pool).await;
    let json = serde_json::to_value(&spec).expect("spec must serialize");

    assert_eq!(
        json["components"]["securitySchemes"]["session_id"],
        serde_json::json!({ "type": "apiKey", "in": "header", "name": "X-FTL-SID" })
    );
}
