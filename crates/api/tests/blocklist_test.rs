mod helpers;

#[tokio::test]
async fn test_placeholder() {
    // Placeholder - aguardando TestApp com métodos get(), post_json(), delete()
    assert!(true);
}

/*
use helpers::TestApp;
use axum::http::StatusCode;

#[tokio::test]
async fn test_get_blocklist_endpoint() {
    let app = TestApp::new().await;
    let response = app.get("/blocklist").await;
    assert_eq!(response.status(), StatusCode::OK);
}

// ... outros testes comentados
*/
