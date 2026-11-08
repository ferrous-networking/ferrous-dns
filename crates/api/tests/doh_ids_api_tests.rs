use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ferrous_dns_api::create_api_router_with_openapi;
use helpers::TestApp;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

mod helpers;

async fn test_app() -> TestApp {
    TestApp::builder().groups(&["Office", "Kids"]).build().await
}

async fn read_json(response: axum::response::Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn test_get_doh_ids_empty() {
    let app = test_app().await.router;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert_eq!(json, json!([]));
}

#[tokio::test]
async fn test_create_doh_id_generates_uuid_and_enriches_group_name() {
    let app = test_app().await.router;

    let payload = json!({
        "name": "Alice Phone",
        "group_id": 2,
        "comment": "Personal iPhone"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = read_json(response).await;
    assert_eq!(json["name"], "Alice Phone");
    assert_eq!(json["group_id"], 2);
    assert_eq!(json["group_name"], "Office");
    assert_eq!(json["comment"], "Personal iPhone");
    assert_eq!(json["client_id"].as_str().unwrap().len(), 36);
    assert!(json["created_at"].is_string());
    assert!(json["updated_at"].is_string());
}

#[tokio::test]
async fn test_crud_doh_id_lifecycle_with_custom_id_and_comment_clear() {
    let app = test_app().await.router;

    // Create with custom client_id
    let create_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Kids Tablet",
                        "client_id": "kids-tablet",
                        "group_id": 3,
                        "comment": "Bedtime filtered"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);
    let created = read_json(create_res).await;
    let id = created["id"].as_i64().unwrap();
    assert_eq!(created["client_id"], "kids-tablet");
    assert_eq!(created["group_name"], "Kids");

    // GET all verifies group_name resolution on list
    let list_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let listed = read_json(list_res).await;
    let listed_arr = listed.as_array().unwrap();
    assert_eq!(listed_arr.len(), 1);
    assert_eq!(listed_arr[0]["id"], id);
    assert_eq!(listed_arr[0]["group_name"], "Kids");

    // GET by id
    let get_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/doh-ids/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    assert_eq!(read_json(get_res).await["name"], "Kids Tablet");

    // PUT keeping client_id (omitted) and clearing comment (null)
    let update_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/doh-ids/{id}"))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Kids iPad",
                        "group_id": 2,
                        "comment": null
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_res.status(), StatusCode::OK);
    let updated = read_json(update_res).await;
    assert_eq!(updated["name"], "Kids iPad");
    assert_eq!(updated["client_id"], "kids-tablet");
    assert_eq!(updated["group_id"], 2);
    assert_eq!(updated["group_name"], "Office");
    assert!(updated["comment"].is_null());

    // PUT rotating client_id
    let rotate_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/doh-ids/{id}"))
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Kids iPad",
                        "client_id": "kids-ipad-v2",
                        "group_id": 2,
                        "comment": "Rotated"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotate_res.status(), StatusCode::OK);
    assert_eq!(read_json(rotate_res).await["client_id"], "kids-ipad-v2");

    // DELETE
    let del_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/doh-ids/{id}"))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_res.status(), StatusCode::NO_CONTENT);

    // Second DELETE -> 404
    let del_again = app
        .oneshot(
            Request::builder()
                .uri(format!("/doh-ids/{id}"))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_again.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_doh_ids_validation_not_found_and_conflict_status_codes() {
    let app = test_app().await.router;

    // 400 invalid client_id
    let bad_req = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Phone",
                        "client_id": "UPPERCASE_NOT_ALLOWED",
                        "group_id": 1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_req.status(), StatusCode::BAD_REQUEST);

    // 404 missing group
    let missing_group = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Phone",
                        "group_id": 999
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_group.status(), StatusCode::NOT_FOUND);

    // Seed one entry, then verify 409 on duplicate name or duplicate client_id
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Work Laptop",
                        "client_id": "work-laptop",
                        "group_id": 1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let dup_name = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Work Laptop",
                        "group_id": 1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_name.status(), StatusCode::CONFLICT);

    let dup_cid = app
        .oneshot(
            Request::builder()
                .uri("/doh-ids")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Second Laptop",
                        "client_id": "work-laptop",
                        "group_id": 1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_cid.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_openapi_spec_registers_doh_ids_routes_and_schemas() {
    let app = test_app().await;
    let (_router, openapi) = create_api_router_with_openapi(app.state);
    let spec = serde_json::to_value(&openapi).unwrap();

    assert!(spec["paths"]["/doh-ids"]["get"].is_object());
    assert!(spec["paths"]["/doh-ids"]["post"].is_object());
    assert!(spec["paths"]["/doh-ids/{id}"]["get"].is_object());
    assert!(spec["paths"]["/doh-ids/{id}"]["put"].is_object());
    assert!(spec["paths"]["/doh-ids/{id}"]["delete"].is_object());

    let schemas = &spec["components"]["schemas"];
    assert!(schemas["DohIdResponse"].is_object());
    assert!(schemas["CreateDohIdRequest"].is_object());
    assert!(schemas["UpdateDohIdRequest"].is_object());
}
