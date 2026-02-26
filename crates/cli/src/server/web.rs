use axum::{
    http::{header, HeaderValue, Method},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tracing::info;

pub async fn start_web_server(
    bind_addr: SocketAddr,
    state: AppState,
    cors_allowed_origins: &[String],
) -> anyhow::Result<()> {
    info!(
        bind_address = %bind_addr,
        dashboard_url = format!("http://{}", bind_addr),
        api_url = format!("http://{}/api", bind_addr),
        "Starting web server"
    );

    let app = create_app(state, cors_allowed_origins);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!("Web server started successfully");

    axum::serve(listener, app).await?;

    Ok(())
}

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins == ["*"] {
        return CorsLayer::permissive();
    }
    build_strict_cors(allowed_origins)
}

fn build_strict_cors(allowed_origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}

fn create_app(state: AppState, cors_allowed_origins: &[String]) -> Router {
    Router::new()
        .nest("/api", create_api_routes(state))
        .route("/static/shared.css", get(shared_css_handler))
        .route("/", get(index_handler))
        .route("/dashboard.html", get(dashboard_handler))
        .route("/queries.html", get(queries_handler))
        .route("/clients.html", get(clients_handler))
        .route("/groups.html", get(groups_handler))
        .route("/local-dns-settings.html", get(local_dns_settings_handler))
        .route("/settings.html", get(settings_handler))
        .route("/dns-filter.html", get(dns_filter_handler))
        .route("/block-services.html", get(block_services_handler))
        .layer(build_cors_layer(cors_allowed_origins))
}

async fn shared_css_handler() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../../web/static/shared.css"),
    )
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/index.html"))
}

async fn dashboard_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/dashboard.html"))
}

async fn queries_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/queries.html"))
}

async fn clients_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/clients.html"))
}

async fn groups_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/groups.html"))
}

async fn local_dns_settings_handler() -> Html<&'static str> {
    Html(include_str!(
        "../../../../web/static/local-dns-settings.html"
    ))
}

async fn settings_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/settings.html"))
}

async fn dns_filter_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/dns-filter.html"))
}

async fn block_services_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/block-services.html"))
}
