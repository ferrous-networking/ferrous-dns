use axum::{
    http::{header, HeaderValue, Method},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tracing::info;

pub async fn start_doh_server(
    bind_addr: SocketAddr,
    handler: Arc<DnsServerHandler>,
) -> anyhow::Result<()> {
    info!(
        bind_address = %bind_addr,
        endpoint = format!("http://{}/dns-query", bind_addr),
        "Starting DoH server (DNS-over-HTTPS, RFC 8484)"
    );

    let app = Router::new()
        .route(
            "/dns-query",
            get(crate::server::doh::dns_query_handler).post(crate::server::doh::dns_query_handler),
        )
        .layer(axum::Extension(handler));

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!("DoH server ready on {}", bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn start_web_server(
    bind_addr: SocketAddr,
    state: AppState,
    cors_allowed_origins: &[String],
    doh_handler: Option<Arc<DnsServerHandler>>,
) -> anyhow::Result<()> {
    info!(
        bind_address = %bind_addr,
        dashboard_url = format!("http://{}", bind_addr),
        api_url = format!("http://{}/api", bind_addr),
        "Starting web server"
    );

    let app = create_app(state, cors_allowed_origins, doh_handler);
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

fn create_app(
    state: AppState,
    cors_allowed_origins: &[String],
    doh_handler: Option<Arc<DnsServerHandler>>,
) -> Router {
    let mut app = Router::new()
        .nest("/api", create_api_routes(state))
        .route("/static/shared.css", get(shared_css_handler))
        .route("/static/shared.js", get(shared_js_handler))
        .route("/static/logo.svg", get(logo_svg_handler))
        .route("/", get(index_handler))
        .route("/dashboard.html", get(dashboard_handler))
        .route("/queries.html", get(queries_handler))
        .route("/clients.html", get(clients_handler))
        .route("/groups.html", get(groups_handler))
        .route("/local-dns-settings.html", get(local_dns_settings_handler))
        .route("/settings.html", get(settings_handler))
        .route("/dns-filter.html", get(dns_filter_handler))
        .route("/block-services.html", get(block_services_handler))
        .layer(CompressionLayer::new().gzip(true))
        .layer(build_cors_layer(cors_allowed_origins));

    if let Some(handler) = doh_handler {
        app = app
            .route(
                "/dns-query",
                get(crate::server::doh::dns_query_handler)
                    .post(crate::server::doh::dns_query_handler),
            )
            .layer(axum::Extension(handler));
    }

    app
}

async fn shared_css_handler() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../../web/static/shared.css"),
    )
}

async fn shared_js_handler() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../../../../web/static/shared.js"),
    )
}

async fn logo_svg_handler() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        include_str!("../../../../web/static/logo.svg"),
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
