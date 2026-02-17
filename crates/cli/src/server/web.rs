use axum::{response::Html, routing::get, Router};
use ferrous_dns_api::{create_api_routes, AppState};
use std::net::SocketAddr;
use tower_http::services::ServeDir;
use tracing::info;

pub async fn start_web_server(bind_addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    info!(
        bind_address = %bind_addr,
        dashboard_url = format!("http://{}", bind_addr),
        api_url = format!("http://{}/api", bind_addr),
        "Starting web server"
    );

    let app = create_app(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!("Web server started successfully");

    axum::serve(listener, app).await?;

    Ok(())
}

fn create_app(state: AppState) -> Router {
    Router::new()
        .nest("/api", create_api_routes(state))
        .nest_service("/static", ServeDir::new("web/static"))
        .route("/", get(index_handler))
        .route("/dashboard.html", get(dashboard_handler))
        .route("/queries.html", get(queries_handler))
        .route("/clients.html", get(clients_handler))
        .route("/groups.html", get(groups_handler))
        .route("/local-dns-settings.html", get(local_dns_settings_handler))
        .route("/settings.html", get(settings_handler))
        .route("/dns-filter.html", get(dns_filter_handler))
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
