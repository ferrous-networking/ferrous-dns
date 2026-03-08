use axum::{
    extract::State,
    http::{header, HeaderValue, Method},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use ferrous_dns_api::{create_api_routes, AppState};
use ferrous_dns_api_pihole::{create_pihole_routes, PiholeAppState};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tracing::info;

use super::web_tls;

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
    ferrous_state: AppState,
    pihole_state: PiholeAppState,
    cors_allowed_origins: &[String],
    pihole_compat: bool,
    doh_handler: Option<Arc<DnsServerHandler>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> anyhow::Result<()> {
    let scheme = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };

    if pihole_compat {
        info!(
            bind_address = %bind_addr,
            dashboard_url = format!("{}://{}", scheme, bind_addr),
            ferrous_api_url = format!("{}://{}/ferrous/api", scheme, bind_addr),
            pihole_api_url = format!("{}://{}/api", scheme, bind_addr),
            "Starting web server (Pi-hole compat mode)"
        );
    } else {
        info!(
            bind_address = %bind_addr,
            dashboard_url = format!("{}://{}", scheme, bind_addr),
            api_url = format!("{}://{}/api", scheme, bind_addr),
            "Starting web server"
        );
    }

    let app = create_app(
        ferrous_state,
        pihole_state,
        cors_allowed_origins,
        pihole_compat,
        doh_handler,
    );

    if let Some(tls_cfg) = tls_config {
        info!("Web server started successfully (HTTPS)");
        web_tls::start_https_web_server(bind_addr, app, tls_cfg).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!("Web server started successfully");
        axum::serve(listener, app).await?;
    }

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
    ferrous_state: AppState,
    pihole_state: PiholeAppState,
    cors_allowed_origins: &[String],
    pihole_compat: bool,
    doh_handler: Option<Arc<DnsServerHandler>>,
) -> Router {
    let router = if pihole_compat {
        Router::new()
            .nest("/api", create_pihole_routes(pihole_state))
            .nest("/ferrous/api", create_api_routes(ferrous_state))
    } else {
        Router::new().nest("/api", create_api_routes(ferrous_state))
    };

    let mut app = router
        .route(
            "/ferrous-config.js",
            get(ferrous_config_js_handler).with_state(pihole_compat),
        )
        .route("/static/shared.css", get(shared_css_handler))
        .route("/static/shared.js", get(shared_js_handler))
        .route("/static/logo.svg", get(logo_svg_handler))
        .route("/static/dashboard.css", get(dashboard_css_handler))
        .route("/static/dashboard.js", get(dashboard_js_handler))
        .route("/static/queries.css", get(queries_css_handler))
        .route("/static/queries.js", get(queries_js_handler))
        .route("/static/clients.css", get(clients_css_handler))
        .route("/static/clients.js", get(clients_js_handler))
        .route("/static/groups.css", get(groups_css_handler))
        .route("/static/groups.js", get(groups_js_handler))
        .route(
            "/static/local-dns-settings.css",
            get(local_dns_settings_css_handler),
        )
        .route(
            "/static/local-dns-settings.js",
            get(local_dns_settings_js_handler),
        )
        .route("/static/settings.css", get(settings_css_handler))
        .route("/static/settings.js", get(settings_js_handler))
        .route("/static/dns-filter.css", get(dns_filter_css_handler))
        .route("/static/dns-filter.js", get(dns_filter_js_handler))
        .route(
            "/static/block-services.css",
            get(block_services_css_handler),
        )
        .route("/static/block-services.js", get(block_services_js_handler))
        .route("/static/login.css", get(login_css_handler))
        .route("/static/login.js", get(login_js_handler))
        .route("/", get(index_handler))
        .route("/login.html", get(login_handler))
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

/// Returns a small JS snippet that sets `window.FERROUS_API_BASE` at runtime.
///
/// The HTMLs are compiled into the binary via `include_str!` and cannot be
/// patched at runtime, so the frontend discovers the correct API prefix here.
///
/// - `pihole_compat = false` → `window.FERROUS_API_BASE = "/api";`
/// - `pihole_compat = true`  → `window.FERROUS_API_BASE = "/ferrous/api";`
async fn ferrous_config_js_handler(State(pihole_compat): State<bool>) -> impl IntoResponse {
    let api_base = if pihole_compat {
        "/ferrous/api"
    } else {
        "/api"
    };
    let body = format!(r#"window.FERROUS_API_BASE = "{api_base}";"#);
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        body,
    )
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

async fn login_handler() -> Html<&'static str> {
    Html(include_str!("../../../../web/static/login.html"))
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

macro_rules! css_handler {
    ($name:ident, $path:expr) => {
        async fn $name() -> impl IntoResponse {
            (
                [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                include_str!($path),
            )
        }
    };
}

macro_rules! js_handler {
    ($name:ident, $path:expr) => {
        async fn $name() -> impl IntoResponse {
            (
                [(
                    header::CONTENT_TYPE,
                    "application/javascript; charset=utf-8",
                )],
                include_str!($path),
            )
        }
    };
}

css_handler!(
    dashboard_css_handler,
    "../../../../web/static/dashboard.css"
);
js_handler!(dashboard_js_handler, "../../../../web/static/dashboard.js");
css_handler!(queries_css_handler, "../../../../web/static/queries.css");
js_handler!(queries_js_handler, "../../../../web/static/queries.js");
css_handler!(clients_css_handler, "../../../../web/static/clients.css");
js_handler!(clients_js_handler, "../../../../web/static/clients.js");
css_handler!(groups_css_handler, "../../../../web/static/groups.css");
js_handler!(groups_js_handler, "../../../../web/static/groups.js");
css_handler!(
    local_dns_settings_css_handler,
    "../../../../web/static/local-dns-settings.css"
);
js_handler!(
    local_dns_settings_js_handler,
    "../../../../web/static/local-dns-settings.js"
);
css_handler!(settings_css_handler, "../../../../web/static/settings.css");
js_handler!(settings_js_handler, "../../../../web/static/settings.js");
css_handler!(
    dns_filter_css_handler,
    "../../../../web/static/dns-filter.css"
);
js_handler!(
    dns_filter_js_handler,
    "../../../../web/static/dns-filter.js"
);
css_handler!(
    block_services_css_handler,
    "../../../../web/static/block-services.css"
);
js_handler!(
    block_services_js_handler,
    "../../../../web/static/block-services.js"
);
css_handler!(login_css_handler, "../../../../web/static/login.css");
js_handler!(login_js_handler, "../../../../web/static/login.js");
