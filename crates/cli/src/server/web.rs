use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use ferrous_dns_api::{create_api_router_with_openapi, metrics_routes, AppState};
use ferrous_dns_api_pihole::{create_pihole_router_with_openapi, PiholeAppState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tracing::info;
use utoipa::openapi::OpenApi;
use utoipa_scalar::{Scalar, Servable};

use super::doh::{dns_query_handler, DohContext};
use super::web_tls;

pub async fn start_doh_server(bind_addr: SocketAddr, doh: Arc<DohContext>) -> anyhow::Result<()> {
    info!(
        bind_address = %bind_addr,
        endpoint = format!("http://{}/dns-query", bind_addr),
        "Starting DoH server (DNS-over-HTTPS, RFC 8484)"
    );

    let listener = TcpListener::bind(&bind_addr).await?;

    info!("DoH server ready on {}", bind_addr);

    serve_doh(listener, doh).await
}

/// Serves the dedicated plain-HTTP DoH endpoint on an already bound listener.
pub async fn serve_doh(listener: TcpListener, doh: Arc<DohContext>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/dns-query", get(dns_query_handler).post(dns_query_handler))
        .layer(axum::Extension(doh));

    // The handler attributes each query to the socket peer.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

pub async fn start_web_server(
    bind_addr: SocketAddr,
    ferrous_state: AppState,
    pihole_state: Option<PiholeAppState>,
    cors_allowed_origins: &[String],
    metrics_enabled: bool,
    doh: Option<Arc<DohContext>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> anyhow::Result<()> {
    let scheme = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };

    if pihole_state.is_some() {
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
        metrics_enabled,
        doh,
    );

    if let Some(tls_cfg) = tls_config {
        info!("Web server started successfully (HTTPS)");
        web_tls::start_https_web_server(bind_addr, app, tls_cfg).await?;
    } else {
        let listener = TcpListener::bind(&bind_addr).await?;
        info!("Web server started successfully");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
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

/// An API's routes plus its `/openapi.json` spec and Scalar UI at `/docs`.
fn api_branch(router: Router, spec: OpenApi) -> Router {
    let json = spec.clone();
    Router::new()
        .route(
            "/openapi.json",
            get(move || {
                let json = json.clone();
                async move { Json(json) }
            }),
        )
        .merge(Router::from(Scalar::with_url("/docs", spec)))
        .merge(router)
}

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JS: &str = "application/javascript; charset=utf-8";
const SVG: &str = "image/svg+xml; charset=utf-8";
const WOFF2: &str = "font/woff2";

/// Mounts files embedded from `web/static`, one `url => (file, content type)`
/// row each, so a route cannot drift from the file it serves.
macro_rules! static_files {
    ($router:expr, { $($url:literal => ($file:literal, $mime:expr)),* $(,)? }) => {
        $router$(
            .route(
                $url,
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, $mime)],
                        include_str!(concat!("../../../../web/static/", $file)),
                    )
                }),
            )
        )*
    };
}

/// The third-party files in `web/static/vendor`, one `file => content type`
/// row each, embedded so the UI never needs internet access (#271).
macro_rules! vendor_files {
    ($($file:literal => $mime:expr),* $(,)?) => {
        &[$((
            $file,
            include_bytes!(concat!("../../../../web/static/vendor/", $file)),
            $mime,
        )),*]
    };
}

const VENDOR_FILES: &[(&str, &[u8], &str)] = vendor_files![
    "alpinejs-3.13.5.min.js" => JS,
    "chart.js-4.4.1.umd.js" => JS,
    "lucide-0.469.0.min.js" => JS,
    "scalar-api-reference-1.73.1.standalone.js" => JS,
    "tailwind-preflight-3.4.17.css" => CSS,
    "inter-v20/inter.css" => CSS,
    "inter-v20/inter-cyrillic-ext.woff2" => WOFF2,
    "inter-v20/inter-cyrillic.woff2" => WOFF2,
    "inter-v20/inter-greek-ext.woff2" => WOFF2,
    "inter-v20/inter-greek.woff2" => WOFF2,
    "inter-v20/inter-latin-ext.woff2" => WOFF2,
    "inter-v20/inter-latin.woff2" => WOFF2,
    "inter-v20/inter-vietnamese.woff2" => WOFF2,
];

const VENDOR_ROUTE: &str = "/static/vendor/{*file}";

/// Every vendored file name carries its upstream version, so a browser can
/// keep it for good instead of re-downloading it on each page.
async fn vendor_file_handler(Path(file): Path<String>) -> Response {
    match VENDOR_FILES.iter().find(|(name, _, _)| *name == file) {
        Some((_, body, mime)) => (
            [
                (header::CONTENT_TYPE, *mime),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            *body,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The web app. The Pi-hole API, when `pihole_state` is given, takes `/api`
/// and moves the Ferrous API to `/ferrous/api`.
fn create_app(
    ferrous_state: AppState,
    pihole_state: Option<PiholeAppState>,
    cors_allowed_origins: &[String],
    metrics_enabled: bool,
    doh: Option<Arc<DohContext>>,
) -> Router {
    let pihole_compat = pihole_state.is_some();
    // Clone before the state is moved into the API router so the bare
    // `/metrics` route can carry its own copy.
    let metrics_state = metrics_enabled.then(|| ferrous_state.clone());
    let (ferrous_router, ferrous_openapi) = create_api_router_with_openapi(ferrous_state);
    let ferrous_branch = api_branch(ferrous_router, ferrous_openapi);

    let router = match pihole_state {
        Some(state) => {
            let (pihole_router, pihole_openapi) = create_pihole_router_with_openapi(state);
            Router::new()
                .nest("/api", api_branch(pihole_router, pihole_openapi))
                .nest("/ferrous/api", ferrous_branch)
        }
        None => Router::new().nest("/api", ferrous_branch),
    };

    let router = router.route(
        "/ferrous-config.js",
        get(ferrous_config_js_handler).with_state(pihole_compat),
    );
    let mut app = static_files!(router, {
        "/static/shared.css" => ("shared.css", CSS),
        "/static/shared.js" => ("shared.js", JS),
        "/static/logo.svg" => ("logo.svg", SVG),
        "/static/dashboard.css" => ("dashboard.css", CSS),
        "/static/dashboard.js" => ("dashboard.js", JS),
        "/static/queries.css" => ("queries.css", CSS),
        "/static/queries.js" => ("queries.js", JS),
        "/static/cache-control.css" => ("cache-control.css", CSS),
        "/static/cache-control.js" => ("cache-control.js", JS),
        "/static/dnssec.css" => ("dnssec.css", CSS),
        "/static/dnssec.js" => ("dnssec.js", JS),
        "/static/clients.css" => ("clients.css", CSS),
        "/static/clients.js" => ("clients.js", JS),
        "/static/groups.css" => ("groups.css", CSS),
        "/static/groups.js" => ("groups.js", JS),
        "/static/local-dns-settings.css" => ("local-dns-settings.css", CSS),
        "/static/local-dns-settings.js" => ("local-dns-settings.js", JS),
        "/static/settings.css" => ("settings.css", CSS),
        "/static/settings.js" => ("settings.js", JS),
        "/static/dns-filter.css" => ("dns-filter.css", CSS),
        "/static/dns-filter.js" => ("dns-filter.js", JS),
        "/static/block-services.css" => ("block-services.css", CSS),
        "/static/block-services.js" => ("block-services.js", JS),
        "/static/login.css" => ("login.css", CSS),
        "/static/login.js" => ("login.js", JS),
        "/" => ("index.html", HTML),
        "/login.html" => ("login.html", HTML),
        "/dashboard.html" => ("dashboard.html", HTML),
        "/queries.html" => ("queries.html", HTML),
        "/cache-control.html" => ("cache-control.html", HTML),
        "/dnssec.html" => ("dnssec.html", HTML),
        "/clients.html" => ("clients.html", HTML),
        "/groups.html" => ("groups.html", HTML),
        "/local-dns-settings.html" => ("local-dns-settings.html", HTML),
        "/settings.html" => ("settings.html", HTML),
        "/dns-filter.html" => ("dns-filter.html", HTML),
        "/block-services.html" => ("block-services.html", HTML),
    })
    .route(VENDOR_ROUTE, get(vendor_file_handler))
    .layer(CompressionLayer::new().gzip(true))
    .layer(build_cors_layer(cors_allowed_origins));

    // Bare unauthenticated `/metrics`, mounted outside the `/api` nest (and thus
    // outside the auth layer) per the Prometheus scrape convention.
    if let Some(state) = metrics_state {
        app = app.merge(metrics_routes(state));
    }

    if let Some(doh) = doh {
        app = app
            .route("/dns-query", get(dns_query_handler).post(dns_query_handler))
            .layer(axum::Extension(doh));
    }

    app
}

/// Returns a small JS snippet that sets `window.FERROUS_API_BASE` and
/// `window.FERROUS_VERSION` at runtime.
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
    let version = env!("CARGO_PKG_VERSION");
    let body =
        format!(r#"window.FERROUS_API_BASE = "{api_base}";window.FERROUS_VERSION = "{version}";"#);
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::path::Path as FsPath;
    use tower::ServiceExt;

    fn vendor_request(file: &str) -> Request<Body> {
        Request::get(format!("/static/vendor/{file}"))
            .body(Body::empty())
            .unwrap()
    }

    fn files_under(dir: &FsPath, root: &FsPath, files: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_under(&path, root, files);
            } else {
                let relative = path.strip_prefix(root).unwrap();
                files.push(relative.to_str().unwrap().replace('\\', "/"));
            }
        }
    }

    #[test]
    fn test_vendor_files_match_the_vendor_directory() {
        let root = FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../../web/static/vendor");
        let mut on_disk = Vec::new();
        files_under(&root, &root, &mut on_disk);
        on_disk.retain(|file| file != "README.md" && !file.starts_with("LICENSES/"));
        on_disk.sort();

        let mut served: Vec<String> = VENDOR_FILES
            .iter()
            .map(|(name, _, _)| name.to_string())
            .collect();
        served.sort();

        assert_eq!(
            served, on_disk,
            "VENDOR_FILES and web/static/vendor list different files"
        );
    }

    #[tokio::test]
    async fn test_vendor_file_is_served_with_its_type_and_immutable_cache() {
        let router = Router::new().route(VENDOR_ROUTE, get(vendor_file_handler));

        let response = router
            .oneshot(vendor_request("inter-v20/inter-latin.woff2"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], WOFF2);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
    }

    #[tokio::test]
    async fn test_vendor_file_unknown_name_is_not_found() {
        let router = Router::new().route(VENDOR_ROUTE, get(vendor_file_handler));

        let response = router
            .oneshot(vendor_request("alpinejs-0.0.0.min.js"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_api_docs_load_scalar_from_the_binary() {
        let response = api_branch(Router::new(), OpenApi::default())
            .oneshot(Request::get("/docs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !html.contains(r#"src="http"#) && !html.contains(r#"href="http"#),
            "the API docs page fetches from a third-party host:\n{html}"
        );
        assert!(html.contains(r#"src="/static/vendor/scalar-api-reference-"#));
    }
}
