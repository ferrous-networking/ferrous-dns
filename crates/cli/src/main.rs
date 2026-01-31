//! # Ferrous DNS Server
//!
//! Main entry point for the DNS server with integrated web UI

use axum::{response::Html, routing::get, Router};
use clap::Parser;
use std::net::SocketAddr;
use tower_http::services::ServeDir;

#[derive(Parser)]
#[command(name = "ferrous-dns")]
#[command(version = "0.1.0")]
#[command(about = "🦀 A blazingly fast DNS server with ad-blocking")]
struct Cli {
    /// DNS server port
    #[arg(short = 'd', long, default_value = "53")]
    dns_port: u16,

    /// Web server port
    #[arg(short = 'w', long, default_value = "8080")]
    web_port: u16,

    /// Bind address
    #[arg(short = 'b', long, default_value = "0.0.0.0")]
    bind: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();

    tracing::info!("🦀 Ferrous DNS Server Starting...");
    tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Start DNS server (async task)
    let dns_addr = format!("{}:{}", cli.bind, cli.dns_port);
    tokio::spawn(async move {
        tracing::info!("🌐 DNS Server: {}", dns_addr);
        tracing::info!("   Status: Ready to resolve queries");
        // TODO: Start actual DNS server here
    });

    // Start web server
    let web_addr: SocketAddr = format!("{}:{}", cli.bind, cli.web_port)
        .parse()
        .expect("Invalid address");

    tracing::info!("🌍 Web Server: http://{}", web_addr);
    tracing::info!("   Dashboard: http://{}", web_addr);
    tracing::info!("   API: http://{}/api", web_addr);
    tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let app = create_app();

    let listener = tokio::net::TcpListener::bind(&web_addr).await?;
    tracing::info!("✅ Server ready! Press Ctrl+C to stop");

    axum::serve(listener, app).await?;

    Ok(())
}

/// Creates the main application router
fn create_app() -> Router {
    Router::new()
        // API Routes
        .nest("/api", api_routes())
        // Static files (CSS, JS, images)
        .nest_service("/static", ServeDir::new("web/static"))
        // Root - serve index.html
        .route("/", get(index_handler))
}

/// API routes
fn api_routes() -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/stats", get(get_stats))
        .route("/queries", get(get_queries))
        .route("/blocklist", get(get_blocklist))
}

/// Handlers
async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../../../web/static/index.html"))
}

async fn health_check() -> &'static str {
    "OK"
}

async fn get_stats() -> &'static str {
    r#"{
        "queries_total": 1234,
        "queries_blocked": 567,
        "clients": 5,
        "uptime": 3600
    }"#
}

async fn get_queries() -> &'static str {
    r#"[
        {
            "timestamp": "2025-01-31T20:30:00Z",
            "domain": "example.com",
            "client": "192.168.1.100",
            "type": "A",
            "blocked": false
        }
    ]"#
}

async fn get_blocklist() -> &'static str {
    r#"[
        {
            "domain": "ads.example.com",
            "added_at": "2025-01-31T10:00:00Z"
        }
    ]"#
}
