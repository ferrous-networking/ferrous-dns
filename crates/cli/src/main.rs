use clap::Parser;
use ferrous_dns_api::AppState;
use ferrous_dns_domain::CliOverrides;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

mod bootstrap;
mod di;
mod server;

#[derive(Parser)]
#[command(name = "ferrous-dns")]
#[command(version = "0.1.0")]
#[command(about = "Ferrous DNS - High-performance DNS server with ad-blocking")]
struct Cli {
    /// Configuration file path
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<String>,

    /// DNS server port
    #[arg(short = 'd', long)]
    dns_port: Option<u16>,

    /// Web server port
    #[arg(short = 'w', long)]
    web_port: Option<u16>,

    /// Bind address
    #[arg(short = 'b', long)]
    bind: Option<String>,

    /// Database path
    #[arg(long)]
    database: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let cli_overrides = CliOverrides {
        dns_port: cli.dns_port,
        web_port: cli.web_port,
        bind_address: cli.bind.clone(),
        database_path: cli.database.clone(),
        log_level: cli.log_level.clone(),
    };

    let config = bootstrap::load_config(cli.config.as_deref(), cli_overrides)?;

    // Initialize logging
    bootstrap::init_logging(&config);

    info!("Starting Ferrous DNS Server v{}", env!("CARGO_PKG_VERSION"));

    // Initialize database
    let database_url = format!("sqlite:{}", config.database.path);
    let pool = bootstrap::init_database(&database_url).await?;

    // Wrap config in Arc<RwLock> for sharing
    let config_arc = Arc::new(RwLock::new(config.clone()));

    // Dependency Injection - Build all dependencies
    let repos = di::Repositories::new(pool).await?;
    let dns_services = di::DnsServices::new(&config, &repos).await?;
    let use_cases = di::UseCases::new(
        &repos,
        config_arc.clone(),
        dns_services.pool_manager.clone(),
    );

    // Start background jobs for client tracking
    info!("Starting client tracking background jobs");
    let client_sync_job = Arc::new(ferrous_dns_infrastructure::jobs::ClientSyncJob::new(
        use_cases.sync_arp.clone(),
        use_cases.sync_hostnames.clone(),
    ));
    client_sync_job.start().await;

    let retention_job = Arc::new(ferrous_dns_infrastructure::jobs::RetentionJob::new(
        use_cases.cleanup_clients.clone(),
        30, // 30 days retention
    ));
    retention_job.start().await;
    info!("Client tracking background jobs started");

    // Create AppState for web server
    let app_state = AppState {
        get_stats: use_cases.get_stats,
        get_queries: use_cases.get_queries,
        get_blocklist: use_cases.get_blocklist,
        get_clients: use_cases.get_clients,
        config: config_arc,
        cache: dns_services.cache.clone(),
        dns_resolver: dns_services.resolver.clone(),
    };

    // Start DNS server in background
    let dns_addr = format!("{}:{}", config.server.bind_address, config.server.dns_port);
    let dns_handler = DnsServerHandler::new(dns_services.handler_use_case);

    tokio::spawn(async move {
        if let Err(e) = server::start_dns_server(dns_addr, dns_handler).await {
            error!(error = %e, "DNS server error");
        }
    });

    // Start web server (blocking)
    let web_addr: SocketAddr = format!("{}:{}", config.server.bind_address, config.server.web_port)
        .parse()
        .expect("Invalid address");

    server::start_web_server(web_addr, app_state).await?;

    info!("Server shutdown complete");
    Ok(())
}
