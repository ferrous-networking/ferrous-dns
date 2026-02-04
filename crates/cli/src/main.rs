use axum::{response::Html, routing::get, Router};
use clap::Parser;
use ferrous_dns_api::{create_api_routes, state::AppState};
use ferrous_dns_application::use_cases::{
    handle_dns_query::HandleDnsQueryUseCase, GetBlocklistUseCase, GetQueryStatsUseCase,
    GetRecentQueriesUseCase,
};
use ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository;
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use ferrous_dns_infrastructure::{
    database::create_pool, dns::server::DnsServerHandler, dns::HickoryDnsResolver,
};
use hickory_server::ServerFuture;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tower_http::services::ServeDir;
use tracing::{error, info};

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

    // Load configuration (file + CLI overrides)
    let cli_overrides = ferrous_dns_domain::CliOverrides {
        dns_port: cli.dns_port,
        web_port: cli.web_port,
        bind_address: cli.bind.clone(),
        database_path: cli.database.clone(),
        log_level: cli.log_level.clone(),
    };

    let config = ferrous_dns_domain::Config::load(cli.config.as_deref(), cli_overrides)?;

    config.validate()?;

    // Initialize structured logging from config
    let log_level = config.logging.level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(false)
        .with_level(true)
        .with_max_level(log_level)
        .with_ansi(true)
        .init();

    info!("Starting Ferrous DNS Server v{}", env!("CARGO_PKG_VERSION"));
    info!(
        config_file = cli.config.as_deref().unwrap_or("default"),
        dns_port = config.server.dns_port,
        web_port = config.server.web_port,
        bind = %config.server.bind_address,
        "Configuration loaded"
    );

    // Initialize database from config
    let database_url = format!("sqlite:{}", config.database.path);
    info!("Initializing database: {}", config.database.path);

    let pool = match create_pool(&database_url).await {
        Ok(pool) => {
            info!("Database initialized successfully");
            pool
        }
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(e.into());
        }
    };

    // Dependency Injection - Create repositories
    let query_log_repo = Arc::new(SqliteQueryLogRepository::new(pool.clone()));
    let blocklist_repo = Arc::new(SqliteBlocklistRepository::new(pool.clone()));

    // Config já carregado do TOML acima, apenas logar
    info!(
        upstream_servers = config.dns.upstream_servers.len(),
        cache_enabled = config.dns.cache_enabled,
        blocklist_enabled = config.blocking.enabled,
        "DNS configuration"
    );

    // Create use cases
    let get_stats_use_case = Arc::new(GetQueryStatsUseCase::new(query_log_repo.clone()));
    let get_queries_use_case = Arc::new(GetRecentQueriesUseCase::new(query_log_repo.clone()));
    let get_blocklist_use_case = Arc::new(GetBlocklistUseCase::new(blocklist_repo.clone()));

    // Create DNS resolver with cache
    info!("Initializing DNS resolver with cache");
    
    let mut resolver = HickoryDnsResolver::with_google_dnssec(
        config.dns.dnssec_enabled,  // ← From config!
        Some(query_log_repo.clone()),  // ← For logging internal DNSSEC queries
    ).map_err(|e| {
        error!("Failed to create DNS resolver: {}", e);
        anyhow::anyhow!("DNS resolver initialization failed")
    })?;
    
    info!(
        dnssec_enabled = config.dns.dnssec_enabled,
        "DNS resolver created"
    );

    // Initialize cache if enabled
    let cache = if config.dns.cache_enabled {
        use ferrous_dns_infrastructure::dns::cache::{DnsCache, EvictionStrategy};
        
        // Detect eviction strategy from config (simple enum, no fields)
        let eviction_strategy = match config.dns.cache_eviction_strategy.as_str() {
            "lfu" => EvictionStrategy::LFU,
            "lfu-k" => EvictionStrategy::LFUK,
            _ => EvictionStrategy::HitRate,
        };

        info!(
            strategy = config.dns.cache_eviction_strategy.as_str(),
            max_entries = config.dns.cache_max_entries,
            optimistic_refresh = config.dns.cache_optimistic_refresh,
            adaptive_thresholds = config.dns.cache_adaptive_thresholds,
            "Cache enabled"
        );

        // Create cache with all 7 required parameters
        let cache = Arc::new(DnsCache::new(
            config.dns.cache_max_entries,                  // max_entries: usize
            eviction_strategy,                             // eviction_strategy: EvictionStrategy
            config.dns.cache_min_hit_rate,                 // min_threshold: f64
            config.dns.cache_refresh_threshold,            // refresh_threshold: f64
            config.dns.cache_lfuk_history_size,            // lfuk_history_size: usize
            config.dns.cache_batch_eviction_percentage,    // batch_eviction_percentage: f64
            config.dns.cache_adaptive_thresholds,          // adaptive_thresholds: bool
        ));

        // Attach SHARED cache to resolver (same instance for stats)
        resolver = resolver.with_cache_ref(cache.clone(), config.dns.cache_ttl);

        info!(
            cache_ttl = config.dns.cache_ttl,
            "Cache configured with shared reference"
        );

        cache
    } else {
        // Create empty cache for API even if caching disabled
        use ferrous_dns_infrastructure::dns::cache::{DnsCache, EvictionStrategy};
        Arc::new(DnsCache::new(0, EvictionStrategy::HitRate, 0.0, 0.0, 0, 0.0, false))
    };

    // Create app state with config and cache
    let app_state = AppState {
        get_stats: get_stats_use_case,
        get_queries: get_queries_use_case,
        get_blocklist: get_blocklist_use_case,
        config: Arc::new(tokio::sync::RwLock::new(config.clone())),
        cache: cache.clone(),
    };

    // Spawn background tasks if cache enabled and optimistic refresh enabled
    if config.dns.cache_enabled && config.dns.cache_optimistic_refresh {
        use ferrous_dns_infrastructure::dns::cache_updater::CacheUpdater;

        info!("Starting cache background tasks");

        // CacheUpdater needs Arc<HickoryDnsResolver>
        // Use the SAME cache instance
        let resolver_for_updater = HickoryDnsResolver::with_google_dnssec(false, None)
            .map_err(|e| anyhow::anyhow!("Failed to create resolver for updater: {}", e))?
            .with_cache_ref(cache.clone(), config.dns.cache_ttl);

        let updater = CacheUpdater::new(
            cache.clone(),
            Arc::new(resolver_for_updater),
            Some(query_log_repo.clone()),  // Pass query_log for logging refreshes
            60,  // update_interval_secs (optimistic refresh every 60s)
            config.dns.cache_compaction_interval,  // compaction_interval_secs
        );

        // Start both tasks
        let (_refresh_handle, _compaction_handle) = updater.start();
        
        info!("Cache background tasks started successfully");
    }

    let resolver = Arc::new(resolver);

    // Create DNS query handler use case
    let dns_handler_use_case = Arc::new(HandleDnsQueryUseCase::new(
        resolver.clone(),
        blocklist_repo.clone(),
        query_log_repo.clone(),
    ));

    // Start DNS server
    let dns_addr = format!("{}:{}", config.server.bind_address, config.server.dns_port);
    let dns_handler = DnsServerHandler::new(dns_handler_use_case);

    tokio::spawn(async move {
        if let Err(e) = start_dns_server(dns_addr, dns_handler).await {
            error!(error = %e, "DNS server error");
        }
    });

    // Start web server
    let web_addr: SocketAddr = format!("{}:{}", config.server.bind_address, config.server.web_port)
        .parse()
        .expect("Invalid address");

    info!(
        bind_address = %web_addr,
        dashboard_url = format!("http://{}", web_addr),
        api_url = format!("http://{}/api", web_addr),
        "Starting web server"
    );

    let app = create_app(app_state);
    let listener = tokio::net::TcpListener::bind(&web_addr).await?;

    info!("Server started successfully");

    axum::serve(listener, app).await.map_err(|e| {
        error!("Web server error: {}", e);
        e
    })?;

    info!("Server shutdown complete");

    Ok(())
}

/// Start DNS server on UDP and TCP
async fn start_dns_server(bind_addr: String, handler: DnsServerHandler) -> anyhow::Result<()> {
    let socket_addr = SocketAddr::from_str(&bind_addr)?;

    info!(
        bind_address = %socket_addr,
        "Starting DNS server"
    );

    // Create UDP socket
    let udp_socket = UdpSocket::bind(socket_addr).await?;
    info!(protocol = "UDP", "DNS server listening");

    // Create TCP listener
    let tcp_listener = TcpListener::bind(socket_addr).await?;
    info!(protocol = "TCP", "DNS server listening");

    // Start server
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp_socket);
    server.register_listener(tcp_listener, std::time::Duration::from_secs(10));

    info!("DNS server ready to accept queries");

    server.block_until_done().await?;

    Ok(())
}

fn create_app(state: AppState) -> Router {
    Router::new()
        .nest("/api", create_api_routes(state))
        .nest_service("/static", ServeDir::new("web/static"))
        .route("/", get(index_handler))
        .route("/dashboard.html", get(dashboard_handler))
        .route("/queries.html", get(queries_handler))
        .route("/settings.html", get(settings_handler))
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../../../web/static/index.html"))
}

async fn dashboard_handler() -> Html<&'static str> {
    Html(include_str!("../../../web/static/dashboard.html"))
}

async fn queries_handler() -> Html<&'static str> {
    Html(include_str!("../../../web/static/queries.html"))
}

async fn settings_handler() -> Html<&'static str> {
    Html(include_str!("../../../web/static/settings.html"))
}
