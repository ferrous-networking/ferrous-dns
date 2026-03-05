use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::Parser;
use ferrous_dns_domain::CliOverrides;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

mod args;
mod bootstrap;
mod server;
mod wiring;

fn main() -> anyhow::Result<()> {
    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let num_workers = core_ids.len().max(1);
    let core_ids = Arc::new(core_ids);
    let counter = Arc::new(AtomicUsize::new(0));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_workers)
        .thread_name("ferrous-dns-worker")
        .on_thread_start({
            let core_ids = core_ids.clone();
            let counter = counter.clone();
            move || {
                if !core_ids.is_empty() {
                    let idx = counter.fetch_add(1, Ordering::Relaxed) % core_ids.len();
                    core_affinity::set_for_current(core_ids[idx]);
                }
            }
        })
        .enable_all()
        .max_blocking_threads(16)
        .build()
        .expect("Failed to build tokio runtime");

    runtime.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = args::Cli::parse();

    let cli_overrides = CliOverrides {
        dns_port: cli.dns_port,
        web_port: cli.web_port,
        bind_address: cli.bind.clone(),
        database_path: cli.database.clone(),
        log_level: cli.log_level.clone(),
    };

    let config = bootstrap::load_config(cli.config.as_deref(), cli_overrides)?;

    bootstrap::init_logging(&config);

    info!("Starting Ferrous DNS Server v{}", env!("CARGO_PKG_VERSION"));

    ferrous_dns_infrastructure::dns::cache::coarse_clock::start_clock_ticker();

    let database_url = format!("sqlite:{}", config.database.path);
    let (write_pool, query_log_pool, read_pool) =
        bootstrap::init_database(&database_url, &config.database).await?;

    let config_arc = Arc::new(RwLock::new(config.clone()));
    let wal_pool = write_pool.clone();
    let config_repo_pool = wal_pool.clone();

    let repos =
        wiring::Repositories::new(write_pool, query_log_pool, read_pool, &config.database).await?;
    let dns_services = wiring::DnsServices::new(&config, &repos).await?;
    let use_cases = wiring::UseCases::new(
        &repos,
        dns_services.pool_manager.clone(),
        config.dns.local_dns_server.clone(),
    );

    let runner = bootstrap::build_job_runner(
        &use_cases,
        &repos,
        &config,
        wal_pool,
        dns_services.cache_maintenance.clone(),
    );

    runner.start().await;

    info!("Loading subnet matcher cache");
    if let Err(e) = use_cases.subnet_matcher.refresh().await {
        error!(error = %e, "Failed to load subnet matcher cache");
    }
    info!("Subnet matcher cache loaded");

    let api_key = config.server.api_key.as_deref().map(Arc::from);
    let app_state = wiring::build_app_state(
        use_cases,
        &dns_services,
        config_arc,
        config_repo_pool,
        api_key,
    );

    let dns_addr = format!("{}:{}", config.server.bind_address, config.server.dns_port);
    let dns_handler = DnsServerHandler::new(dns_services.handler_use_case);
    let num_dns_workers = core_affinity::get_core_ids()
        .map(|ids| ids.len())
        .unwrap_or(1)
        .max(1);

    tokio::spawn(async move {
        if let Err(e) = server::start_dns_server(dns_addr, dns_handler, num_dns_workers).await {
            error!(error = %e, "DNS server error");
        }
    });

    let web_addr: SocketAddr = format!("{}:{}", config.server.bind_address, config.server.web_port)
        .parse()
        .expect("Invalid address");

    server::start_web_server(web_addr, app_state, &config.server.cors_allowed_origins).await?;

    info!("Server shutdown complete");
    Ok(())
}
