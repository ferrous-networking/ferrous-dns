use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::Parser;
use ferrous_dns_api::AppState;
use ferrous_dns_domain::CliOverrides;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use ferrous_dns_jobs::{
    BlocklistSyncJob, CacheMaintenanceJob, ClientSyncJob, JobRunner, QueryLogRetentionJob,
    RetentionJob, WalCheckpointJob,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<String>,

    #[arg(short = 'd', long)]
    dns_port: Option<u16>,

    #[arg(short = 'w', long)]
    web_port: Option<u16>,

    #[arg(short = 'b', long)]
    bind: Option<String>,

    #[arg(long)]
    database: Option<String>,

    #[arg(long)]
    log_level: Option<String>,
}

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
    let cli = Cli::parse();

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

    let database_url = format!("sqlite:{}", config.database.path);
    let (write_pool, read_pool) = bootstrap::init_database(&database_url, &config.database).await?;

    let config_arc = Arc::new(RwLock::new(config.clone()));
    let wal_pool = write_pool.clone();

    let repos = di::Repositories::new(write_pool, read_pool, &config.database).await?;
    let dns_services = di::DnsServices::new(&config, &repos).await?;
    let use_cases = di::UseCases::new(
        &repos,
        dns_services.pool_manager.clone(),
        config.dns.local_dns_server.clone(),
    );

    let mut runner = JobRunner::new()
        .with_client_sync(ClientSyncJob::new(
            use_cases.sync_arp.clone(),
            use_cases.sync_hostnames.clone(),
        ))
        .with_retention(RetentionJob::new(use_cases.cleanup_clients.clone(), 30))
        .with_query_log_retention(QueryLogRetentionJob::new(
            use_cases.cleanup_query_logs.clone(),
            config.database.queries_log_stored,
        ))
        .with_blocklist_sync(BlocklistSyncJob::new(repos.block_filter_engine.clone()))
        .with_wal_checkpoint(WalCheckpointJob::new(
            wal_pool,
            config.database.wal_checkpoint_interval_secs,
        ));

    if let Some(maintenance) = dns_services.cache_maintenance {
        runner = runner.with_cache_maintenance(
            CacheMaintenanceJob::new(maintenance)
                .with_intervals(60, config.dns.cache_compaction_interval),
        );
    }

    runner.start().await;

    info!("Loading subnet matcher cache");
    if let Err(e) = use_cases.subnet_matcher.refresh().await {
        error!(error = %e, "Failed to load subnet matcher cache");
    }
    info!("Subnet matcher cache loaded");

    let app_state = AppState {
        get_stats: use_cases.get_stats,
        get_queries: use_cases.get_queries,
        get_timeline: use_cases.get_timeline,
        get_query_rate: use_cases.get_query_rate,
        get_cache_stats: use_cases.get_cache_stats,
        get_blocklist: use_cases.get_blocklist,
        get_clients: use_cases.get_clients,
        get_groups: use_cases.get_groups,
        create_group: use_cases.create_group,
        update_group: use_cases.update_group,
        delete_group: use_cases.delete_group,
        assign_client_group: use_cases.assign_client_group,
        get_client_subnets: use_cases.get_client_subnets,
        create_client_subnet: use_cases.create_client_subnet,
        delete_client_subnet: use_cases.delete_client_subnet,
        create_manual_client: use_cases.create_manual_client,
        update_client: use_cases.update_client,
        delete_client: use_cases.delete_client,
        get_blocklist_sources: use_cases.get_blocklist_sources,
        create_blocklist_source: use_cases.create_blocklist_source,
        update_blocklist_source: use_cases.update_blocklist_source,
        delete_blocklist_source: use_cases.delete_blocklist_source,
        get_whitelist: use_cases.get_whitelist,
        get_whitelist_sources: use_cases.get_whitelist_sources,
        create_whitelist_source: use_cases.create_whitelist_source,
        update_whitelist_source: use_cases.update_whitelist_source,
        delete_whitelist_source: use_cases.delete_whitelist_source,
        get_block_filter_stats: use_cases.get_block_filter_stats,
        subnet_matcher: use_cases.subnet_matcher.clone(),
        config: config_arc,
        cache: dns_services.cache.clone(),
        dns_resolver: dns_services.resolver.clone(),
        get_managed_domains: use_cases.get_managed_domains,
        create_managed_domain: use_cases.create_managed_domain,
        update_managed_domain: use_cases.update_managed_domain,
        delete_managed_domain: use_cases.delete_managed_domain,
        get_regex_filters: use_cases.get_regex_filters,
        create_regex_filter: use_cases.create_regex_filter,
        update_regex_filter: use_cases.update_regex_filter,
        delete_regex_filter: use_cases.delete_regex_filter,
        get_service_catalog: use_cases.get_service_catalog,
        get_blocked_services: use_cases.get_blocked_services,
        block_service: use_cases.block_service,
        unblock_service: use_cases.unblock_service,
        create_custom_service: use_cases.create_custom_service,
        get_custom_services: use_cases.get_custom_services,
        update_custom_service: use_cases.update_custom_service,
        delete_custom_service: use_cases.delete_custom_service,
        api_key: config.server.api_key.as_deref().map(Arc::from),
    };

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
