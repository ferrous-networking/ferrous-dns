use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use clap::Parser;
use ferrous_dns_api::AppState;
use ferrous_dns_domain::CliOverrides;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use ferrous_dns_jobs::{
    BlocklistSyncJob, ClientSyncJob, JobRunner, QueryLogRetentionJob, RetentionJob,
};
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    let pool = bootstrap::init_database(&database_url).await?;

    let config_arc = Arc::new(RwLock::new(config.clone()));

    let repos = di::Repositories::new(pool).await?;
    let dns_services = di::DnsServices::new(&config, &repos).await?;
    let use_cases = di::UseCases::new(&repos, dns_services.pool_manager.clone());

    JobRunner::new()
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
        .start()
        .await;

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
    };

    let dns_addr = format!("{}:{}", config.server.bind_address, config.server.dns_port);
    let dns_handler = DnsServerHandler::new(dns_services.handler_use_case);

    tokio::spawn(async move {
        if let Err(e) = server::start_dns_server(dns_addr, dns_handler).await {
            error!(error = %e, "DNS server error");
        }
    });

    let web_addr: SocketAddr = format!("{}:{}", config.server.bind_address, config.server.web_port)
        .parse()
        .expect("Invalid address");

    server::start_web_server(web_addr, app_state).await?;

    info!("Server shutdown complete");
    Ok(())
}
