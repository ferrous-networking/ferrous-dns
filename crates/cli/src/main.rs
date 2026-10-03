use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use anyhow::Context;
use clap::Parser;
use ferrous_dns_application::drop_counter::ShedCounters;
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

mod args;
mod bootstrap;
mod wiring;
use ferrous_dns::server;

fn main() -> anyhow::Result<()> {
    ferrous_dns::install_crypto_provider();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name("ferrous-dns-worker")
        .enable_all()
        .max_blocking_threads(16)
        .build()
        .context("Failed to build tokio runtime")?;

    runtime.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = args::Cli::parse();
    let log_level = bootstrap::init_logging();

    let config_path = bootstrap::resolve_config_path(cli.config.as_deref());
    let overrides = bootstrap::config_overrides(&cli);
    let config = bootstrap::load_config(config_path.as_deref(), &overrides)?;

    bootstrap::apply_log_level(&log_level, &config);

    info!("Starting Ferrous DNS Server v{}", env!("CARGO_PKG_VERSION"));

    ferrous_dns_infrastructure::dns::cache::coarse_clock::start_clock_ticker();

    let database_url = format!("sqlite:{}", config.database.path);
    let (write_pool, query_log_pool, read_pool) =
        bootstrap::init_database(&database_url, &config.database).await?;

    let config_arc = Arc::new(RwLock::new(config.clone()));
    let wal_pool = write_pool.clone();

    let shed = ShedCounters::default();
    let repos = wiring::Repositories::new(
        write_pool,
        query_log_pool,
        read_pool,
        &config.database,
        config.blocking.enabled,
        shed.query_log.clone(),
    )
    .await?;
    let dns_services = wiring::DnsServices::new(&config, &repos, shed.upstream.clone()).await?;
    let use_cases = wiring::UseCases::new(
        &repos,
        dns_services.pool_manager.clone(),
        dns_services.local_dns_server,
    );

    bootstrap::spawn_jobs(
        &use_cases,
        &repos,
        &config,
        wal_pool,
        dns_services.cache_maintenance.clone(),
    );

    let effective_config_path: Option<Arc<str>> = config_path.as_deref().map(Arc::from);
    let config_services = wiring::app_state::build_config_services(
        &dns_services,
        config_arc.clone(),
        effective_config_path.clone(),
        overrides,
    );

    let auth =
        wiring::build_auth_services(&repos, config_arc.clone(), effective_config_path.as_deref())
            .await;

    let pihole_state = config.server.pihole_compat.then(|| {
        wiring::build_pihole_state(
            &use_cases,
            &auth,
            repos.block_filter_engine.clone(),
            config_arc.clone(),
            config_services.reload.clone(),
        )
    });

    // The session cookie's `Secure` flag must follow the transport actually in
    // use, so the web TLS material is loaded before the state is built: with
    // `enabled = true` and no certificate on disk the server falls back to
    // plain HTTP, and a `Secure` cookie would then be dropped by the browser.
    let web_tls_config = if config.server.web_tls.enabled {
        server::load_server_tls_config(
            &config.server.web_tls.tls_cert_path,
            &config.server.web_tls.tls_key_path,
            "Web HTTPS",
            &[],
        )?
    } else {
        None
    };

    let udp_fallback_shed = shed.udp_fallback.clone();
    let app_state = wiring::build_app_state(
        use_cases,
        auth.use_cases,
        &repos,
        &dns_services,
        &config_services,
        shed,
        web_tls_config.is_some(),
    )
    .await;

    let dns_addr = config.server.dns_listen_address();
    let handler_use_case = dns_services.handler_use_case;
    let tcp_conn_limiter = dns_services.tcp_conn_limiter;
    let dot_conn_limiter = dns_services.dot_conn_limiter;
    let doq_conn_limiter = dns_services.doq_conn_limiter;
    let block_policy = BlockPolicy {
        mode: config.blocking.block_mode,
        ttl: config.blocking.block_ttl,
        sinkhole_ipv4: config.blocking.sinkhole_ipv4,
        sinkhole_ipv6: config.blocking.sinkhole_ipv6,
    };
    let dns_handler = DnsServerHandler::new(handler_use_case.clone(), block_policy);
    let num_dns_workers = tokio::runtime::Handle::current().metrics().num_workers();

    let proxy_protocol_enabled = config.server.proxy_protocol_enabled;
    tokio::spawn(async move {
        if let Err(e) = server::start_dns_server(
            dns_addr,
            dns_handler,
            num_dns_workers,
            proxy_protocol_enabled,
            tcp_conn_limiter,
            udp_fallback_shed,
        )
        .await
        {
            error!(error = %e, "DNS server error");
        }
    });

    if config.dns.mdns_enabled {
        tokio::spawn(server::start_mdns_listener());
    }

    if config.server.encrypted_dns.dot_enabled {
        let dot_tls_config = server::load_server_tls_config(
            &config.server.encrypted_dns.tls_cert_path,
            &config.server.encrypted_dns.tls_key_path,
            "DoT",
            &[],
        )?;
        if let Some(tls_cfg) = dot_tls_config {
            let dot_addr = config.server.dot_listen_address();
            let dot_handler = Arc::new(DnsServerHandler::new(
                handler_use_case.clone(),
                block_policy,
            ));
            tokio::spawn(async move {
                if let Err(e) = server::start_dot_server(
                    dot_addr,
                    dot_handler,
                    tls_cfg,
                    num_dns_workers,
                    proxy_protocol_enabled,
                    dot_conn_limiter,
                )
                .await
                {
                    error!(error = %e, "DoT server error");
                }
            });
        }
    }

    if config.server.encrypted_dns.doq_enabled {
        let doq_tls_config = server::load_server_tls_config(
            &config.server.encrypted_dns.tls_cert_path,
            &config.server.encrypted_dns.tls_key_path,
            "DoQ",
            &[b"doq"],
        )?;
        if let Some(tls_cfg) = doq_tls_config {
            let doq_addr = config.server.doq_listen_address();
            let doq_handler = Arc::new(DnsServerHandler::new(
                handler_use_case.clone(),
                block_policy,
            ));
            tokio::spawn(async move {
                if let Err(e) =
                    server::start_doq_server(doq_addr, doq_handler, tls_cfg, doq_conn_limiter).await
                {
                    error!(error = %e, "DoQ server error");
                }
            });
        }
    }

    // DoH is plain HTTP here (TLS is terminated in front of it, or by the web
    // listener), so unlike DoT and DoQ it needs no certificate.
    let doh = config.server.encrypted_dns.doh_enabled.then(|| {
        Arc::new(server::DohContext {
            handler: Arc::new(DnsServerHandler::new(handler_use_case, block_policy)),
            trusted_proxies: config.server.trusted_proxies.clone(),
        })
    });
    let web_doh = match (doh, config.server.doh_listen_address()) {
        (Some(doh), Some(doh_addr)) => {
            tokio::spawn(async move {
                if let Err(e) = server::start_doh_server(doh_addr, doh).await {
                    error!(error = %e, "DoH server error");
                }
            });
            None
        }
        (doh, _) => doh,
    };

    let web_addr = config.server.web_listen_address();

    server::start_web_server(
        web_addr,
        app_state,
        pihole_state,
        &config.server.cors_allowed_origins,
        config.server.metrics_enabled,
        web_doh,
        web_tls_config,
    )
    .await?;

    info!("Server shutdown complete");
    Ok(())
}
