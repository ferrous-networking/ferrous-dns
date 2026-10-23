use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::load_balancer::{run_hostname_refresh, HostnameRefreshTimes};
use ferrous_dns_infrastructure::dns::transport::resolver::UpstreamHostResolver;
use ferrous_dns_infrastructure::dns::{HealthChecker, PoolManager};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Longest wait between two retries of an upstream hostname that keeps failing.
const MAX_HOSTNAME_RETRY_DELAY: Duration = Duration::from_secs(300);
/// The bounds an upstream hostname's answer TTL is held to.
const MIN_HOSTNAME_TTL: Duration = Duration::from_secs(60);
const MAX_HOSTNAME_TTL: Duration = Duration::from_secs(3600);
/// How long a system resolver answer, which has no TTL, is kept.
const HOSTNAME_TTL_UNKNOWN: Duration = Duration::from_secs(300);

pub(super) fn setup_health_checker(config: &Config) -> Arc<HealthChecker> {
    let checker = Arc::new(HealthChecker::new(
        config.dns.health_check.failure_threshold,
        config.dns.health_check.success_threshold,
    ));
    info!(
        interval_seconds = config.dns.health_check.interval,
        timeout_ms = config.dns.health_check.timeout,
        "Health checker enabled"
    );
    checker
}

/// Anti-spoofing hardening for upstream A/AAAA queries. DNS Cookies are always
/// on (graceful); 0x20 case randomization follows the config flag.
fn hardening_opts(config: &Config) -> HardeningOpts {
    HardeningOpts {
        cookie: true,
        qname_0x20: config.dns.qname_case_randomization,
    }
}

/// `local_dns_server` is asked first for upstream hostnames, so they resolve
/// even when this machine resolves through Ferrous DNS itself.
pub(super) async fn setup_pool_manager(
    config: &Config,
    health_checker: &Arc<HealthChecker>,
    local_dns_server: Option<SocketAddr>,
) -> anyhow::Result<Arc<PoolManager>> {
    let host_resolver = UpstreamHostResolver::new(local_dns_server, hardening_opts(config));
    Ok(Arc::new(
        PoolManager::with_host_resolver(
            config.dns.pools.clone(),
            Some(Arc::clone(health_checker)),
            host_resolver,
        )
        .await?
        .with_hardening(hardening_opts(config)),
    ))
}

/// Looks each upstream hostname up again when its answer's TTL runs out. A
/// lookup that fails — at startup, on a pool save or later — is retried from
/// the health-check interval, doubling up to five minutes while it keeps
/// failing. Holds a weak ref, like the probe loop.
pub(super) fn start_hostname_refresh_task(pool_manager: &Arc<PoolManager>, config: &Config) {
    let retry = Duration::from_secs(config.dns.health_check.interval);
    let times = HostnameRefreshTimes {
        min_ttl: MIN_HOSTNAME_TTL,
        max_ttl: MAX_HOSTNAME_TTL,
        without_ttl: HOSTNAME_TTL_UNKNOWN,
        retry,
        max_retry: MAX_HOSTNAME_RETRY_DELAY.max(retry),
    };
    tokio::spawn(run_hostname_refresh(Arc::downgrade(pool_manager), times));
}

pub(super) fn start_health_checker_task(
    checker: Arc<HealthChecker>,
    pool_manager: &Arc<PoolManager>,
    config: &Config,
) {
    // Weak ref so the probe loop reads the live pool set each tick (picking up
    // hot reloads) without forming an Arc cycle with the PoolManager.
    let pm_weak = Arc::downgrade(pool_manager);
    let interval = config.dns.health_check.interval;
    let timeout = config.dns.health_check.timeout;
    tokio::spawn(async move {
        checker
            .run_probes(
                move || {
                    pm_weak
                        .upgrade()
                        .map(|pm| pm.get_health_probes())
                        .unwrap_or_default()
                },
                interval,
                timeout,
            )
            .await;
    });
    info!("Health checker background task started");
}
