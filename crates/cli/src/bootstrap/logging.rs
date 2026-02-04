use ferrous_dns_domain::Config;
use tracing::info;

pub fn init_logging(config: &Config) {
    let log_level = config.logging.level.parse().unwrap_or(tracing::Level::INFO);

    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(false)
        .with_level(true)
        .with_max_level(log_level)
        .with_ansi(true)
        .init();

    info!("Logging initialized at level: {}", config.logging.level);
}
