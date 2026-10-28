use ferrous_dns_domain::Config;
use tracing::{info, warn};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*, reload, Registry};

pub type LogLevelHandle = reload::Handle<LevelFilter, Registry>;

/// Installs the subscriber at `initial` (INFO for the server) so warnings raised
/// while the config file is read (legacy values rewritten at load) are not
/// lost; [`apply_log_level`] switches to the configured level afterwards.
pub fn init_logging(initial: LevelFilter) -> LogLevelHandle {
    let (level, handle) = reload::Layer::new(initial);
    tracing_subscriber::registry()
        .with(level)
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_level(true)
                .with_ansi(true),
        )
        .init();
    handle
}

pub fn apply_log_level(handle: &LogLevelHandle, config: &Config) {
    let level = config.logging.level.parse().unwrap_or(tracing::Level::INFO);
    if let Err(e) = handle.reload(LevelFilter::from_level(level)) {
        warn!(error = %e, "Failed to apply the configured log level");
    }
    info!("Logging initialized at level: {}", config.logging.level);
}
