use std::sync::Arc;

use ferrous_dns_domain::{BindAddress, Config, DomainError};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use tracing::{info, instrument, Instrument};

use crate::ports::{ConfigFilePersistence, UpstreamReloadPort};

/// Command-line settings that win over the config file, at startup and on
/// every reload.
#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    pub dns_port: Option<u16>,
    pub web_port: Option<u16>,
    pub bind_address: Option<BindAddress>,
    pub database_path: Option<String>,
    pub log_level: Option<String>,
}

impl ConfigOverrides {
    pub fn apply(&self, config: &mut Config) {
        if let Some(port) = self.dns_port {
            config.server.dns_port = port;
        }
        if let Some(port) = self.web_port {
            config.server.web_port = port;
        }
        if let Some(bind) = self.bind_address {
            config.server.bind_address = bind;
        }
        if let Some(path) = &self.database_path {
            config.database.path = path.clone();
        }
        if let Some(level) = &self.log_level {
            config.logging.level = level.clone();
        }
    }
}

/// Re-reads the config file into the running config, the way a restart
/// would load it: command-line overrides re-applied, upstream pools
/// hot-reloaded like an API save. Only exists when the server has a file.
pub struct ReloadConfigUseCase {
    config: Arc<RwLock<Config>>,
    config_writer: Arc<Mutex<()>>,
    config_file_persistence: Arc<dyn ConfigFilePersistence>,
    config_path: Arc<str>,
    upstream: Arc<dyn UpstreamReloadPort>,
    overrides: ConfigOverrides,
}

impl ReloadConfigUseCase {
    pub fn new(
        config: Arc<RwLock<Config>>,
        config_writer: Arc<Mutex<()>>,
        config_file_persistence: Arc<dyn ConfigFilePersistence>,
        config_path: Arc<str>,
        upstream: Arc<dyn UpstreamReloadPort>,
        overrides: ConfigOverrides,
    ) -> Self {
        Self {
            config,
            config_writer,
            config_file_persistence,
            config_path,
            upstream,
            overrides,
        }
    }

    /// On any error the running config and upstream pools are left untouched;
    /// a dropped caller does not stop a reload that has taken the writer lock.
    #[instrument(skip(self), name = "reload_config")]
    pub async fn execute(self: Arc<Self>) -> Result<(), DomainError> {
        let writer = Arc::clone(&self.config_writer).lock_owned().await;
        // Pools go live before the running config is swapped, so the swap must not be cancellable.
        tokio::spawn(async move { self.reload(writer).await }.in_current_span())
            .await
            .map_err(|e| DomainError::ConfigError(format!("Config reload failed: {e}")))?
    }

    async fn reload(&self, _writer: OwnedMutexGuard<()>) -> Result<(), DomainError> {
        let path = &*self.config_path;
        let mut new_config = self.config_file_persistence.load_config_from_file(path)?;
        self.overrides.apply(&mut new_config);
        new_config.validate()?;

        // No config lock is held here: resolving upstream hostnames can take seconds.
        let pools_changed = self.config.read().await.dns.pools != new_config.dns.pools;
        if pools_changed {
            self.upstream
                .reload_pools(new_config.dns.pools.clone())
                .await?;
        }

        *self.config.write().await = new_config;
        info!(path, pools_changed, "Configuration reloaded");
        Ok(())
    }
}
