use serde::{Deserialize, Serialize};

use super::blocking::BlockingConfig;
use super::database::DatabaseConfig;
use super::dns::DnsConfig;
use super::errors::ConfigError;
use super::logging::LoggingConfig;
use super::server::ServerConfig;
use super::upstream::UpstreamPool;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Config {
    pub server: ServerConfig,

    pub dns: DnsConfig,

    pub blocking: BlockingConfig,

    pub logging: LoggingConfig,

    pub database: DatabaseConfig,
}

impl Config {
    pub fn load(path: Option<&str>, cli_overrides: CliOverrides) -> Result<Self, ConfigError> {
        let mut config = if let Some(path) = path {
            Self::from_file(path)?
        } else if std::path::Path::new("ferrous-dns.toml").exists() {
            Self::from_file("ferrous-dns.toml")?
        } else if std::path::Path::new("/etc/ferrous-dns/config.toml").exists() {
            Self::from_file("/etc/ferrous-dns/config.toml")?
        } else {
            Self::default()
        };

        config.apply_cli_overrides(cli_overrides);
        config.normalize_pools();
        Ok(config)
    }

    fn from_file(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::FileRead(path.to_string(), e.to_string()))?;
        toml::from_str(&contents).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    fn apply_cli_overrides(&mut self, overrides: CliOverrides) {
        if let Some(port) = overrides.dns_port {
            self.server.dns_port = port;
        }
        if let Some(port) = overrides.web_port {
            self.server.web_port = port;
        }
        if let Some(bind) = overrides.bind_address {
            self.server.bind_address = bind;
        }
        if let Some(db) = overrides.database_path {
            self.database.path = db;
        }
        if let Some(level) = overrides.log_level {
            self.logging.level = level;
        }
    }

    fn normalize_pools(&mut self) {
        if self.dns.pools.is_empty() && !self.dns.upstream_servers.is_empty() {
            self.dns.pools.push(UpstreamPool {
                name: "default".to_string(),
                strategy: self.dns.default_strategy,
                priority: 1,
                servers: self.dns.upstream_servers.clone(),
                weight: None,
            });
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.dns_port == 0 {
            return Err(ConfigError::Validation("DNS port cannot be 0".to_string()));
        }

        if self.dns.pools.is_empty() && self.dns.upstream_servers.is_empty() {
            return Err(ConfigError::Validation(
                "No upstream servers configured".to_string(),
            ));
        }

        for pool in &self.dns.pools {
            if pool.servers.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "Pool '{}' has no servers",
                    pool.name
                )));
            }
        }

        Ok(())
    }

    pub fn save(&self, path: &str) -> Result<(), ConfigError> {
        let toml_string = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Parse(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, toml_string)
            .map_err(|e| ConfigError::FileWrite(path.to_string(), e.to_string()))?;
        Ok(())
    }

    pub fn get_config_path() -> Option<String> {
        if std::path::Path::new("ferrous-dns.toml").exists() {
            Some("ferrous-dns.toml".to_string())
        } else if std::path::Path::new("/etc/ferrous-dns/config.toml").exists() {
            Some("/etc/ferrous-dns/config.toml".to_string())
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct CliOverrides {
    pub dns_port: Option<u16>,
    pub web_port: Option<u16>,
    pub bind_address: Option<String>,
    pub database_path: Option<String>,
    pub log_level: Option<String>,
}
