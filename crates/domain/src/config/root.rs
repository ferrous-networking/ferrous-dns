use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::auth::AuthConfig;
use super::blocking::BlockingConfig;
use super::database::DatabaseConfig;
use super::dns::DnsConfig;
use super::dns64::Dns64Config;
use super::errors::ConfigError;
use super::logging::LoggingConfig;
use super::server::ServerConfig;
use super::upstream::UpstreamPool;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Config {
    pub server: ServerConfig,

    pub dns: DnsConfig,

    pub blocking: BlockingConfig,

    #[serde(default)]
    pub dns64: Dns64Config,

    pub logging: LoggingConfig,

    pub database: DatabaseConfig,

    #[serde(default)]
    pub auth: AuthConfig,
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

        // Every listener parses its address only when it binds, and the
        // encrypted ones bind inside a spawned task — so without this an
        // unparseable address takes a listener down with a single log line
        // while the process stays up. Check them all up front instead. A
        // listener that falls back to `bind_address` is already covered by
        // the first check, so only an explicit override is named separately.
        check_listen_address("server.bind_address", &self.server.dns_listen_address())?;
        let encrypted = &self.server.encrypted_dns;
        if encrypted.dot_enabled && encrypted.dot_bind_address.is_some() {
            check_listen_address(
                "server.encrypted_dns.dot_bind_address",
                &self.server.dot_listen_address(),
            )?;
        }
        if encrypted.doq_enabled && encrypted.doq_bind_address.is_some() {
            check_listen_address(
                "server.encrypted_dns.doq_bind_address",
                &self.server.doq_listen_address(),
            )?;
        }
        if encrypted.doh_enabled && encrypted.doh_bind_address.is_some() {
            if let Some(addr) = self.server.doh_listen_address() {
                check_listen_address("server.encrypted_dns.doh_bind_address", &addr)?;
            }
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

/// Rejects a listen address the listeners could not bind. `field` names the
/// configuration key so the operator knows which one to fix.
fn check_listen_address(field: &str, addr: &str) -> Result<(), ConfigError> {
    if addr.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    Err(ConfigError::Validation(format!(
        "{field} yields the invalid listen address '{addr}'; it must be an IPv4 or IPv6 literal, not a hostname"
    )))
}
