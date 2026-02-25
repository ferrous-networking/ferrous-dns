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
        let existing = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::FileRead(path.to_string(), e.to_string()))?;

        let mut doc = existing
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| ConfigError::Parse(format!("Failed to parse config file: {}", e)))?;

        fn set_val(table: &mut toml_edit::Table, key: &str, new_val: toml_edit::Value) {
            match table.get_mut(key) {
                Some(item @ toml_edit::Item::Value(_)) => {
                    let suffix = item.as_value().and_then(|v| v.decor().suffix()).cloned();
                    *item = toml_edit::Item::Value(new_val);
                    if let (Some(s), Some(v)) = (suffix, item.as_value_mut()) {
                        v.decor_mut().set_suffix(s);
                    }
                }
                Some(item) => *item = toml_edit::Item::Value(new_val),
                None => {
                    table.insert(key, toml_edit::Item::Value(new_val));
                }
            }
        }

        fn str_array(values: &[String]) -> toml_edit::Value {
            let mut arr = toml_edit::Array::new();
            for v in values {
                arr.push(v.as_str());
            }
            toml_edit::Value::Array(arr)
        }

        if let Some(t) = doc.get_mut("server").and_then(|i| i.as_table_mut()) {
            set_val(
                t,
                "dns_port",
                toml_edit::Value::from(self.server.dns_port as i64),
            );
            set_val(
                t,
                "web_port",
                toml_edit::Value::from(self.server.web_port as i64),
            );
            set_val(
                t,
                "bind_address",
                toml_edit::Value::from(self.server.bind_address.clone()),
            );
        }

        if let Some(dns_item) = doc.get_mut("dns") {
            if let Some(t) = dns_item.as_table_mut() {
                set_val(t, "upstream_servers", str_array(&self.dns.upstream_servers));
                set_val(
                    t,
                    "query_timeout",
                    toml_edit::Value::from(self.dns.query_timeout as i64),
                );
                set_val(
                    t,
                    "cache_enabled",
                    toml_edit::Value::from(self.dns.cache_enabled),
                );
                set_val(
                    t,
                    "cache_ttl",
                    toml_edit::Value::from(self.dns.cache_ttl as i64),
                );
                set_val(
                    t,
                    "cache_min_ttl",
                    toml_edit::Value::from(self.dns.cache_min_ttl as i64),
                );
                set_val(
                    t,
                    "cache_max_ttl",
                    toml_edit::Value::from(self.dns.cache_max_ttl as i64),
                );
                set_val(
                    t,
                    "dnssec_enabled",
                    toml_edit::Value::from(self.dns.dnssec_enabled),
                );
                set_val(
                    t,
                    "default_strategy",
                    toml_edit::Value::from(format!("{:?}", self.dns.default_strategy)),
                );
                set_val(
                    t,
                    "cache_max_entries",
                    toml_edit::Value::from(self.dns.cache_max_entries as i64),
                );
                set_val(
                    t,
                    "cache_eviction_strategy",
                    toml_edit::Value::from(self.dns.cache_eviction_strategy.clone()),
                );
                set_val(
                    t,
                    "cache_optimistic_refresh",
                    toml_edit::Value::from(self.dns.cache_optimistic_refresh),
                );
                set_val(
                    t,
                    "cache_min_hit_rate",
                    toml_edit::Value::from(self.dns.cache_min_hit_rate),
                );
                set_val(
                    t,
                    "cache_min_frequency",
                    toml_edit::Value::from(self.dns.cache_min_frequency as i64),
                );
                set_val(
                    t,
                    "cache_min_lfuk_score",
                    toml_edit::Value::from(self.dns.cache_min_lfuk_score),
                );
                set_val(
                    t,
                    "cache_refresh_threshold",
                    toml_edit::Value::from(self.dns.cache_refresh_threshold),
                );
                set_val(
                    t,
                    "cache_lfuk_history_size",
                    toml_edit::Value::from(self.dns.cache_lfuk_history_size as i64),
                );
                set_val(
                    t,
                    "cache_batch_eviction_percentage",
                    toml_edit::Value::from(self.dns.cache_batch_eviction_percentage),
                );
                set_val(
                    t,
                    "cache_compaction_interval",
                    toml_edit::Value::from(self.dns.cache_compaction_interval as i64),
                );
                set_val(
                    t,
                    "cache_adaptive_thresholds",
                    toml_edit::Value::from(self.dns.cache_adaptive_thresholds),
                );
                set_val(
                    t,
                    "cache_access_window_secs",
                    toml_edit::Value::from(self.dns.cache_access_window_secs as i64),
                );
                set_val(
                    t,
                    "block_private_ptr",
                    toml_edit::Value::from(self.dns.block_private_ptr),
                );
                set_val(
                    t,
                    "block_non_fqdn",
                    toml_edit::Value::from(self.dns.block_non_fqdn),
                );
                if let Some(ref domain) = self.dns.local_domain {
                    set_val(t, "local_domain", toml_edit::Value::from(domain.clone()));
                }

                if let Some(hc) = t.get_mut("health_check").and_then(|i| i.as_table_mut()) {
                    set_val(
                        hc,
                        "interval",
                        toml_edit::Value::from(self.dns.health_check.interval as i64),
                    );
                    set_val(
                        hc,
                        "timeout",
                        toml_edit::Value::from(self.dns.health_check.timeout as i64),
                    );
                    set_val(
                        hc,
                        "failure_threshold",
                        toml_edit::Value::from(self.dns.health_check.failure_threshold as i64),
                    );
                    set_val(
                        hc,
                        "success_threshold",
                        toml_edit::Value::from(self.dns.health_check.success_threshold as i64),
                    );
                }
            }
        }

        if let Some(t) = doc.get_mut("blocking").and_then(|i| i.as_table_mut()) {
            set_val(t, "enabled", toml_edit::Value::from(self.blocking.enabled));
            set_val(
                t,
                "custom_blocked",
                str_array(&self.blocking.custom_blocked),
            );
            set_val(t, "whitelist", str_array(&self.blocking.whitelist));
        }

        if let Some(t) = doc.get_mut("logging").and_then(|i| i.as_table_mut()) {
            set_val(
                t,
                "level",
                toml_edit::Value::from(self.logging.level.clone()),
            );
        }

        if let Some(t) = doc.get_mut("database").and_then(|i| i.as_table_mut()) {
            set_val(
                t,
                "path",
                toml_edit::Value::from(self.database.path.clone()),
            );
            set_val(
                t,
                "log_queries",
                toml_edit::Value::from(self.database.log_queries),
            );
            set_val(
                t,
                "queries_log_stored",
                toml_edit::Value::from(self.database.queries_log_stored as i64),
            );
            set_val(
                t,
                "client_tracking_interval",
                toml_edit::Value::from(self.database.client_tracking_interval as i64),
            );
            set_val(
                t,
                "query_log_channel_capacity",
                toml_edit::Value::from(self.database.query_log_channel_capacity as i64),
            );
            set_val(
                t,
                "query_log_max_batch_size",
                toml_edit::Value::from(self.database.query_log_max_batch_size as i64),
            );
            set_val(
                t,
                "query_log_flush_interval_ms",
                toml_edit::Value::from(self.database.query_log_flush_interval_ms as i64),
            );
            set_val(
                t,
                "query_log_sample_rate",
                toml_edit::Value::from(self.database.query_log_sample_rate as i64),
            );
            set_val(
                t,
                "client_channel_capacity",
                toml_edit::Value::from(self.database.client_channel_capacity as i64),
            );
            set_val(
                t,
                "write_pool_max_connections",
                toml_edit::Value::from(self.database.write_pool_max_connections as i64),
            );
            set_val(
                t,
                "read_pool_max_connections",
                toml_edit::Value::from(self.database.read_pool_max_connections as i64),
            );
            set_val(
                t,
                "write_busy_timeout_secs",
                toml_edit::Value::from(self.database.write_busy_timeout_secs as i64),
            );
            set_val(
                t,
                "read_busy_timeout_secs",
                toml_edit::Value::from(self.database.read_busy_timeout_secs as i64),
            );
            set_val(
                t,
                "read_acquire_timeout_secs",
                toml_edit::Value::from(self.database.read_acquire_timeout_secs as i64),
            );
            set_val(
                t,
                "wal_autocheckpoint",
                toml_edit::Value::from(self.database.wal_autocheckpoint as i64),
            );
        }

        std::fs::write(path, doc.to_string())
            .map_err(|e| ConfigError::FileWrite(path.to_string(), e.to_string()))?;
        Ok(())
    }

    pub fn save_local_records(&self, path: &str) -> Result<(), ConfigError> {
        let existing = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::FileRead(path.to_string(), e.to_string()))?;

        let mut doc = existing
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| ConfigError::Parse(format!("Failed to parse config file: {}", e)))?;

        if let Some(dns) = doc.get_mut("dns").and_then(|i| i.as_table_mut()) {
            if self.dns.local_records.is_empty() {
                dns.remove("local_records");
            } else {
                let mut aot = toml_edit::ArrayOfTables::new();
                for record in &self.dns.local_records {
                    let mut table = toml_edit::Table::new();
                    table.insert("hostname", toml_edit::value(record.hostname.clone()));
                    if let Some(ref domain) = record.domain {
                        table.insert("domain", toml_edit::value(domain.clone()));
                    }
                    table.insert("ip", toml_edit::value(record.ip.clone()));
                    table.insert("record_type", toml_edit::value(record.record_type.clone()));
                    if let Some(ttl) = record.ttl {
                        table.insert("ttl", toml_edit::value(ttl as i64));
                    }
                    aot.push(table);
                }
                dns.insert("local_records", toml_edit::Item::ArrayOfTables(aot));
            }
        }

        std::fs::write(path, doc.to_string())
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
