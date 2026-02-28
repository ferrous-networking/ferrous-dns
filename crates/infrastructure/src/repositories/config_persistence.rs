use ferrous_dns_application::ports::ConfigFilePersistence;
use ferrous_dns_domain::{config::errors::ConfigError, Config};

pub struct TomlConfigFilePersistence;

impl ConfigFilePersistence for TomlConfigFilePersistence {
    fn save_config_to_file(&self, config: &Config, path: &str) -> Result<(), String> {
        save_config_to_file(config, path).map_err(|e| e.to_string())
    }
}

pub fn save_config_to_file(config: &Config, path: &str) -> Result<(), ConfigError> {
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
            toml_edit::Value::from(config.server.dns_port as i64),
        );
        set_val(
            t,
            "web_port",
            toml_edit::Value::from(config.server.web_port as i64),
        );
        set_val(
            t,
            "bind_address",
            toml_edit::Value::from(config.server.bind_address.clone()),
        );
    }

    if let Some(dns_item) = doc.get_mut("dns") {
        if let Some(t) = dns_item.as_table_mut() {
            set_val(
                t,
                "upstream_servers",
                str_array(&config.dns.upstream_servers),
            );
            set_val(
                t,
                "query_timeout",
                toml_edit::Value::from(config.dns.query_timeout as i64),
            );
            set_val(
                t,
                "cache_enabled",
                toml_edit::Value::from(config.dns.cache_enabled),
            );
            set_val(
                t,
                "cache_ttl",
                toml_edit::Value::from(config.dns.cache_ttl as i64),
            );
            set_val(
                t,
                "cache_min_ttl",
                toml_edit::Value::from(config.dns.cache_min_ttl as i64),
            );
            set_val(
                t,
                "cache_max_ttl",
                toml_edit::Value::from(config.dns.cache_max_ttl as i64),
            );
            set_val(
                t,
                "dnssec_enabled",
                toml_edit::Value::from(config.dns.dnssec_enabled),
            );
            set_val(
                t,
                "default_strategy",
                toml_edit::Value::from(format!("{:?}", config.dns.default_strategy)),
            );
            set_val(
                t,
                "cache_max_entries",
                toml_edit::Value::from(config.dns.cache_max_entries as i64),
            );
            set_val(
                t,
                "cache_eviction_strategy",
                toml_edit::Value::from(config.dns.cache_eviction_strategy.clone()),
            );
            set_val(
                t,
                "cache_optimistic_refresh",
                toml_edit::Value::from(config.dns.cache_optimistic_refresh),
            );
            set_val(
                t,
                "cache_min_hit_rate",
                toml_edit::Value::from(config.dns.cache_min_hit_rate),
            );
            set_val(
                t,
                "cache_min_frequency",
                toml_edit::Value::from(config.dns.cache_min_frequency as i64),
            );
            set_val(
                t,
                "cache_min_lfuk_score",
                toml_edit::Value::from(config.dns.cache_min_lfuk_score),
            );
            set_val(
                t,
                "cache_refresh_threshold",
                toml_edit::Value::from(config.dns.cache_refresh_threshold),
            );
            set_val(
                t,
                "cache_lfuk_history_size",
                toml_edit::Value::from(config.dns.cache_lfuk_history_size as i64),
            );
            set_val(
                t,
                "cache_batch_eviction_percentage",
                toml_edit::Value::from(config.dns.cache_batch_eviction_percentage),
            );
            set_val(
                t,
                "cache_compaction_interval",
                toml_edit::Value::from(config.dns.cache_compaction_interval as i64),
            );
            set_val(
                t,
                "cache_adaptive_thresholds",
                toml_edit::Value::from(config.dns.cache_adaptive_thresholds),
            );
            set_val(
                t,
                "cache_access_window_secs",
                toml_edit::Value::from(config.dns.cache_access_window_secs as i64),
            );
            set_val(
                t,
                "block_private_ptr",
                toml_edit::Value::from(config.dns.block_private_ptr),
            );
            set_val(
                t,
                "block_non_fqdn",
                toml_edit::Value::from(config.dns.block_non_fqdn),
            );
            if let Some(ref domain) = config.dns.local_domain {
                set_val(t, "local_domain", toml_edit::Value::from(domain.clone()));
            }

            if let Some(hc) = t.get_mut("health_check").and_then(|i| i.as_table_mut()) {
                set_val(
                    hc,
                    "interval",
                    toml_edit::Value::from(config.dns.health_check.interval as i64),
                );
                set_val(
                    hc,
                    "timeout",
                    toml_edit::Value::from(config.dns.health_check.timeout as i64),
                );
                set_val(
                    hc,
                    "failure_threshold",
                    toml_edit::Value::from(config.dns.health_check.failure_threshold as i64),
                );
                set_val(
                    hc,
                    "success_threshold",
                    toml_edit::Value::from(config.dns.health_check.success_threshold as i64),
                );
            }
        }
    }

    if let Some(t) = doc.get_mut("blocking").and_then(|i| i.as_table_mut()) {
        set_val(
            t,
            "enabled",
            toml_edit::Value::from(config.blocking.enabled),
        );
        set_val(
            t,
            "custom_blocked",
            str_array(&config.blocking.custom_blocked),
        );
        set_val(t, "whitelist", str_array(&config.blocking.whitelist));
    }

    if let Some(t) = doc.get_mut("logging").and_then(|i| i.as_table_mut()) {
        set_val(
            t,
            "level",
            toml_edit::Value::from(config.logging.level.clone()),
        );
    }

    if let Some(t) = doc.get_mut("database").and_then(|i| i.as_table_mut()) {
        set_val(
            t,
            "path",
            toml_edit::Value::from(config.database.path.clone()),
        );
        set_val(
            t,
            "log_queries",
            toml_edit::Value::from(config.database.log_queries),
        );
        set_val(
            t,
            "queries_log_stored",
            toml_edit::Value::from(config.database.queries_log_stored as i64),
        );
        set_val(
            t,
            "client_tracking_interval",
            toml_edit::Value::from(config.database.client_tracking_interval as i64),
        );
        set_val(
            t,
            "query_log_channel_capacity",
            toml_edit::Value::from(config.database.query_log_channel_capacity as i64),
        );
        set_val(
            t,
            "query_log_max_batch_size",
            toml_edit::Value::from(config.database.query_log_max_batch_size as i64),
        );
        set_val(
            t,
            "query_log_flush_interval_ms",
            toml_edit::Value::from(config.database.query_log_flush_interval_ms as i64),
        );
        set_val(
            t,
            "query_log_sample_rate",
            toml_edit::Value::from(config.database.query_log_sample_rate as i64),
        );
        set_val(
            t,
            "client_channel_capacity",
            toml_edit::Value::from(config.database.client_channel_capacity as i64),
        );
        set_val(
            t,
            "write_pool_max_connections",
            toml_edit::Value::from(config.database.write_pool_max_connections as i64),
        );
        set_val(
            t,
            "read_pool_max_connections",
            toml_edit::Value::from(config.database.read_pool_max_connections as i64),
        );
        set_val(
            t,
            "write_busy_timeout_secs",
            toml_edit::Value::from(config.database.write_busy_timeout_secs as i64),
        );
        set_val(
            t,
            "read_busy_timeout_secs",
            toml_edit::Value::from(config.database.read_busy_timeout_secs as i64),
        );
        set_val(
            t,
            "read_acquire_timeout_secs",
            toml_edit::Value::from(config.database.read_acquire_timeout_secs as i64),
        );
        set_val(
            t,
            "wal_autocheckpoint",
            toml_edit::Value::from(config.database.wal_autocheckpoint as i64),
        );
    }

    std::fs::write(path, doc.to_string())
        .map_err(|e| ConfigError::FileWrite(path.to_string(), e.to_string()))?;
    Ok(())
}

pub fn save_local_records_to_file(config: &Config, path: &str) -> Result<(), ConfigError> {
    let existing = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::FileRead(path.to_string(), e.to_string()))?;

    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| ConfigError::Parse(format!("Failed to parse config file: {}", e)))?;

    if let Some(dns) = doc.get_mut("dns").and_then(|i| i.as_table_mut()) {
        if config.dns.local_records.is_empty() {
            dns.remove("local_records");
        } else {
            let mut aot = toml_edit::ArrayOfTables::new();
            for record in &config.dns.local_records {
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
