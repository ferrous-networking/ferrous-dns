use serde::{Deserialize, Serialize};

use super::auth::{expiry_from_now, AuthConfig, MAX_STORED_EXPIRY_YEAR};
use super::blocking::BlockingConfig;
use super::database::DatabaseConfig;
use super::dns::DnsConfig;
use super::dns64::Dns64Config;
use super::legacy;
use super::logging::LoggingConfig;
use super::malware_detection;
use super::server::ServerConfig;
use super::upstream::{validate_pool_routes, UpstreamPool};
use crate::errors::domain_error::DomainError;

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
    /// Parses a `ferrous-dns.toml` document, rewriting with a warning each
    /// value earlier releases ran with but this one rejects. Call
    /// [`Config::validate`] once every override is applied.
    pub fn from_toml_str(contents: &str) -> Result<Self, DomainError> {
        let parse_error =
            |e: toml::de::Error| DomainError::ConfigError(format!("Failed to parse config: {e}"));
        let mut doc: toml::Table = toml::from_str(contents).map_err(parse_error)?;
        legacy::normalize_document(&mut doc);
        let mut config = Self::deserialize(doc).map_err(parse_error)?;
        legacy::normalize_values(&mut config);
        config.normalize_pools();
        Ok(config)
    }

    /// The configuration used when no config file exists.
    pub fn builtin() -> Self {
        let mut config = Self::default();
        config.normalize_pools();
        config
    }

    fn normalize_pools(&mut self) {
        if self.dns.pools.is_empty() && !self.dns.upstream_servers.is_empty() {
            self.dns.pools.push(UpstreamPool {
                name: "default".to_string(),
                strategy: self.dns.default_strategy,
                priority: 1,
                servers: self.dns.upstream_servers.clone(),
                ..UpstreamPool::default()
            });
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.server.dns_port == 0 {
            return Err(DomainError::ConfigError("DNS port cannot be 0".to_string()));
        }

        self.validate_non_zero()?;
        self.validate_derived_durations()?;
        malware_detection::validate(&self.dns)?;

        self.dns.local_dns_server_addr()?;

        if self.dns.pools.is_empty() && self.dns.upstream_servers.is_empty() {
            return Err(DomainError::ConfigError(
                "No upstream servers configured".to_string(),
            ));
        }

        for pool in &self.dns.pools {
            if pool.servers.is_empty() {
                return Err(DomainError::ConfigError(format!(
                    "Pool '{}' has no servers",
                    pool.name
                )));
            }
        }
        validate_pool_routes(&self.dns.pools)?;

        Ok(())
    }

    /// Rejects values the runtime cannot honour: a zero interval, timeout,
    /// TTL or capacity panics (zero-period timer, zero-capacity channel or
    /// pool), spins, or silently disables the component it sizes.
    fn validate_non_zero(&self) -> Result<(), DomainError> {
        let dns = &self.dns;
        let database = &self.database;
        let auth = &self.auth;
        let zero_checks = [
            ("dns.query_timeout", dns.query_timeout == 0),
            ("dns.cache_max_entries", dns.cache_max_entries == 0),
            (
                "dns.cache_compaction_interval",
                dns.cache_compaction_interval == 0,
            ),
            (
                "dns.cache_eviction_sample_size",
                dns.cache_eviction_sample_size == 0,
            ),
            ("dns.health_check.interval", dns.health_check.interval == 0),
            ("dns.health_check.timeout", dns.health_check.timeout == 0),
            (
                "dns.rate_limit.queries_per_second",
                dns.rate_limit.queries_per_second == 0,
            ),
            ("dns.rate_limit.burst_size", dns.rate_limit.burst_size == 0),
            (
                "dns.rate_limit.stale_entry_ttl_secs",
                dns.rate_limit.stale_entry_ttl_secs == 0,
            ),
            (
                "dns.tunneling_detection.stale_entry_ttl_secs",
                dns.tunneling_detection.stale_entry_ttl_secs == 0,
            ),
            (
                "dns.tunneling_detection.query_rate_per_apex",
                dns.tunneling_detection.query_rate_per_apex == 0,
            ),
            (
                "dns.tunneling_detection.unique_subdomain_threshold",
                dns.tunneling_detection.unique_subdomain_threshold == 0,
            ),
            (
                "dns.nxdomain_hijack.probe_interval_secs",
                dns.nxdomain_hijack.probe_interval_secs == 0,
            ),
            (
                "dns.nxdomain_hijack.probe_timeout_ms",
                dns.nxdomain_hijack.probe_timeout_ms == 0,
            ),
            (
                "dns.nxdomain_hijack.hijack_ip_ttl_secs",
                dns.nxdomain_hijack.hijack_ip_ttl_secs == 0,
            ),
            (
                "dns.nxdomain_hijack.probes_per_round",
                dns.nxdomain_hijack.probes_per_round == 0,
            ),
            (
                "dns.response_ip_filter.refresh_interval_secs",
                dns.response_ip_filter.refresh_interval_secs == 0,
            ),
            (
                "dns.response_ip_filter.ip_ttl_secs",
                dns.response_ip_filter.ip_ttl_secs == 0,
            ),
            (
                "dns.dga_detection.stale_entry_ttl_secs",
                dns.dga_detection.stale_entry_ttl_secs == 0,
            ),
            (
                "dns.dga_detection.dga_rate_per_client",
                dns.dga_detection.dga_rate_per_client == 0,
            ),
            (
                "database.query_log_channel_capacity",
                database.query_log_channel_capacity == 0,
            ),
            (
                "database.query_log_max_batch_size",
                database.query_log_max_batch_size == 0,
            ),
            (
                "database.query_log_flush_interval_ms",
                database.query_log_flush_interval_ms == 0,
            ),
            (
                "database.client_channel_capacity",
                database.client_channel_capacity == 0,
            ),
            (
                "database.write_pool_max_connections",
                database.write_pool_max_connections == 0,
            ),
            (
                "database.query_log_pool_max_connections",
                database.query_log_pool_max_connections == 0,
            ),
            (
                "database.read_pool_max_connections",
                database.read_pool_max_connections == 0,
            ),
            (
                "database.write_busy_timeout_secs",
                database.write_busy_timeout_secs == 0,
            ),
            (
                "database.read_acquire_timeout_secs",
                database.read_acquire_timeout_secs == 0,
            ),
            (
                "database.wal_checkpoint_interval_secs",
                database.wal_checkpoint_interval_secs == 0,
            ),
            ("auth.session_ttl_hours", auth.session_ttl_hours == 0),
            ("auth.remember_me_days", auth.remember_me_days == 0),
            (
                "auth.login_rate_limit_window_secs",
                auth.login_rate_limit_window_secs == 0,
            ),
            (
                "auth.mfa_challenge_ttl_secs",
                auth.mfa_challenge_ttl_secs <= 0,
            ),
        ];
        if let Some((field, _)) = zero_checks.into_iter().find(|&(_, is_zero)| is_zero) {
            return Err(DomainError::ConfigError(format!(
                "{field} must be greater than 0"
            )));
        }

        // DashMap asserts a power-of-two shard count above 1.
        for (field, shards) in [
            ("dns.cache_shard_amount", dns.cache_shard_amount),
            ("dns.cache_inflight_shards", dns.cache_inflight_shards),
        ] {
            if shards < 2 || !shards.is_power_of_two() {
                return Err(DomainError::ConfigError(format!(
                    "{field} must be a power of two of at least 2, got {shards}"
                )));
            }
        }

        // Every cached TTL is clamped to this range, which must not be inverted.
        if dns.cache_min_ttl > dns.cache_max_ttl {
            return Err(DomainError::ConfigError(format!(
                "dns.cache_min_ttl ({}) must not exceed dns.cache_max_ttl ({})",
                dns.cache_min_ttl, dns.cache_max_ttl
            )));
        }

        Ok(())
    }

    /// Rejects values whose derived duration overflows where it is used:
    /// session and MFA-challenge expiries are `now + ttl` and must be storable
    /// with a four-digit year, and the upstream timeout is taken in milliseconds.
    fn validate_derived_durations(&self) -> Result<(), DomainError> {
        let auth = &self.auth;
        for (field, ttl_secs) in [
            ("auth.session_ttl_hours", auth.session_ttl_secs(false)),
            ("auth.remember_me_days", auth.session_ttl_secs(true)),
            ("auth.mfa_challenge_ttl_secs", auth.mfa_challenge_ttl_secs),
        ] {
            if expiry_from_now(ttl_secs).is_none() {
                return Err(DomainError::ConfigError(format!(
                    "{field} is too large: an expiry {ttl_secs}s from now is past year {MAX_STORED_EXPIRY_YEAR}"
                )));
            }
        }

        if self.dns.query_timeout.checked_mul(1000).is_none() {
            return Err(DomainError::ConfigError(format!(
                "dns.query_timeout is too large: {} seconds overflow when converted to milliseconds",
                self.dns.query_timeout
            )));
        }

        Ok(())
    }
}
