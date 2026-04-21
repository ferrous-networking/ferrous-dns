use std::sync::Arc;

use chrono::Utc;
use ferrous_dns_domain::{Config, DomainError};
use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::ports::{BlocklistSourceRepository, GroupRepository};

use super::snapshot::{
    BackupSnapshot, BlocklistSourceSnapshot, GroupSnapshot, LocalRecordSnapshot,
    SnapshotAuthConfig, SnapshotBlockingConfig, SnapshotConfig, SnapshotData, SnapshotDnsConfig,
    SnapshotLoggingConfig, SnapshotServerConfig,
};

const SNAPSHOT_FORMAT_VERSION: &str = "1";
const FERROUS_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct ExportConfigUseCase {
    config: Arc<RwLock<Config>>,
    group_repo: Arc<dyn GroupRepository>,
    blocklist_source_repo: Arc<dyn BlocklistSourceRepository>,
}

impl ExportConfigUseCase {
    pub fn new(
        config: Arc<RwLock<Config>>,
        group_repo: Arc<dyn GroupRepository>,
        blocklist_source_repo: Arc<dyn BlocklistSourceRepository>,
    ) -> Self {
        Self {
            config,
            group_repo,
            blocklist_source_repo,
        }
    }

    #[instrument(skip(self), name = "export_config")]
    pub async fn execute(&self) -> Result<Vec<u8>, DomainError> {
        let config = self.config.read().await;

        let snapshot_config = self.build_snapshot_config(&config);

        let groups = self.group_repo.get_all().await?;
        let group_snapshots: Vec<GroupSnapshot> = groups
            .into_iter()
            .map(|g| GroupSnapshot {
                name: g.name.to_string(),
                comment: g.comment.map(|c| c.to_string()),
            })
            .collect();

        let blocklist_sources = self.blocklist_source_repo.get_all().await?;
        let source_snapshots: Vec<BlocklistSourceSnapshot> = blocklist_sources
            .into_iter()
            .map(|s| BlocklistSourceSnapshot {
                name: s.name.to_string(),
                url: s.url.map(|u| u.to_string()),
                group_ids: s.group_ids,
                comment: s.comment.map(|c| c.to_string()),
                enabled: s.enabled,
            })
            .collect();

        let local_record_snapshots: Vec<LocalRecordSnapshot> = config
            .dns
            .local_records
            .iter()
            .map(|r| LocalRecordSnapshot {
                hostname: r.hostname.clone(),
                domain: r.domain.clone(),
                ip: r.ip.clone(),
                record_type: r.record_type.clone(),
                ttl: r.ttl,
            })
            .collect();

        let snapshot = BackupSnapshot {
            version: SNAPSHOT_FORMAT_VERSION.to_string(),
            ferrous_version: FERROUS_VERSION.to_string(),
            exported_at: Utc::now().to_rfc3339(),
            config: snapshot_config,
            data: SnapshotData {
                groups: group_snapshots,
                blocklist_sources: source_snapshots,
                local_records: local_record_snapshots,
            },
        };

        let bytes = serde_json::to_vec(&snapshot)
            .map_err(|e| DomainError::IoError(format!("Failed to serialize backup: {}", e)))?;

        info!(
            groups = snapshot.data.groups.len(),
            blocklist_sources = snapshot.data.blocklist_sources.len(),
            local_records = snapshot.data.local_records.len(),
            "Configuration exported successfully"
        );

        Ok(bytes)
    }

    fn build_snapshot_config(&self, config: &Config) -> SnapshotConfig {
        SnapshotConfig {
            server: SnapshotServerConfig {
                dns_port: config.server.dns_port,
                web_port: config.server.web_port,
                bind_address: config.server.bind_address.clone(),
                pihole_compat: config.server.pihole_compat,
                tls_cert_path: config.server.web_tls.tls_cert_path.clone(),
                tls_key_path: config.server.web_tls.tls_key_path.clone(),
                tls_enabled: config.server.web_tls.enabled,
            },
            dns: SnapshotDnsConfig {
                upstream_servers: config.dns.upstream_servers.clone(),
                cache_enabled: config.dns.cache_enabled,
                dnssec_enabled: config.dns.dnssec_enabled,
                cache_eviction_strategy: config.dns.cache_eviction_strategy.clone(),
                cache_max_entries: config.dns.cache_max_entries,
                cache_min_hit_rate: config.dns.cache_min_hit_rate,
                cache_min_frequency: config.dns.cache_min_frequency,
                cache_min_lfuk_score: config.dns.cache_min_lfuk_score,
                cache_compaction_interval: config.dns.cache_compaction_interval,
                cache_refresh_threshold: config.dns.cache_refresh_threshold,
                cache_optimistic_refresh: config.dns.cache_optimistic_refresh,
                cache_adaptive_thresholds: config.dns.cache_adaptive_thresholds,
                cache_access_window_secs: config.dns.cache_access_window_secs,
                cache_min_ttl: config.dns.cache_min_ttl,
                cache_max_ttl: config.dns.cache_max_ttl,
                block_non_fqdn: config.dns.block_non_fqdn,
                block_private_ptr: config.dns.block_private_ptr,
                local_domain: config.dns.local_domain.clone(),
                local_dns_server: config.dns.local_dns_server.clone(),
            },
            blocking: SnapshotBlockingConfig {
                enabled: config.blocking.enabled,
                custom_blocked: config.blocking.custom_blocked.clone(),
                whitelist: config.blocking.whitelist.clone(),
            },
            logging: SnapshotLoggingConfig {
                level: config.logging.level.clone(),
            },
            auth: SnapshotAuthConfig {
                enabled: config.auth.enabled,
                session_ttl_hours: config.auth.session_ttl_hours,
                remember_me_days: config.auth.remember_me_days,
                login_rate_limit_attempts: config.auth.login_rate_limit_attempts,
                login_rate_limit_window_secs: config.auth.login_rate_limit_window_secs,
            },
        }
    }
}
