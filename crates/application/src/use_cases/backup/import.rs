use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

use crate::ports::{
    BlocklistSourceCreator, ConfigFilePersistence, GroupCreator, LocalRecordCreator,
};

use super::snapshot::{BackupSnapshot, ImportSummary};

const SUPPORTED_VERSION: &str = "1";

/// Returns `true` for errors that represent a pre-existing entity (idempotent import).
///
/// When a group or blocklist source already exists, the repository returns
/// `InvalidGroupName` / `InvalidBlocklistSource` with an "already exists" message.
/// These are expected during re-import and must not be surfaced as failures.
fn is_duplicate_error(e: &DomainError) -> bool {
    match e {
        DomainError::InvalidGroupName(msg) | DomainError::InvalidBlocklistSource(msg) => {
            msg.contains("already exists")
        }
        _ => false,
    }
}

pub struct ImportConfigUseCase {
    config: Arc<RwLock<Config>>,
    config_file_persistence: Arc<dyn ConfigFilePersistence>,
    config_path: Option<String>,
    group_creator: Arc<dyn GroupCreator>,
    blocklist_source_creator: Arc<dyn BlocklistSourceCreator>,
    local_record_creator: Arc<dyn LocalRecordCreator>,
}

impl ImportConfigUseCase {
    pub fn new(
        config: Arc<RwLock<Config>>,
        config_file_persistence: Arc<dyn ConfigFilePersistence>,
        config_path: Option<String>,
        group_creator: Arc<dyn GroupCreator>,
        blocklist_source_creator: Arc<dyn BlocklistSourceCreator>,
        local_record_creator: Arc<dyn LocalRecordCreator>,
    ) -> Self {
        Self {
            config,
            config_file_persistence,
            config_path,
            group_creator,
            blocklist_source_creator,
            local_record_creator,
        }
    }

    #[instrument(skip(self, snapshot), name = "import_config")]
    pub async fn execute(&self, snapshot: BackupSnapshot) -> Result<ImportSummary, DomainError> {
        if snapshot.version != SUPPORTED_VERSION {
            return Err(DomainError::InvalidInput(format!(
                "Unsupported backup version '{}'. Expected '{}'.",
                snapshot.version, SUPPORTED_VERSION
            )));
        }

        let mut errors: Vec<String> = Vec::new();

        let config_updated = self.apply_config(&snapshot, &mut errors).await;

        let (groups_imported, groups_skipped) = self.import_groups(&snapshot, &mut errors).await;

        let (blocklist_sources_imported, blocklist_sources_skipped) =
            self.import_blocklist_sources(&snapshot, &mut errors).await;

        let (local_records_imported, local_records_skipped) =
            self.import_local_records(&snapshot, &mut errors).await;

        info!(
            config_updated,
            groups_imported,
            groups_skipped,
            blocklist_sources_imported,
            blocklist_sources_skipped,
            local_records_imported,
            local_records_skipped,
            errors = errors.len(),
            "Backup import completed"
        );

        Ok(ImportSummary {
            config_updated,
            groups_imported,
            groups_skipped,
            blocklist_sources_imported,
            blocklist_sources_skipped,
            local_records_imported,
            local_records_skipped,
            errors,
        })
    }

    async fn apply_config(&self, snapshot: &BackupSnapshot, errors: &mut Vec<String>) -> bool {
        let path = match &self.config_path {
            Some(p) => p.clone(),
            None => {
                let discovered = Config::get_config_path();
                match discovered {
                    Some(p) => p,
                    None => {
                        let msg = "No config file path available — config section not restored.";
                        warn!(msg);
                        errors.push(msg.to_string());
                        return false;
                    }
                }
            }
        };

        let mut new_config = self.config.read().await.clone();

        let sc = &snapshot.config;
        new_config.server.dns_port = sc.server.dns_port;
        new_config.server.web_port = sc.server.web_port;
        new_config.server.bind_address = sc.server.bind_address.clone();
        new_config.server.pihole_compat = sc.server.pihole_compat;
        new_config.server.web_tls.enabled = sc.server.tls_enabled;
        new_config.server.web_tls.tls_cert_path = sc.server.tls_cert_path.clone();
        new_config.server.web_tls.tls_key_path = sc.server.tls_key_path.clone();

        new_config.dns.upstream_servers = sc.dns.upstream_servers.clone();
        new_config.dns.cache_enabled = sc.dns.cache_enabled;
        new_config.dns.dnssec_enabled = sc.dns.dnssec_enabled;
        new_config.dns.cache_eviction_strategy = sc.dns.cache_eviction_strategy.clone();
        new_config.dns.cache_max_entries = sc.dns.cache_max_entries;
        new_config.dns.cache_min_hit_rate = sc.dns.cache_min_hit_rate;
        new_config.dns.cache_min_frequency = sc.dns.cache_min_frequency;
        new_config.dns.cache_min_lfuk_score = sc.dns.cache_min_lfuk_score;
        new_config.dns.cache_compaction_interval = sc.dns.cache_compaction_interval;
        new_config.dns.cache_refresh_threshold = sc.dns.cache_refresh_threshold;
        new_config.dns.cache_optimistic_refresh = sc.dns.cache_optimistic_refresh;
        new_config.dns.cache_adaptive_thresholds = sc.dns.cache_adaptive_thresholds;
        new_config.dns.cache_access_window_secs = sc.dns.cache_access_window_secs;
        new_config.dns.cache_min_ttl = sc.dns.cache_min_ttl;
        new_config.dns.cache_max_ttl = sc.dns.cache_max_ttl;
        new_config.dns.block_non_fqdn = sc.dns.block_non_fqdn;
        new_config.dns.block_private_ptr = sc.dns.block_private_ptr;
        new_config.dns.local_domain = sc.dns.local_domain.clone();
        new_config.dns.local_dns_server = sc.dns.local_dns_server.clone();

        new_config.blocking.enabled = sc.blocking.enabled;
        new_config.blocking.custom_blocked = sc.blocking.custom_blocked.clone();
        new_config.blocking.whitelist = sc.blocking.whitelist.clone();

        new_config.logging.level = sc.logging.level.clone();

        new_config.auth.enabled = sc.auth.enabled;
        new_config.auth.session_ttl_hours = sc.auth.session_ttl_hours;
        new_config.auth.remember_me_days = sc.auth.remember_me_days;
        new_config.auth.login_rate_limit_attempts = sc.auth.login_rate_limit_attempts;
        new_config.auth.login_rate_limit_window_secs = sc.auth.login_rate_limit_window_secs;

        match self
            .config_file_persistence
            .save_config_to_file(&new_config, &path)
        {
            Ok(_) => {
                *self.config.write().await = new_config;
                true
            }
            Err(e) => {
                let msg = format!("Failed to persist config: {}", e);
                error!(error = %e, "Config persistence failed during import");
                errors.push(msg);
                false
            }
        }
    }

    async fn import_groups(
        &self,
        snapshot: &BackupSnapshot,
        errors: &mut Vec<String>,
    ) -> (usize, usize) {
        let mut imported = 0usize;
        let mut skipped = 0usize;

        for group in &snapshot.data.groups {
            match self
                .group_creator
                .create_group(group.name.clone(), group.comment.clone())
                .await
            {
                Ok(_) => imported += 1,
                Err(e) if is_duplicate_error(&e) => {
                    skipped += 1;
                }
                Err(e) => {
                    warn!(name = %group.name, error = %e, "Skipping group during import");
                    skipped += 1;
                    errors.push(format!("Group '{}': {}", group.name, e));
                }
            }
        }

        (imported, skipped)
    }

    async fn import_blocklist_sources(
        &self,
        snapshot: &BackupSnapshot,
        errors: &mut Vec<String>,
    ) -> (usize, usize) {
        let mut imported = 0usize;
        let mut skipped = 0usize;

        for source in &snapshot.data.blocklist_sources {
            match self
                .blocklist_source_creator
                .create_blocklist_source(
                    source.name.clone(),
                    source.url.clone(),
                    source.group_ids.clone(),
                    source.comment.clone(),
                    source.enabled,
                )
                .await
            {
                Ok(_) => imported += 1,
                Err(e) if is_duplicate_error(&e) => {
                    skipped += 1;
                }
                Err(e) => {
                    warn!(name = %source.name, error = %e, "Skipping blocklist source during import");
                    skipped += 1;
                    errors.push(format!("Blocklist source '{}': {}", source.name, e));
                }
            }
        }

        (imported, skipped)
    }

    async fn import_local_records(
        &self,
        snapshot: &BackupSnapshot,
        errors: &mut Vec<String>,
    ) -> (usize, usize) {
        let mut imported = 0usize;
        let mut skipped = 0usize;

        for record in &snapshot.data.local_records {
            {
                let config = self.config.read().await;
                let already_exists = config.dns.local_records.iter().any(|r| {
                    r.hostname == record.hostname
                        && r.domain.as_deref().unwrap_or("")
                            == record.domain.as_deref().unwrap_or("")
                });
                if already_exists {
                    skipped += 1;
                    continue;
                }
            }

            match self
                .local_record_creator
                .create_local_record(
                    record.hostname.clone(),
                    record.domain.clone(),
                    record.ip.clone(),
                    record.record_type.clone(),
                    record.ttl,
                )
                .await
            {
                Ok(_) => imported += 1,
                Err(e) => {
                    warn!(hostname = %record.hostname, error = %e, "Skipping local record during import");
                    skipped += 1;
                    let fqdn = match &record.domain {
                        Some(d) => format!("{}.{}", record.hostname, d),
                        None => record.hostname.clone(),
                    };
                    errors.push(format!("Local record '{}': {}", fqdn, e));
                }
            }
        }

        (imported, skipped)
    }
}
