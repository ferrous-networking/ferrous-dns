use std::collections::HashMap;
use std::sync::Arc;

use ferrous_dns_domain::{Config, DnsProtocol, DomainError, LocalDnsRecord};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, instrument, warn};

use crate::ports::{
    BlockFilterEnginePort, BlocklistSourceCreator, ConfigFilePersistence, GroupCreator,
    GroupRepository, LocalRecordCreator,
};

use super::snapshot::{BackupSnapshot, ImportSummary};

const SUPPORTED_VERSION: &str = "1";

/// Pre-existing entities are expected on re-import and are skipped silently.
fn is_duplicate_error(e: &DomainError) -> bool {
    matches!(e, DomainError::AlreadyExists(_))
}

/// The exporting server's group ids, keyed to the ids the same groups have
/// here; `Err` carries the first id the backup does not list.
fn translate_group_ids(ids: &[i64], here: &HashMap<i64, i64>) -> Result<Vec<i64>, i64> {
    ids.iter()
        .map(|id| here.get(id).copied().ok_or(*id))
        .collect()
}

/// The live config an import restores into, and the file it is saved to.
/// `writer` is the lock every config writer holds for its read-modify-write.
pub struct ConfigDestination {
    pub config: Arc<RwLock<Config>>,
    pub writer: Arc<Mutex<()>>,
    pub persistence: Arc<dyn ConfigFilePersistence>,
    pub path: Option<String>,
}

pub struct ImportConfigUseCase {
    destination: ConfigDestination,
    group_creator: Arc<dyn GroupCreator>,
    group_repo: Arc<dyn GroupRepository>,
    blocklist_source_creator: Arc<dyn BlocklistSourceCreator>,
    local_record_creator: Arc<dyn LocalRecordCreator>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl ImportConfigUseCase {
    pub fn new(
        destination: ConfigDestination,
        group_creator: Arc<dyn GroupCreator>,
        group_repo: Arc<dyn GroupRepository>,
        blocklist_source_creator: Arc<dyn BlocklistSourceCreator>,
        local_record_creator: Arc<dyn LocalRecordCreator>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            destination,
            group_creator,
            group_repo,
            blocklist_source_creator,
            local_record_creator,
            block_filter_engine,
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

        // Groups first: pools and blocklist sources name them by id.
        let (groups_imported, groups_skipped) = self.import_groups(&snapshot, &mut errors).await;
        let group_ids = self.map_group_ids(&snapshot, &mut errors).await;

        let config_changed = self.apply_config(&snapshot, &group_ids, &mut errors).await;
        let config_updated = config_changed.is_some();
        let restart_required = config_changed == Some(true);

        let (blocklist_sources_imported, blocklist_sources_skipped) = self
            .import_blocklist_sources(&snapshot, &group_ids, &mut errors)
            .await;

        // The creator above deliberately skips the per-source reload, so the
        // whole batch costs one block index rebuild instead of one each.
        if blocklist_sources_imported > 0 {
            if let Err(e) = self.block_filter_engine.reload().await {
                error!(error = %e, "Failed to reload block filter after backup import");
            }
        }

        let (local_records_imported, local_records_skipped) =
            self.import_local_records(&snapshot, &mut errors).await;

        info!(
            config_updated,
            restart_required,
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
            restart_required,
            groups_imported,
            groups_skipped,
            blocklist_sources_imported,
            blocklist_sources_skipped,
            local_records_imported,
            local_records_skipped,
            errors,
        })
    }

    /// Maps each backed-up group's id to the id it has here: its name's, or
    /// for the default group, whatever this server calls it. `None` for an
    /// older backup, whose groups carry no ids.
    async fn map_group_ids(
        &self,
        snapshot: &BackupSnapshot,
        errors: &mut Vec<String>,
    ) -> Option<HashMap<i64, i64>> {
        if snapshot.data.groups.iter().all(|group| group.id.is_none()) {
            return None;
        }
        let here = self.group_repo.get_all().await.unwrap_or_else(|e| {
            errors.push(format!("Could not read the client groups: {e}"));
            Vec::new()
        });
        let default_here = here
            .iter()
            .find(|group| group.is_default)
            .and_then(|g| g.id);
        let by_name: HashMap<&str, i64> = here
            .iter()
            .filter_map(|group| Some((group.name.as_ref(), group.id?)))
            .collect();
        Some(
            snapshot
                .data
                .groups
                .iter()
                .filter_map(|group| {
                    let id_here = if group.is_default {
                        default_here
                    } else {
                        by_name.get(group.name.as_str()).copied()
                    };
                    Some((group.id?, id_here?))
                })
                .collect(),
        )
    }

    /// Restores the config section. Returns whether it differs from the
    /// config that was running, or `None` when it was not restored.
    async fn apply_config(
        &self,
        snapshot: &BackupSnapshot,
        group_ids: &Option<HashMap<i64, i64>>,
        errors: &mut Vec<String>,
    ) -> Option<bool> {
        let Some(path) = &self.destination.path else {
            let msg = "No config file path available — config section not restored.";
            warn!(msg);
            errors.push(msg.to_string());
            return None;
        };

        // Merged and stored under the write guard: a writer that slipped in
        // between reading and storing would be overwritten.
        let _writer = self.destination.writer.lock().await;
        let mut config = self.destination.config.write().await;
        let mut new_config = config.clone();

        let sc = &snapshot.config;
        new_config.server.dns_port = sc.server.dns_port;
        new_config.server.web_port = sc.server.web_port;
        match ferrous_dns_domain::config::server::parse_bind_host(&sc.server.bind_address) {
            Ok(ip) => new_config.server.bind_address = ip,
            Err(e) => {
                errors.push(format!("Config section not restored: {e}"));
                return None;
            }
        }
        new_config.server.pihole_compat = sc.server.pihole_compat;
        new_config.server.web_tls.enabled = sc.server.tls_enabled;
        new_config.server.web_tls.tls_cert_path = sc.server.tls_cert_path.clone();
        new_config.server.web_tls.tls_key_path = sc.server.tls_key_path.clone();

        new_config.dns.upstream_servers = sc.dns.upstream_servers.clone();
        new_config.dns.cache_enabled = sc.dns.cache_enabled;
        if let Some(ref mode) = sc.dns.dnssec_mode {
            new_config.dns.dnssec_mode = mode.parse::<ferrous_dns_domain::DnssecMode>().ok();
        } else if let Some(enabled) = sc.dns.dnssec_enabled {
            // Back-compat: older snapshots carried a boolean.
            new_config.dns.dnssec_mode = Some(if enabled {
                ferrous_dns_domain::DnssecMode::Permissive
            } else {
                ferrous_dns_domain::DnssecMode::Off
            });
        }
        // A backup always names the mode, while a config that never set it
        // runs the default. When they agree, keep it written as it is here,
        // so restoring the same settings changes nothing.
        if new_config.dns.effective_dnssec_mode() == config.dns.effective_dnssec_mode() {
            new_config.dns.dnssec_mode = config.dns.dnssec_mode;
            new_config.dns.dnssec_enabled = config.dns.dnssec_enabled;
        }
        new_config.dns.cache_eviction_strategy = sc.dns.cache_eviction_strategy;
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
        new_config.dns.mdns_enabled = sc.dns.mdns_enabled;
        new_config.dns.local_domain = sc.dns.local_domain.clone();
        new_config.dns.local_dns_server = sc.dns.local_dns_server.clone();
        if let Some(pools) = &sc.dns.pools {
            let no_groups = HashMap::new();
            let mut restored = pools.clone();
            for pool in &mut restored {
                // Unlike a blocklist source's, a route is never taken as it
                // is: a backup with pools carries its group ids.
                match translate_group_ids(&pool.groups, group_ids.as_ref().unwrap_or(&no_groups)) {
                    Ok(ids) => pool.groups = ids,
                    Err(id) => {
                        errors.push(format!(
                            "Config section not restored: pool '{}' is routed for client group {id}, which the backup does not list",
                            pool.name
                        ));
                        return None;
                    }
                }
                // `validate` does not parse servers; the resolver would fail
                // on them at the next start.
                if let Some(e) = pool
                    .servers
                    .iter()
                    .find_map(|server| server.parse::<DnsProtocol>().err())
                {
                    errors.push(format!(
                        "Config section not restored: pool '{}': {e}",
                        pool.name
                    ));
                    return None;
                }
            }
            new_config.dns.pools = restored;
        }
        if let Some(rate_limit) = &sc.dns.rate_limit {
            new_config.dns.rate_limit = rate_limit.clone();
        }
        if let Some(malware) = &sc.dns.malware {
            new_config.dns.malware_detection_enabled = malware.enabled;
            new_config.dns.rebinding_protection_enabled = malware.rebinding_protection_enabled;
            new_config.dns.rebinding_allowlist = malware.rebinding_allowlist.clone();
            new_config.dns.tunneling_detection = malware.tunneling_detection.clone();
            new_config.dns.dga_detection = malware.dga_detection.clone();
            new_config.dns.nxdomain_hijack = malware.nxdomain_hijack.clone();
            new_config.dns.response_ip_filter = malware.response_ip_filter.clone();
        }

        new_config.blocking.enabled = sc.blocking.enabled;
        new_config.blocking.custom_blocked = sc.blocking.custom_blocked.clone();
        new_config.blocking.whitelist = sc.blocking.whitelist.clone();
        new_config.blocking.block_mode = sc.blocking.block_mode;
        new_config.blocking.block_ttl = sc.blocking.block_ttl;
        new_config.blocking.sinkhole_ipv4 = sc.blocking.sinkhole_ipv4;
        new_config.blocking.sinkhole_ipv6 = sc.blocking.sinkhole_ipv6;

        new_config.dns64.enabled = sc.dns64.enabled;
        if let Some(prefix) = sc.dns64.prefix.clone() {
            new_config.dns64.prefix = prefix;
        }

        new_config.logging.level = sc.logging.level.clone();

        new_config.auth.enabled = sc.auth.enabled;
        new_config.auth.session_ttl_hours = sc.auth.session_ttl_hours;
        new_config.auth.remember_me_days = sc.auth.remember_me_days;
        new_config.auth.login_rate_limit_attempts = sc.auth.login_rate_limit_attempts;
        new_config.auth.login_rate_limit_window_secs = sc.auth.login_rate_limit_window_secs;
        new_config.auth.webauthn.rp_id = sc.auth.webauthn_rp_id.clone();
        new_config.auth.webauthn.rp_origin = sc.auth.webauthn_rp_origin.clone();

        if let Err(e) = new_config.validate() {
            errors.push(format!("Config section not restored: {e}"));
            return None;
        }

        match self
            .destination
            .persistence
            .save_config_to_file(&new_config, path)
        {
            Ok(_) => {
                // Compared as the config handlers compare: none of these
                // settings applies before a restart.
                let changed =
                    serde_json::to_value(&*config).ok() != serde_json::to_value(&new_config).ok();
                *config = new_config;
                Some(changed)
            }
            Err(e) => {
                let msg = format!("Failed to persist config: {}", e);
                error!(error = %e, "Config persistence failed during import");
                errors.push(msg);
                None
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
        group_ids: &Option<HashMap<i64, i64>>,
        errors: &mut Vec<String>,
    ) -> (usize, usize) {
        let mut imported = 0usize;
        let mut skipped = 0usize;

        for source in &snapshot.data.blocklist_sources {
            // An older backup's ids are used as they are, as they always were.
            let source_group_ids = match group_ids {
                Some(here) => match translate_group_ids(&source.group_ids, here) {
                    Ok(ids) => ids,
                    Err(id) => {
                        skipped += 1;
                        errors.push(format!(
                            "Blocklist source '{}': client group {id} is not in the backup",
                            source.name
                        ));
                        continue;
                    }
                },
                None => source.group_ids.clone(),
            };
            match self
                .blocklist_source_creator
                .create_blocklist_source(
                    source.name.clone(),
                    source.url.clone(),
                    source_group_ids,
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
                let config = self.destination.config.read().await;
                // A and AAAA for the same name are distinct records, so the type is part of the key.
                let already_exists = config.dns.local_records.iter().any(|r| {
                    r.hostname == record.hostname
                        && r.domain.as_deref().unwrap_or("")
                            == record.domain.as_deref().unwrap_or("")
                        && r.record_type
                            .as_str()
                            .eq_ignore_ascii_case(&record.record_type)
                });
                if already_exists {
                    skipped += 1;
                    continue;
                }
            }

            let parsed = LocalDnsRecord::parse(
                record.hostname.clone(),
                record.domain.clone(),
                &record.ip,
                &record.record_type,
                record.ttl,
            );
            let created = match parsed {
                Ok(parsed) => self.local_record_creator.create_local_record(parsed).await,
                Err(e) => Err(e),
            };
            match created {
                Ok(()) => imported += 1,
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
