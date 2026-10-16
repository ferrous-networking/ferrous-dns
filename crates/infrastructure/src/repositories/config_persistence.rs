use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ferrous_dns_application::ports::ConfigFilePersistence;
use ferrous_dns_domain::{Config, DomainError};

pub struct TomlConfigFilePersistence;

impl ConfigFilePersistence for TomlConfigFilePersistence {
    fn load_config_from_file(&self, path: &str) -> Result<Config, DomainError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            DomainError::ConfigError(format!("Failed to read config file {path}: {e}"))
        })?;
        Config::from_toml_str(&contents)
    }

    fn save_config_to_file(&self, config: &Config, path: &str) -> Result<(), DomainError> {
        save_config_to_file(config, path)
    }
}

/// Updates an existing value preserving its inline comment (suffix decoration),
/// or inserts a new key if absent.
fn set_val(table: &mut toml_edit::Table, key: &str, new_val: impl Into<toml_edit::Value>) {
    let new_val = new_val.into();
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

/// The `f64` an `f32` reads as: widening its bits would write `3.8` as
/// `3.799999952316284`.
fn f32_value(value: f32) -> f64 {
    value.to_string().parse().unwrap_or(f64::from(value))
}

/// Gets a mutable reference to a top-level table, creating it if absent
/// (handles commented-out sections that `toml_edit` doesn't see).
fn ensure_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    key: &str,
) -> Result<&'a mut toml_edit::Table, DomainError> {
    if doc.get(key).is_none() {
        doc.insert(key, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    doc.get_mut(key)
        .and_then(|item| item.as_table_mut())
        .ok_or_else(|| DomainError::ConfigError(format!("Failed to ensure table '{key}'")))
}

/// Gets a mutable reference to a sub-table inside a parent table,
/// creating it if absent.
fn ensure_subtable<'a>(
    parent: &'a mut toml_edit::Table,
    key: &str,
) -> Result<&'a mut toml_edit::Table, DomainError> {
    if parent.get(key).is_none() {
        parent.insert(key, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(|item| item.as_table_mut())
        .ok_or_else(|| DomainError::ConfigError(format!("Failed to ensure subtable '{key}'")))
}

/// Reads and parses the file at `path`, applies `edit`, and writes the document back,
/// so every key and comment the edit doesn't touch survives the save.
fn edit_config_file(
    path: &str,
    edit: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<(), DomainError>,
) -> Result<(), DomainError> {
    let existing = std::fs::read_to_string(path)
        .map_err(|e| DomainError::ConfigError(format!("Failed to read config file {path}: {e}")))?;

    let mut doc = existing.parse::<toml_edit::DocumentMut>().map_err(|e| {
        DomainError::ConfigError(format!("Failed to parse config file {path}: {e}"))
    })?;

    edit(&mut doc)?;

    replace_file(Path::new(path), doc.to_string().as_bytes(), |from, to| {
        std::fs::rename(from, to)
    })
    .map_err(|e| DomainError::ConfigError(format!("Failed to write config file {path}: {e}")))
}

/// Replaces the file at `path` with `contents` so that a crash leaves either
/// the old or the new document, never a truncated one: the bytes go to a
/// synced sibling temp file that is renamed over the target. Where the target
/// cannot be replaced (a single-file bind mount, a read-only or unwritable
/// directory) or its owner cannot be kept, the file is rewritten in place.
fn replace_file(
    path: &Path,
    contents: &[u8],
    rename: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    // Renaming over a symlink would replace the link, not the file it names.
    let target = std::fs::canonicalize(path)?;
    let temp = temp_path_for(&target)?;

    match write_synced_temp(&temp, &target, contents) {
        Ok(Replacement::Atomic) => {}
        Ok(Replacement::InPlace) => {
            remove_temp(&temp);
            return overwrite_in_place(&target, contents);
        }
        Err(e) => {
            remove_temp(&temp);
            return if needs_in_place_write(&e) {
                overwrite_in_place(&target, contents)
            } else {
                Err(e)
            };
        }
    }

    if let Err(e) = rename(&temp, &target) {
        remove_temp(&temp);
        return if needs_in_place_write(&e) {
            overwrite_in_place(&target, contents)
        } else {
            Err(e)
        };
    }

    // The new document is already in place; a failed sync only delays its durability.
    if let Some(dir) = target.parent() {
        if let Err(e) = File::open(dir).and_then(|dir| dir.sync_all()) {
            tracing::warn!(path = %dir.display(), error = %e, "Failed to sync the config directory after saving");
        }
    }
    Ok(())
}

/// How the target is rewritten.
#[derive(Debug, PartialEq, Eq)]
enum Replacement {
    /// The synced temp file is renamed over the target.
    Atomic,
    /// The target is overwritten, keeping its inode, owner and group.
    InPlace,
}

/// A renamed temp file would hand the config to the daemon's user and group,
/// so it takes the target's `(uid, gid)` first; when `chown` cannot give it
/// them, e.g. for an unprivileged daemon, the target is rewritten in place.
#[cfg(unix)]
fn replacement_for(
    created: (u32, u32),
    target: (u32, u32),
    chown: impl FnOnce() -> io::Result<()>,
) -> Replacement {
    if created == target {
        return Replacement::Atomic;
    }
    match chown() {
        Ok(()) => Replacement::Atomic,
        Err(e) => {
            tracing::debug!(error = %e, "Cannot give the temporary config file the target's owner; rewriting in place");
            Replacement::InPlace
        }
    }
}

/// EBUSY / EXDEV: the target is a mount point (Docker single-file bind mount)
/// or lives on another filesystem. EACCES / EROFS on the temp file: the
/// directory is not writable although the file may be.
fn needs_in_place_write(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ResourceBusy
            | io::ErrorKind::CrossesDevices
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::ReadOnlyFilesystem
    )
}

fn temp_path_for(target: &Path) -> io::Result<PathBuf> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let name = target.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} does not name a file", target.display()),
        )
    })?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(target.with_file_name(temp_name))
}

fn write_synced_temp(temp: &Path, target: &Path, contents: &[u8]) -> io::Result<Replacement> {
    let metadata = std::fs::metadata(target)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    // Private until the target's mode is copied: the file holds the admin password hash.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let created = file.metadata()?;
        let (uid, gid) = (metadata.uid(), metadata.gid());
        let replacement = replacement_for((created.uid(), created.gid()), (uid, gid), || {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
        });
        if replacement == Replacement::InPlace {
            return Ok(Replacement::InPlace);
        }
    }
    // After the chown, which clears the setuid and setgid bits.
    file.set_permissions(metadata.permissions())?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(Replacement::Atomic)
}

fn overwrite_in_place(target: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).truncate(true).open(target)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn remove_temp(temp: &Path) {
    if let Err(e) = std::fs::remove_file(temp) {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::warn!(path = %temp.display(), error = %e, "Failed to remove temporary config file");
        }
    }
}

/// Bind hosts are written the way the sample config spells them, IPv6 bracketed.
fn bind_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

pub fn save_config_to_file(config: &Config, path: &str) -> Result<(), DomainError> {
    edit_config_file(path, |doc| write_config(doc, config))
}

fn write_config(doc: &mut toml_edit::DocumentMut, config: &Config) -> Result<(), DomainError> {
    {
        let t = ensure_table(doc, "server")?;
        set_val(t, "dns_port", config.server.dns_port as i64);
        set_val(t, "web_port", config.server.web_port as i64);
        set_val(t, "bind_address", bind_host(config.server.bind_address));
        t.remove("api_key");
        set_val(t, "pihole_compat", config.server.pihole_compat);
    }

    {
        let server = ensure_table(doc, "server")?;
        let wt = ensure_subtable(server, "web_tls")?;
        set_val(wt, "enabled", config.server.web_tls.enabled);
        set_val(
            wt,
            "tls_cert_path",
            config.server.web_tls.tls_cert_path.as_str(),
        );
        set_val(
            wt,
            "tls_key_path",
            config.server.web_tls.tls_key_path.as_str(),
        );
    }

    {
        let t = ensure_table(doc, "dns")?;
        set_val(
            t,
            "upstream_servers",
            str_array(&config.dns.upstream_servers),
        );
        set_val(t, "query_timeout", config.dns.query_timeout as i64);
        set_val(t, "cache_enabled", config.dns.cache_enabled);
        set_val(t, "cache_ttl", config.dns.cache_ttl as i64);
        set_val(t, "cache_min_ttl", config.dns.cache_min_ttl as i64);
        set_val(t, "cache_max_ttl", config.dns.cache_max_ttl as i64);
        set_val(
            t,
            "dnssec_mode",
            config.dns.effective_dnssec_mode().to_string(),
        );
        set_val(
            t,
            "default_strategy",
            config.dns.default_strategy.to_string(),
        );
        set_val(t, "cache_max_entries", config.dns.cache_max_entries as i64);
        set_val(
            t,
            "cache_eviction_strategy",
            config.dns.cache_eviction_strategy.as_str(),
        );
        set_val(
            t,
            "cache_optimistic_refresh",
            config.dns.cache_optimistic_refresh,
        );
        set_val(t, "cache_min_hit_rate", config.dns.cache_min_hit_rate);
        set_val(
            t,
            "cache_min_frequency",
            config.dns.cache_min_frequency as i64,
        );
        set_val(t, "cache_min_lfuk_score", config.dns.cache_min_lfuk_score);
        set_val(
            t,
            "cache_refresh_threshold",
            config.dns.cache_refresh_threshold,
        );
        // Retired key: drop it so files written by older versions stop carrying it.
        t.remove("cache_max_refresh_per_sec");
        set_val(
            t,
            "cache_lfuk_history_size",
            config.dns.cache_lfuk_history_size as i64,
        );
        set_val(
            t,
            "cache_batch_eviction_percentage",
            config.dns.cache_batch_eviction_percentage,
        );
        set_val(
            t,
            "cache_compaction_interval",
            config.dns.cache_compaction_interval as i64,
        );
        set_val(
            t,
            "cache_adaptive_thresholds",
            config.dns.cache_adaptive_thresholds,
        );
        set_val(
            t,
            "cache_access_window_secs",
            config.dns.cache_access_window_secs as i64,
        );
        set_val(t, "block_private_ptr", config.dns.block_private_ptr);
        set_val(t, "block_non_fqdn", config.dns.block_non_fqdn);
        set_val(t, "mdns_enabled", config.dns.mdns_enabled);
        set_val(
            t,
            "malware_detection_enabled",
            config.dns.malware_detection_enabled,
        );
        set_val(
            t,
            "rebinding_protection_enabled",
            config.dns.rebinding_protection_enabled,
        );
        set_val(
            t,
            "rebinding_allowlist",
            str_array(&config.dns.rebinding_allowlist),
        );
        match &config.dns.local_domain {
            Some(domain) => set_val(t, "local_domain", domain.as_str()),
            None => {
                t.remove("local_domain");
            }
        }
        match &config.dns.local_dns_server {
            Some(server) => set_val(t, "local_dns_server", server.as_str()),
            None => {
                t.remove("local_dns_server");
            }
        }
    }

    {
        let dns = ensure_table(doc, "dns")?;
        dns.remove("pools");
        if !config.dns.pools.is_empty() {
            let mut aot = toml_edit::ArrayOfTables::new();
            for pool in &config.dns.pools {
                let mut table = toml_edit::Table::new();
                table.insert("name", toml_edit::value(pool.name.as_str()));
                table.insert("strategy", toml_edit::value(pool.strategy.to_string()));
                table.insert("priority", toml_edit::value(pool.priority as i64));
                table.insert("servers", toml_edit::Item::Value(str_array(&pool.servers)));
                if let Some(weight) = pool.weight {
                    table.insert("weight", toml_edit::value(weight as i64));
                }
                if pool.is_conditional() {
                    table.insert("domains", toml_edit::Item::Value(str_array(&pool.domains)));
                    if !pool.groups.is_empty() {
                        let groups: toml_edit::Array = pool.groups.iter().copied().collect();
                        table.insert("groups", toml_edit::Item::Value(groups.into()));
                    }
                    if pool.internal {
                        table.insert("internal", toml_edit::value(true));
                    }
                }
                aot.push(table);
            }
            dns.insert("pools", toml_edit::Item::ArrayOfTables(aot));
        }
    }

    {
        let dns = ensure_table(doc, "dns")?;
        let hc = ensure_subtable(dns, "health_check")?;
        set_val(hc, "interval", config.dns.health_check.interval as i64);
        set_val(hc, "timeout", config.dns.health_check.timeout as i64);
        set_val(
            hc,
            "failure_threshold",
            config.dns.health_check.failure_threshold as i64,
        );
        set_val(
            hc,
            "success_threshold",
            config.dns.health_check.success_threshold as i64,
        );
    }

    {
        let dns = ensure_table(doc, "dns")?;
        let rl = ensure_subtable(dns, "rate_limit")?;
        set_val(rl, "enabled", config.dns.rate_limit.enabled);
        set_val(
            rl,
            "queries_per_second",
            config.dns.rate_limit.queries_per_second as i64,
        );
        set_val(rl, "burst_size", config.dns.rate_limit.burst_size as i64);
        set_val(
            rl,
            "ipv4_prefix_len",
            config.dns.rate_limit.ipv4_prefix_len as i64,
        );
        set_val(
            rl,
            "ipv6_prefix_len",
            config.dns.rate_limit.ipv6_prefix_len as i64,
        );
        set_val(
            rl,
            "nxdomain_per_second",
            config.dns.rate_limit.nxdomain_per_second as i64,
        );
        set_val(rl, "slip_ratio", config.dns.rate_limit.slip_ratio as i64);
        set_val(rl, "dry_run", config.dns.rate_limit.dry_run);
        set_val(
            rl,
            "stale_entry_ttl_secs",
            config.dns.rate_limit.stale_entry_ttl_secs as i64,
        );
        set_val(
            rl,
            "tcp_max_connections_per_ip",
            config.dns.rate_limit.tcp_max_connections_per_ip as i64,
        );
        set_val(
            rl,
            "dot_max_connections_per_ip",
            config.dns.rate_limit.dot_max_connections_per_ip as i64,
        );
        set_val(
            rl,
            "doq_max_connections_per_ip",
            config.dns.rate_limit.doq_max_connections_per_ip as i64,
        );
        set_val(rl, "whitelist", str_array(&config.dns.rate_limit.whitelist));
    }

    {
        let td = &config.dns.tunneling_detection;
        let dns = ensure_table(doc, "dns")?;
        let t = ensure_subtable(dns, "tunneling_detection")?;
        set_val(t, "enabled", td.enabled);
        set_val(t, "action", td.action.as_str());
        set_val(t, "max_fqdn_length", td.max_fqdn_length as i64);
        set_val(t, "max_label_length", td.max_label_length as i64);
        set_val(t, "block_null_queries", td.block_null_queries);
        set_val(t, "entropy_threshold", f32_value(td.entropy_threshold));
        set_val(t, "query_rate_per_apex", td.query_rate_per_apex as i64);
        set_val(
            t,
            "unique_subdomain_threshold",
            td.unique_subdomain_threshold as i64,
        );
        set_val(
            t,
            "txt_proportion_threshold",
            f32_value(td.txt_proportion_threshold),
        );
        set_val(
            t,
            "nxdomain_ratio_threshold",
            f32_value(td.nxdomain_ratio_threshold),
        );
        set_val(
            t,
            "confidence_threshold",
            f32_value(td.confidence_threshold),
        );
        set_val(t, "stale_entry_ttl_secs", td.stale_entry_ttl_secs as i64);
        set_val(t, "domain_whitelist", str_array(&td.domain_whitelist));
        set_val(t, "client_whitelist", str_array(&td.client_whitelist));
    }

    {
        let dga = &config.dns.dga_detection;
        let dns = ensure_table(doc, "dns")?;
        let t = ensure_subtable(dns, "dga_detection")?;
        set_val(t, "enabled", dga.enabled);
        set_val(t, "action", dga.action.as_str());
        set_val(
            t,
            "hot_path_confidence_threshold",
            f32_value(dga.hot_path_confidence_threshold),
        );
        set_val(
            t,
            "sld_entropy_threshold",
            f32_value(dga.sld_entropy_threshold),
        );
        set_val(t, "sld_max_length", dga.sld_max_length as i64);
        set_val(
            t,
            "consonant_ratio_threshold",
            f32_value(dga.consonant_ratio_threshold),
        );
        set_val(
            t,
            "digit_ratio_threshold",
            f32_value(dga.digit_ratio_threshold),
        );
        set_val(
            t,
            "ngram_score_threshold",
            f32_value(dga.ngram_score_threshold),
        );
        set_val(t, "dga_rate_per_client", dga.dga_rate_per_client as i64);
        set_val(
            t,
            "confidence_threshold",
            f32_value(dga.confidence_threshold),
        );
        set_val(t, "stale_entry_ttl_secs", dga.stale_entry_ttl_secs as i64);
        set_val(t, "domain_whitelist", str_array(&dga.domain_whitelist));
        set_val(t, "client_whitelist", str_array(&dga.client_whitelist));
    }

    {
        let hijack = &config.dns.nxdomain_hijack;
        let dns = ensure_table(doc, "dns")?;
        let t = ensure_subtable(dns, "nxdomain_hijack")?;
        set_val(t, "enabled", hijack.enabled);
        set_val(t, "action", hijack.action.as_str());
        set_val(t, "probe_interval_secs", hijack.probe_interval_secs as i64);
        set_val(t, "probe_timeout_ms", hijack.probe_timeout_ms as i64);
        set_val(t, "probes_per_round", i64::from(hijack.probes_per_round));
        set_val(t, "hijack_ip_ttl_secs", hijack.hijack_ip_ttl_secs as i64);
    }

    {
        let filter = &config.dns.response_ip_filter;
        let dns = ensure_table(doc, "dns")?;
        let t = ensure_subtable(dns, "response_ip_filter")?;
        set_val(t, "enabled", filter.enabled);
        set_val(t, "action", filter.action.as_str());
        set_val(t, "ip_list_urls", str_array(&filter.ip_list_urls));
        set_val(
            t,
            "refresh_interval_secs",
            filter.refresh_interval_secs as i64,
        );
        set_val(t, "ip_ttl_secs", filter.ip_ttl_secs as i64);
    }

    {
        let t = ensure_table(doc, "blocking")?;
        set_val(t, "enabled", config.blocking.enabled);
        set_val(
            t,
            "custom_blocked",
            str_array(&config.blocking.custom_blocked),
        );
        set_val(t, "whitelist", str_array(&config.blocking.whitelist));
        set_val(t, "block_mode", config.blocking.block_mode.as_str());
        set_val(t, "block_ttl", config.blocking.block_ttl as i64);
        // Optional custom sinkhole targets: write when set, drop the key when
        // cleared so the file reflects "no custom target" (falls back to null).
        match config.blocking.sinkhole_ipv4 {
            Some(addr) => set_val(t, "sinkhole_ipv4", addr.to_string()),
            None => {
                t.remove("sinkhole_ipv4");
            }
        }
        match config.blocking.sinkhole_ipv6 {
            Some(addr) => set_val(t, "sinkhole_ipv6", addr.to_string()),
            None => {
                t.remove("sinkhole_ipv6");
            }
        }
    }

    {
        let t = ensure_table(doc, "dns64")?;
        set_val(t, "enabled", config.dns64.enabled);
        set_val(t, "prefix", config.dns64.prefix.as_str());
    }

    {
        let t = ensure_table(doc, "logging")?;
        set_val(t, "level", config.logging.level.as_str());
    }

    {
        let t = ensure_table(doc, "database")?;
        set_val(t, "path", config.database.path.as_str());
        set_val(t, "log_queries", config.database.log_queries);
        set_val(
            t,
            "queries_log_stored",
            config.database.queries_log_stored as i64,
        );
        set_val(
            t,
            "client_tracking_interval",
            config.database.client_tracking_interval as i64,
        );
        set_val(
            t,
            "query_log_channel_capacity",
            config.database.query_log_channel_capacity as i64,
        );
        set_val(
            t,
            "query_log_max_batch_size",
            config.database.query_log_max_batch_size as i64,
        );
        set_val(
            t,
            "query_log_flush_interval_ms",
            config.database.query_log_flush_interval_ms as i64,
        );
        set_val(
            t,
            "query_log_sample_rate",
            config.database.query_log_sample_rate as i64,
        );
        set_val(
            t,
            "client_channel_capacity",
            config.database.client_channel_capacity as i64,
        );
        set_val(
            t,
            "write_pool_max_connections",
            config.database.write_pool_max_connections as i64,
        );
        set_val(
            t,
            "read_pool_max_connections",
            config.database.read_pool_max_connections as i64,
        );
        set_val(
            t,
            "write_busy_timeout_secs",
            config.database.write_busy_timeout_secs as i64,
        );
        set_val(
            t,
            "read_busy_timeout_secs",
            config.database.read_busy_timeout_secs as i64,
        );
        set_val(
            t,
            "read_acquire_timeout_secs",
            config.database.read_acquire_timeout_secs as i64,
        );
        set_val(
            t,
            "wal_autocheckpoint",
            config.database.wal_autocheckpoint as i64,
        );
    }

    {
        let t = ensure_table(doc, "auth")?;
        set_val(t, "enabled", config.auth.enabled);
        set_val(t, "session_ttl_hours", config.auth.session_ttl_hours as i64);
        set_val(t, "remember_me_days", config.auth.remember_me_days as i64);
        set_val(
            t,
            "login_rate_limit_attempts",
            config.auth.login_rate_limit_attempts as i64,
        );
        set_val(
            t,
            "login_rate_limit_window_secs",
            config.auth.login_rate_limit_window_secs as i64,
        );
        set_val(t, "totp_issuer", config.auth.totp_issuer.as_str());
        set_val(
            t,
            "mfa_challenge_ttl_secs",
            config.auth.mfa_challenge_ttl_secs,
        );
    }

    {
        let auth = ensure_table(doc, "auth")?;
        let admin = ensure_subtable(auth, "admin")?;
        set_val(admin, "username", config.auth.admin.username.as_str());
        match &config.auth.admin.password_hash {
            Some(hash) => set_val(admin, "password_hash", hash.as_str()),
            None => {
                admin.remove("password_hash");
            }
        }
    }

    {
        let auth = ensure_table(doc, "auth")?;
        let webauthn = ensure_subtable(auth, "webauthn")?;
        set_val(webauthn, "rp_id", config.auth.webauthn.rp_id.as_str());
        set_val(
            webauthn,
            "rp_origin",
            config.auth.webauthn.rp_origin.as_str(),
        );
    }

    Ok(())
}

pub fn save_local_records_to_file(config: &Config, path: &str) -> Result<(), DomainError> {
    edit_config_file(path, |doc| write_local_records(doc, config))
}

fn write_local_records(
    doc: &mut toml_edit::DocumentMut,
    config: &Config,
) -> Result<(), DomainError> {
    let dns = ensure_table(doc, "dns")?;
    if config.dns.local_records.is_empty() {
        dns.remove("local_records");
    } else {
        let mut aot = toml_edit::ArrayOfTables::new();
        for record in &config.dns.local_records {
            let mut table = toml_edit::Table::new();
            table.insert("hostname", toml_edit::value(record.hostname.as_str()));
            if let Some(ref domain) = record.domain {
                table.insert("domain", toml_edit::value(domain.as_str()));
            }
            table.insert("ip", toml_edit::value(record.ip.to_string()));
            table.insert("record_type", toml_edit::value(record.record_type.as_str()));
            if let Some(ttl) = record.ttl {
                table.insert("ttl", toml_edit::value(ttl as i64));
            }
            aot.push(table);
        }
        dns.insert("local_records", toml_edit::Item::ArrayOfTables(aot));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_with(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    fn only_entry_is_the_config(dir: &tempfile::TempDir) -> bool {
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names == ["config.toml"]
    }

    #[test]
    fn a_rename_refused_by_a_bind_mount_falls_back_to_an_in_place_write() {
        for kind in [io::ErrorKind::ResourceBusy, io::ErrorKind::CrossesDevices] {
            let (dir, path) = file_with("old = 1\n");

            replace_file(&path, b"new = 2\n", |_, _| Err(io::Error::from(kind))).unwrap();

            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "new = 2\n",
                "{kind:?}"
            );
            assert!(
                only_entry_is_the_config(&dir),
                "{kind:?}: temp file left behind"
            );
        }
    }

    #[test]
    fn any_other_rename_failure_is_reported_and_keeps_the_original() {
        let (dir, path) = file_with("old = 1\n");

        let err = replace_file(&path, b"new = 2\n", |_, _| {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old = 1\n");
        assert!(only_entry_is_the_config(&dir), "temp file left behind");
    }

    #[test]
    fn a_failed_directory_sync_after_the_rename_still_reports_the_save() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("config");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "old = 1\n").unwrap();
        let moved = root.path().join("moved");

        // Moving the directory away once the file is renamed makes its sync fail.
        replace_file(&path, b"new = 2\n", |from, to| {
            std::fs::rename(from, to)?;
            std::fs::rename(&dir, &moved)
        })
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(moved.join("config.toml")).unwrap(),
            "new = 2\n"
        );
    }

    #[cfg(unix)]
    fn refused() -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    #[cfg(unix)]
    #[test]
    fn a_temp_file_already_owned_like_the_target_is_renamed_without_a_chown() {
        assert_eq!(
            replacement_for((1000, 1000), (1000, 1000), refused),
            Replacement::Atomic
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_temp_file_given_the_target_owner_is_renamed() {
        assert_eq!(
            replacement_for((0, 0), (1000, 100), || Ok(())),
            Replacement::Atomic
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_target_owner_the_daemon_cannot_hand_over_is_rewritten_in_place() {
        for target in [(0, 1000), (1000, 0)] {
            assert_eq!(
                replacement_for((1000, 1000), target, refused),
                Replacement::InPlace,
                "{target:?}"
            );
        }
    }

    #[test]
    fn test_set_val_preserves_inline_comment() {
        let input = r#"
[server]
dns_port = 53  # UDP port
"#;
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let server = doc.get_mut("server").unwrap().as_table_mut().unwrap();

        set_val(server, "dns_port", 5353i64);

        let output = doc.to_string();
        assert!(output.contains("5353"));
        assert!(output.contains("# UDP port"));
    }

    #[test]
    fn test_set_val_inserts_missing_key() {
        let input = r#"
[server]
dns_port = 53
"#;
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let server = doc.get_mut("server").unwrap().as_table_mut().unwrap();

        set_val(server, "new_key", "new_value");

        let output = doc.to_string();
        assert!(output.contains("new_key = \"new_value\""));
    }

    #[test]
    fn test_ensure_table_creates_missing_section() {
        let input = "# empty config\n";
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();

        let table = ensure_table(&mut doc, "new_section").unwrap();
        table.insert("key", toml_edit::value("val"));

        let output = doc.to_string();
        assert!(output.contains("[new_section]"));
        assert!(output.contains("key = \"val\""));
    }

    #[test]
    fn test_ensure_subtable_creates_nested_section() {
        let input = r#"
[dns]
cache_enabled = true
"#;
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let dns = ensure_table(&mut doc, "dns").unwrap();
        let sub = ensure_subtable(dns, "nested").unwrap();
        sub.insert("value", toml_edit::value(42i64));

        let output = doc.to_string();
        assert!(output.contains("[dns.nested]") && output.contains("value = 42"));
    }
}
