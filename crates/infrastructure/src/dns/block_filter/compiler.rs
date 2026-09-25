use super::block_index::{
    AllowlistIndex, BlockIndex, RegexRule, SourceBitSet, SourceDescriptor, SourceMeta,
    MANUAL_SOURCE_BIT,
};
use super::download::ListDownloader;
use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use fancy_regex::Regex;
use ferrous_dns_domain::{DomainAction, DomainError};
use futures::{stream, StreamExt};
use rayon::prelude::*;
use rustc_hash::FxBuildHasher;
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use tracing::{info, warn};

/// `None` when the dedicated pool cannot be built: the build then runs on
/// rayon's global pool instead.
static BLOCKLIST_BUILD_POOL: LazyLock<Option<rayon::ThreadPool>> = LazyLock::new(|| {
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let num_threads = (parallelism / 2).clamp(1, 4);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .inspect_err(|e| {
            warn!(error = %e, "Blocklist build pool unavailable; using the global rayon pool");
        })
        .ok()
});

const MAX_CONCURRENT_DOWNLOADS: usize = 4;

/// The last successful download of each list, keyed by URL.
pub(super) type HeldLists = HashMap<String, Arc<str>>;

/// Whether a build downloads the lists it already holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListFetch {
    /// Download only the lists not held yet, such as a newly added source.
    ReuseHeld,
    /// Download every list again, as a sync does.
    Redownload,
}

#[derive(Debug)]
pub enum ParsedEntry {
    Exact(String),
    Wildcard(String),
    Pattern(String),
    /// Adblock `||domain^`: the domain itself AND every subdomain of it.
    /// Compiles to an exact entry plus a suffix rule.
    DomainAndSubdomains(String),
}

fn parse_list_line(line: &str) -> Option<ParsedEntry> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }

    if line.starts_with("@@") {
        return None;
    }

    if line.starts_with('/') && line.ends_with('/') && line.len() > 2 {
        return Some(ParsedEntry::Pattern(line[1..line.len() - 1].to_lowercase()));
    }

    if line.starts_with("||") {
        let inner = line.strip_prefix("||").unwrap_or("");
        let domain = match inner.find('^') {
            Some(pos) => &inner[..pos],
            None => inner,
        };
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() || !domain.contains('.') {
            return None;
        }
        if domain.starts_with("*.") {
            return Some(ParsedEntry::Wildcard(domain));
        }
        return Some(ParsedEntry::DomainAndSubdomains(domain));
    }

    if line.starts_with("*.") {
        let pattern = line.to_ascii_lowercase();
        return Some(ParsedEntry::Wildcard(pattern));
    }

    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() >= 2 {
        let addr = parts[0];
        let domain = parts[1];

        let is_hosts_addr = matches!(addr, "0.0.0.0" | "127.0.0.1" | "::" | "::1");
        if is_hosts_addr {
            if matches!(
                domain,
                "localhost" | "0.0.0.0" | "broadcasthost" | "ip6-localhost" | "ip6-loopback"
            ) {
                return None;
            }
            if !domain.contains('.') {
                return None;
            }
            return Some(ParsedEntry::Exact(domain.to_ascii_lowercase()));
        }
    }

    if parts.len() == 1 && parts[0].contains('.') {
        return Some(ParsedEntry::Exact(parts[0].to_ascii_lowercase()));
    }

    None
}

pub fn parse_list_text(text: &str) -> Vec<ParsedEntry> {
    text.lines().filter_map(parse_list_line).collect()
}

struct SourceLoad {
    sources: Vec<SourceMeta>,
    url_tasks: Vec<(u8, String)>,
    all_group_ids: Vec<i64>,
    /// Reverse map from source bit index (0..=63) to the owning source.
    bit_to_source: Vec<Option<SourceDescriptor>>,
}

async fn load_sources(pool: &SqlitePool) -> Result<SourceLoad, DomainError> {
    // Bits 0..=62 go to downloaded sources; bit 63 is the manual blocklist.
    let source_rows =
        sqlx::query("SELECT id, name, url FROM blocklist_sources WHERE enabled = 1 ORDER BY id")
            .fetch_all(pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    if source_rows.len() > 63 {
        warn!(
            count = source_rows.len(),
            "More than 63 blocklist sources; only the first 63 will be used"
        );
    }

    let id_to_bit: HashMap<i64, u8> = source_rows
        .iter()
        .take(63)
        .enumerate()
        .map(|(idx, row)| (row.get::<i64, _>("id"), idx as u8))
        .collect();

    // Length 64: indices 0..=62 are downloaded sources, index 63 is the manual list.
    let mut bit_to_source: Vec<Option<SourceDescriptor>> = vec![None; 64];
    for (idx, row) in source_rows.iter().take(63).enumerate() {
        bit_to_source[idx] = Some(SourceDescriptor {
            id: row.get::<i64, _>("id"),
            name: row.get::<String, _>("name"),
        });
    }

    // Every (source, group) assignment of an enabled source.
    let assignment_rows = sqlx::query(
        "SELECT bsg.source_id, bsg.group_id
         FROM blocklist_source_groups bsg
         JOIN blocklist_sources bs ON bs.id = bsg.source_id
         WHERE bs.enabled = 1",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    // One entry per assignment: the same bit can serve several groups.
    let sources: Vec<SourceMeta> = assignment_rows
        .iter()
        .filter_map(|row| {
            let source_id: i64 = row.get("source_id");
            let group_id: i64 = row.get("group_id");
            id_to_bit
                .get(&source_id)
                .map(|&bit| SourceMeta { group_id, bit })
        })
        .collect();

    let url_tasks: Vec<(u8, String)> = source_rows
        .iter()
        .take(63)
        .enumerate()
        .filter_map(|(idx, row)| {
            let url: Option<String> = row.get("url");
            url.map(|u| (idx as u8, u))
        })
        .collect();

    // Load ALL group IDs so every group gets a mask entry (even if no blocklists)
    let all_group_ids: Vec<i64> = sqlx::query("SELECT id FROM groups")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?
        .iter()
        .map(|row| row.get::<i64, _>("id"))
        .collect();

    Ok(SourceLoad {
        sources,
        url_tasks,
        all_group_ids,
        bit_to_source,
    })
}

fn build_group_masks(sources: &[SourceMeta], all_group_ids: &[i64]) -> HashMap<i64, SourceBitSet> {
    // Pre-populate ALL groups with MANUAL_SOURCE_BIT only (global manual blocklist).
    // Each group is independent — no inheritance from default.
    let mut group_masks: HashMap<i64, SourceBitSet> = HashMap::with_capacity(all_group_ids.len());
    for &gid in all_group_ids {
        group_masks.insert(gid, MANUAL_SOURCE_BIT);
    }

    // Add each source's bit ONLY to its assigned group
    for src in sources {
        let entry = group_masks.entry(src.group_id).or_insert(MANUAL_SOURCE_BIT);
        *entry |= 1u64 << src.bit;
    }

    group_masks
}

/// Puts the text of every URL into `next`: the copy in `held`, unless `fetch`
/// asks for a new download or no copy is held. A failed download keeps the
/// held copy, so a flaky server cannot unblock a whole list. Returns the URLs
/// downloaded by this call.
async fn fetch_lists(
    urls: HashSet<String>,
    downloader: &ListDownloader,
    held: &HeldLists,
    fetch: ListFetch,
    table: SourceTable,
    next: &mut HeldLists,
) -> HashSet<String> {
    let mut to_download = Vec::new();
    for url in urls {
        match held.get(&url) {
            Some(text) if fetch == ListFetch::ReuseHeld => {
                next.insert(url, Arc::clone(text));
            }
            _ => to_download.push(url),
        }
    }

    let results: Vec<_> = stream::iter(to_download)
        .map(|url| async move {
            let result = downloader.fetch(&url).await;
            (url, result)
        })
        .buffer_unordered(MAX_CONCURRENT_DOWNLOADS)
        .collect()
        .await;

    let kind = table.kind();
    let mut downloaded = HashSet::new();
    for (url, result) in results {
        match (result, held.get(&url)) {
            (Ok(text), _) => {
                info!(url = %url, "Fetched {kind} source");
                next.insert(url.clone(), Arc::from(text));
                downloaded.insert(url);
            }
            (Err(e), Some(text)) => {
                warn!(url = %url, error = %e, "Failed to fetch {kind} source; keeping the previous download");
                next.insert(url, Arc::clone(text));
            }
            (Err(e), None) => warn!(url = %url, error = %e, "Failed to fetch {kind} source"),
        }
    }
    downloaded
}

/// Source table stamped by [`mark_sources_synced`]. An enum because the
/// table name is spliced into the statement rather than bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceTable {
    Blocklist,
    Whitelist,
}

impl SourceTable {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blocklist => "blocklist_sources",
            Self::Whitelist => "whitelist_sources",
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::Blocklist => "blocklist",
            Self::Whitelist => "whitelist",
        }
    }
}

/// Records `at` as the last successful sync for `ids` in `table`.
pub async fn mark_sources_synced(
    pool: &SqlitePool,
    table: SourceTable,
    ids: &[i64],
    at: &str,
) -> Result<(), DomainError> {
    if ids.is_empty() {
        return Ok(());
    }

    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "UPDATE {} SET last_synced_at = ? WHERE id IN ({placeholders})",
        table.as_str()
    );

    let mut query = sqlx::query(&sql).bind(at);
    for id in ids {
        query = query.bind(id);
    }

    query
        .execute(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    Ok(())
}

struct ManagedDomainEntry {
    domain: String,
    action: DomainAction,
    group_id: i64,
}

struct BlockIndexData {
    total_exact: usize,
    total_wildcard: usize,
    bloom: AtomicBloom,
    exact: DashMap<CompactString, SourceBitSet, FxBuildHasher>,
    wildcard: SuffixTrie,
    patterns: Vec<(AhoCorasick, SourceBitSet)>,
}

fn build_exact_and_wildcard(
    manual_domains: &[String],
    source_entries: &HashMap<u8, Vec<ParsedEntry>>,
) -> BlockIndexData {
    let exact_count: usize = manual_domains.len()
        + source_entries
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|e| {
                matches!(
                    e,
                    ParsedEntry::Exact(_) | ParsedEntry::DomainAndSubdomains(_)
                )
            })
            .count();

    let bloom_capacity = (exact_count + 100).max(1000);
    let bloom = AtomicBloom::new(bloom_capacity, 0.001);
    let exact: DashMap<CompactString, SourceBitSet, FxBuildHasher> =
        DashMap::with_capacity_and_hasher(exact_count, FxBuildHasher);
    let mut wildcard = SuffixTrie::default();
    let mut patterns_by_source: HashMap<u8, Vec<String>> = HashMap::new();

    for domain in manual_domains {
        // A manually added `*.example.com` is a suffix rule, not a literal
        // name — inserting it into `exact` would make it match nothing.
        if domain.starts_with("*.") {
            wildcard.insert_wildcard(domain, MANUAL_SOURCE_BIT);
            continue;
        }
        bloom.set(domain);
        exact
            .entry(CompactString::new(domain))
            .and_modify(|bits| *bits |= MANUAL_SOURCE_BIT)
            .or_insert(MANUAL_SOURCE_BIT);
    }

    source_entries.par_iter().for_each(|(bit, entries)| {
        let source_bit: SourceBitSet = 1u64 << *bit;
        for entry in entries {
            if let ParsedEntry::Exact(domain) | ParsedEntry::DomainAndSubdomains(domain) = entry {
                bloom.set(domain);
                exact
                    .entry(CompactString::new(domain))
                    .and_modify(|bits| *bits |= source_bit)
                    .or_insert(source_bit);
            }
        }
    });

    for (bit, entries) in source_entries {
        let source_bit: SourceBitSet = 1u64 << *bit;
        for entry in entries {
            match entry {
                ParsedEntry::Exact(_) => {}
                ParsedEntry::Wildcard(pattern) => {
                    wildcard.insert_wildcard(pattern, source_bit);
                }
                // The exact half was inserted above; this covers the subdomains.
                // `insert_wildcard` keys on the bare suffix, and `lookup` only
                // reports proper suffixes, so this cannot double-count the apex.
                ParsedEntry::DomainAndSubdomains(domain) => {
                    wildcard.insert_wildcard(domain, source_bit);
                }
                ParsedEntry::Pattern(pat) => {
                    patterns_by_source
                        .entry(*bit)
                        .or_default()
                        .push(pat.clone());
                }
            }
        }
    }

    let mut patterns: Vec<(AhoCorasick, SourceBitSet)> = Vec::new();
    for (bit, pats) in patterns_by_source {
        if pats.is_empty() {
            continue;
        }
        match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&pats)
        {
            Ok(ac) => {
                patterns.push((ac, 1u64 << bit));
            }
            Err(e) => {
                warn!(source_bit = bit, error = %e, "Failed to compile Aho-Corasick patterns");
            }
        }
    }

    let total_wildcard = wildcard.len();

    BlockIndexData {
        total_exact: exact.len(),
        total_wildcard,
        bloom,
        exact,
        wildcard,
        patterns,
    }
}

struct RegexFilterMaps {
    block_patterns: HashMap<i64, Vec<RegexRule>>,
    allow_patterns: HashMap<i64, Vec<RegexRule>>,
}

fn build_regex_filters(rows: &[SqliteRow]) -> RegexFilterMaps {
    let mut block_patterns: HashMap<i64, Vec<RegexRule>> = HashMap::new();
    let mut allow_patterns: HashMap<i64, Vec<RegexRule>> = HashMap::new();

    for row in rows {
        let pattern: String = row.get("pattern");
        let Some(action) = parse_action(row) else {
            continue;
        };

        match Regex::new(&format!("(?i){}", pattern)) {
            Ok(regex) => {
                let rule = RegexRule {
                    id: row.get("id"),
                    name: row.get("name"),
                    regex,
                };
                let patterns = match action {
                    DomainAction::Deny => &mut block_patterns,
                    DomainAction::Allow => &mut allow_patterns,
                };
                patterns.entry(row.get("group_id")).or_default().push(rule);
            }
            Err(e) => {
                warn!(
                    pattern = %pattern,
                    error = %e,
                    "Skipping invalid regex filter pattern during compilation"
                );
            }
        }
    }

    info!(
        block_regex = block_patterns.values().map(|v| v.len()).sum::<usize>(),
        allow_regex = allow_patterns.values().map(|v| v.len()).sum::<usize>(),
        "Loaded regex filter patterns"
    );

    RegexFilterMaps {
        block_patterns,
        allow_patterns,
    }
}

/// The row's `action` column; `None`, logged, for a value no rule can carry.
fn parse_action(row: &SqliteRow) -> Option<DomainAction> {
    let action: String = row.get("action");
    let parsed = action.parse().ok();
    if parsed.is_none() {
        warn!(action = %action, "Skipping rule with an unknown action");
    }
    parsed
}

pub(super) async fn compile_block_index(
    pool: &SqlitePool,
    downloader: &ListDownloader,
    held: &mut HeldLists,
    fetch: ListFetch,
) -> Result<BlockIndex, DomainError> {
    let SourceLoad {
        sources,
        url_tasks,
        all_group_ids,
        bit_to_source,
    } = load_sources(pool).await?;
    // Only lists still in use carry over, so a removed source releases its text.
    let mut next = HeldLists::new();
    let downloaded = fetch_lists(
        url_tasks.iter().map(|(_, url)| url.clone()).collect(),
        downloader,
        held,
        fetch,
        SourceTable::Blocklist,
        &mut next,
    )
    .await;
    let source_texts: HashMap<u8, Arc<str>> = url_tasks
        .iter()
        .filter_map(|(bit, url)| next.get(url).map(|text| (*bit, Arc::clone(text))))
        .collect();

    // Only a download made now advances the timestamp; a reused or kept copy
    // retains the previous one as a staleness signal.
    let synced_source_ids: Vec<i64> = url_tasks
        .iter()
        .filter(|(_, url)| downloaded.contains(url))
        .filter_map(|(bit, _)| bit_to_source[*bit as usize].as_ref().map(|s| s.id))
        .collect();
    if let Err(e) = mark_sources_synced(
        pool,
        SourceTable::Blocklist,
        &synced_source_ids,
        &chrono::Utc::now().to_rfc3339(),
    )
    .await
    {
        warn!(error = %e, "Failed to record blocklist source sync timestamps");
    }

    let manual_rows = sqlx::query("SELECT domain FROM blocklist")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;
    let managed_rows =
        sqlx::query("SELECT domain, action, group_id FROM managed_domains WHERE enabled = 1")
            .fetch_all(pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;
    let regex_rows = sqlx::query(
        "SELECT id, name, pattern, action, group_id FROM regex_filters WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?;
    let allowlist_load = load_allowlists(pool, downloader, held, fetch, &mut next).await?;
    *held = next;

    let build = move || {
        let group_masks = build_group_masks(&sources, &all_group_ids);
        let source_entries = source_texts
            .into_par_iter()
            .map(|(bit, text)| (bit, parse_list_text(&text)))
            .collect();
        let manual_domains: Vec<String> = manual_rows
            .iter()
            .map(|row| row.get::<String, _>("domain").to_ascii_lowercase())
            .collect();
        let managed_entries: Vec<ManagedDomainEntry> = managed_rows
            .iter()
            .filter_map(|row| {
                Some(ManagedDomainEntry {
                    domain: row.get::<String, _>("domain").to_ascii_lowercase(),
                    action: parse_action(row)?,
                    group_id: row.get("group_id"),
                })
            })
            .collect();
        let regex_filters = build_regex_filters(&regex_rows);
        let BlockIndexData {
            total_exact,
            total_wildcard,
            bloom,
            exact,
            wildcard,
            patterns,
        } = build_exact_and_wildcard(&manual_domains, &source_entries);

        let mut managed_denies: HashMap<i64, DashSet<CompactString, FxBuildHasher>> =
            HashMap::new();
        let mut managed_deny_wildcards: HashMap<i64, SuffixTrie> = HashMap::new();
        for entry in &managed_entries {
            match entry.action {
                DomainAction::Deny if entry.domain.starts_with("*.") => {
                    managed_deny_wildcards
                        .entry(entry.group_id)
                        .or_default()
                        .insert_wildcard(&entry.domain, 1u64);
                }
                DomainAction::Deny => {
                    managed_denies
                        .entry(entry.group_id)
                        .or_insert_with(|| DashSet::with_hasher(FxBuildHasher))
                        .insert(CompactString::new(&entry.domain));
                }
                DomainAction::Allow => {}
            }
        }
        let allowlists = build_allowlist_index(allowlist_load, &managed_entries);
        let groups_with_advanced_rules = managed_denies
            .keys()
            .chain(managed_deny_wildcards.keys())
            .chain(regex_filters.allow_patterns.keys())
            .chain(regex_filters.block_patterns.keys())
            .copied()
            .collect();

        info!(
            exact = total_exact,
            wildcards = total_wildcard,
            pattern_automata = patterns.len(),
            "Block index compiled"
        );
        BlockIndex {
            group_masks,
            // Adblock `||example.com^` counts both its apex and suffix rule.
            total_blocked_domains: total_exact + total_wildcard,
            exact,
            bloom,
            wildcard,
            patterns,
            allowlists,
            managed_denies,
            managed_deny_wildcards,
            allow_regex_patterns: regex_filters.allow_patterns,
            block_regex_patterns: regex_filters.block_patterns,
            groups_with_advanced_rules,
            bit_to_source,
        }
    };

    tokio::task::spawn_blocking(move || match BLOCKLIST_BUILD_POOL.as_ref() {
        Some(pool) => pool.install(build),
        None => build(),
    })
    .await
    .map_err(|e| {
        DomainError::BlockFilterCompileError(format!("block index build task failed: {e}"))
    })
}

struct AllowlistLoad {
    manual_rows: Vec<SqliteRow>,
    sources: Vec<(Vec<i64>, Arc<str>)>,
}

async fn load_allowlists(
    pool: &SqlitePool,
    downloader: &ListDownloader,
    held: &HeldLists,
    fetch: ListFetch,
    next: &mut HeldLists,
) -> Result<AllowlistLoad, DomainError> {
    let manual_rows = sqlx::query("SELECT domain FROM whitelist")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;
    let source_rows = sqlx::query(
        "SELECT wsg.source_id, wsg.group_id, ws.url
         FROM whitelist_source_groups wsg
         JOIN whitelist_sources ws ON ws.id = wsg.source_id
         WHERE ws.enabled = 1 AND ws.url IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    // Fetch a URL once, retaining every group assignment and owning source id.
    let mut urls: HashMap<String, (Vec<i64>, Vec<i64>)> = HashMap::new();
    for row in source_rows {
        let url: String = row.get("url");
        let (groups, source_ids) = urls.entry(url).or_default();
        groups.push(row.get("group_id"));
        let source_id: i64 = row.get("source_id");
        if !source_ids.contains(&source_id) {
            source_ids.push(source_id);
        }
    }

    let downloaded = fetch_lists(
        urls.keys().cloned().collect(),
        downloader,
        held,
        fetch,
        SourceTable::Whitelist,
        next,
    )
    .await;
    let synced_source_ids: Vec<i64> = urls
        .iter()
        .filter(|(url, _)| downloaded.contains(*url))
        .flat_map(|(_, (_, ids))| ids.iter().copied())
        .collect();
    if let Err(e) = mark_sources_synced(
        pool,
        SourceTable::Whitelist,
        &synced_source_ids,
        &chrono::Utc::now().to_rfc3339(),
    )
    .await
    {
        warn!(error = %e, "Failed to record allowlist source sync timestamps");
    }

    Ok(AllowlistLoad {
        manual_rows,
        sources: urls
            .into_iter()
            .filter_map(|(url, (groups, _))| next.get(&url).map(|text| (groups, Arc::clone(text))))
            .collect(),
    })
}

fn build_allowlist_index(
    loaded: AllowlistLoad,
    managed_entries: &[ManagedDomainEntry],
) -> AllowlistIndex {
    let mut allowlists = AllowlistIndex::default();
    for row in loaded.manual_rows {
        let domain = row.get::<String, _>("domain").to_ascii_lowercase();
        if domain.starts_with("*.") {
            allowlists.global_wildcard.insert_wildcard(&domain, 1u64);
        } else {
            allowlists.global_exact.insert(CompactString::new(domain));
        }
    }

    for entry in managed_entries {
        match entry.action {
            DomainAction::Allow if entry.domain.starts_with("*.") => {
                allowlists
                    .group_wildcard
                    .entry(entry.group_id)
                    .or_default()
                    .insert_wildcard(&entry.domain, 1u64);
            }
            DomainAction::Allow => {
                allowlists
                    .group_exact
                    .entry(entry.group_id)
                    .or_insert_with(|| DashSet::with_hasher(FxBuildHasher))
                    .insert(CompactString::new(&entry.domain));
            }
            DomainAction::Deny => {}
        }
    }

    for (group_ids, text) in loaded.sources {
        let entries = parse_list_text(&text);
        for group_id in group_ids {
            let exact_set = allowlists
                .group_exact
                .entry(group_id)
                .or_insert_with(|| DashSet::with_hasher(FxBuildHasher));
            let trie = allowlists.group_wildcard.entry(group_id).or_default();
            for entry in &entries {
                match entry {
                    ParsedEntry::Exact(domain) => {
                        exact_set.insert(CompactString::new(domain));
                    }
                    ParsedEntry::Wildcard(pattern) => {
                        trie.insert_wildcard(pattern, 1u64);
                    }
                    ParsedEntry::DomainAndSubdomains(domain) => {
                        exact_set.insert(CompactString::new(domain));
                        trie.insert_wildcard(domain, 1u64);
                    }
                    ParsedEntry::Pattern(_) => {}
                }
            }
        }
    }
    allowlists
}
