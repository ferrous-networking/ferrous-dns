use super::block_index::{AllowlistIndex, BlockIndex, SourceBitSet, SourceMeta, MANUAL_SOURCE_BIT};
use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use fancy_regex::Regex;
use ferrous_dns_domain::DomainError;
use futures::future::join_all;
use rayon::prelude::*;
use rustc_hash::FxBuildHasher;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::LazyLock;
use tracing::{info, warn};

static BLOCKLIST_BUILD_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let num_threads = (parallelism / 2).clamp(1, 4);
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("blocklist rayon pool")
});

#[derive(Debug)]
pub enum ParsedEntry {
    Exact(String),
    Wildcard(String),
    Pattern(String),
}

pub fn parse_list_line(line: &str) -> Option<ParsedEntry> {
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
        return Some(ParsedEntry::Exact(domain));
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

async fn fetch_url(url: &str, client: &reqwest::Client) -> Result<String, String> {
    let response = client
        .get(url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("fetch error for {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {} for {}", response.status().as_u16(), url));
    }

    response
        .text()
        .await
        .map_err(|e| format!("read error for {}: {}", url, e))
}

struct SourceLoad {
    default_group_id: i64,
    sources: Vec<SourceMeta>,
    url_tasks: Vec<(u8, String)>,
    all_group_ids: Vec<i64>,
}

async fn load_sources(pool: &SqlitePool) -> Result<SourceLoad, DomainError> {
    let default_group_id: i64 = sqlx::query("SELECT id FROM groups WHERE is_default = 1 LIMIT 1")
        .fetch_optional(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?
        .map(|row| row.get::<i64, _>("id"))
        .unwrap_or(1);

    // Step 1: Load distinct enabled sources for bit assignment (max 63)
    let source_rows =
        sqlx::query("SELECT id, url FROM blocklist_sources WHERE enabled = 1 ORDER BY id")
            .fetch_all(pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    if source_rows.len() > 63 {
        warn!(
            count = source_rows.len(),
            "More than 63 blocklist sources; only the first 63 will be used"
        );
    }

    // Build id→bit map (capped at 63)
    let id_to_bit: HashMap<i64, u8> = source_rows
        .iter()
        .take(63)
        .enumerate()
        .map(|(idx, row)| (row.get::<i64, _>("id"), idx as u8))
        .collect();

    // Step 2: Load all (source_id, group_id) assignments from pivot
    let assignment_rows = sqlx::query(
        "SELECT bsg.source_id, bsg.group_id
         FROM blocklist_source_groups bsg
         JOIN blocklist_sources bs ON bs.id = bsg.source_id
         WHERE bs.enabled = 1",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    // Expand into flat Vec<SourceMeta> — same bit can appear with multiple group_ids
    // build_group_masks is unchanged: it iterates (bit, group_id) pairs
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
        default_group_id,
        sources,
        url_tasks,
        all_group_ids,
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

async fn fetch_sources_parallel(
    url_tasks: Vec<(u8, String)>,
    client: &reqwest::Client,
) -> HashMap<u8, Vec<ParsedEntry>> {
    struct FetchResult {
        bit: u8,
        text: Option<String>,
    }

    let tasks: Vec<_> = url_tasks
        .into_iter()
        .map(|(bit, u)| {
            let client = client.clone();
            tokio::spawn(async move {
                let text = match fetch_url(&u, &client).await {
                    Ok(t) => {
                        info!(url = %u, "Fetched blocklist source");
                        Some(t)
                    }
                    Err(e) => {
                        warn!(url = %u, error = %e, "Failed to fetch blocklist source");
                        None
                    }
                };
                FetchResult { bit, text }
            })
        })
        .collect();

    let mut source_entries: HashMap<u8, Vec<ParsedEntry>> = HashMap::new();
    for result in join_all(tasks).await {
        match result {
            Ok(fr) => {
                if let Some(text) = fr.text {
                    source_entries.insert(fr.bit, parse_list_text(&text));
                }
            }
            Err(e) => {
                warn!(error = %e, "Fetch task panicked");
            }
        }
    }
    source_entries
}

struct ManagedDomainEntry {
    domain: String,
    action: String,
    group_id: i64,
}

async fn load_managed_domains_for_index(
    pool: &SqlitePool,
) -> Result<Vec<ManagedDomainEntry>, DomainError> {
    let rows =
        sqlx::query("SELECT domain, action, group_id FROM managed_domains WHERE enabled = 1")
            .fetch_all(pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    let entries: Vec<ManagedDomainEntry> = rows
        .iter()
        .map(|row| ManagedDomainEntry {
            domain: row.get::<String, _>("domain").to_ascii_lowercase(),
            action: row.get::<String, _>("action"),
            group_id: row.get::<i64, _>("group_id"),
        })
        .collect();

    info!(count = entries.len(), "Loaded managed domain entries");
    Ok(entries)
}

async fn load_manual_domains(pool: &SqlitePool) -> Result<Vec<String>, DomainError> {
    let rows = sqlx::query("SELECT domain FROM blocklist")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    let domains: Vec<String> = rows
        .iter()
        .map(|row| row.get::<String, _>("domain").to_ascii_lowercase())
        .collect();

    info!(count = domains.len(), "Loaded manual blocklist entries");
    Ok(domains)
}

struct BlockIndexData {
    total_exact: usize,
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
            .filter(|e| matches!(e, ParsedEntry::Exact(_)))
            .count();

    let bloom_capacity = (exact_count + 100).max(1000);
    let bloom = AtomicBloom::new(bloom_capacity, 0.001);
    let exact: DashMap<CompactString, SourceBitSet, FxBuildHasher> =
        DashMap::with_capacity_and_hasher(exact_count, FxBuildHasher);
    let mut wildcard = SuffixTrie::new();
    let mut patterns_by_source: HashMap<u8, Vec<String>> = HashMap::new();

    for domain in manual_domains {
        bloom.set(domain);
        exact
            .entry(CompactString::new(domain))
            .and_modify(|bits| *bits |= MANUAL_SOURCE_BIT)
            .or_insert(MANUAL_SOURCE_BIT);
    }

    BLOCKLIST_BUILD_POOL.install(|| {
        source_entries.par_iter().for_each(|(bit, entries)| {
            let source_bit: SourceBitSet = 1u64 << *bit;
            for entry in entries {
                if let ParsedEntry::Exact(domain) = entry {
                    bloom.set(domain);
                    exact
                        .entry(CompactString::new(domain))
                        .and_modify(|bits| *bits |= source_bit)
                        .or_insert(source_bit);
                }
            }
        });
    });

    for (bit, entries) in source_entries {
        let source_bit: SourceBitSet = 1u64 << *bit;
        for entry in entries {
            match entry {
                ParsedEntry::Exact(_) => {}
                ParsedEntry::Wildcard(pattern) => {
                    wildcard.insert_wildcard(pattern, source_bit);
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

    BlockIndexData {
        total_exact: exact.len(),
        bloom,
        exact,
        wildcard,
        patterns,
    }
}

struct RegexFilterMaps {
    block_patterns: HashMap<i64, Vec<Regex>>,
    allow_patterns: HashMap<i64, Vec<Regex>>,
}

async fn load_regex_filters_for_index(pool: &SqlitePool) -> Result<RegexFilterMaps, DomainError> {
    let rows = sqlx::query("SELECT pattern, action, group_id FROM regex_filters WHERE enabled = 1")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    let mut block_patterns: HashMap<i64, Vec<Regex>> = HashMap::new();
    let mut allow_patterns: HashMap<i64, Vec<Regex>> = HashMap::new();

    for row in &rows {
        let pattern: String = row.get("pattern");
        let action: String = row.get("action");
        let group_id: i64 = row.get("group_id");

        match Regex::new(&format!("(?i){}", &pattern)) {
            Ok(re) => {
                if action == "deny" {
                    block_patterns.entry(group_id).or_default().push(re);
                } else {
                    allow_patterns.entry(group_id).or_default().push(re);
                }
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

    Ok(RegexFilterMaps {
        block_patterns,
        allow_patterns,
    })
}

pub async fn compile_block_index(
    pool: &SqlitePool,
    client: &reqwest::Client,
) -> Result<BlockIndex, DomainError> {
    let SourceLoad {
        default_group_id,
        sources,
        url_tasks,
        all_group_ids,
    } = load_sources(pool).await?;

    let group_masks = build_group_masks(&sources, &all_group_ids);
    let source_entries = fetch_sources_parallel(url_tasks, client).await;
    let manual_domains = load_manual_domains(pool).await?;
    let managed_domain_entries = load_managed_domains_for_index(pool).await?;
    let regex_filter_maps = load_regex_filters_for_index(pool).await?;

    let BlockIndexData {
        total_exact,
        bloom,
        exact,
        wildcard,
        patterns,
    } = tokio::task::spawn_blocking(move || {
        build_exact_and_wildcard(&manual_domains, &source_entries)
    })
    .await
    .map_err(|e| {
        DomainError::BlockFilterCompileError(format!("block index build task panicked: {e}"))
    })?;

    let mut managed_denies: HashMap<i64, DashSet<CompactString, FxBuildHasher>> = HashMap::new();
    let mut managed_deny_wildcards: HashMap<i64, SuffixTrie> = HashMap::new();
    for entry in &managed_domain_entries {
        if entry.action == "deny" {
            if entry.domain.starts_with("*.") {
                managed_deny_wildcards
                    .entry(entry.group_id)
                    .or_default()
                    .insert_wildcard(&entry.domain, 1u64);
            } else {
                managed_denies
                    .entry(entry.group_id)
                    .or_insert_with(|| DashSet::with_hasher(FxBuildHasher))
                    .insert(CompactString::new(&entry.domain));
            }
        }
    }

    info!(
        exact = total_exact,
        wildcards = "built",
        pattern_automata = patterns.len(),
        "Block index compiled"
    );

    let allowlists =
        build_allowlist_index(pool, client, default_group_id, &managed_domain_entries).await?;

    let mut groups_with_advanced_rules = std::collections::HashSet::new();
    for gid in managed_denies.keys() {
        groups_with_advanced_rules.insert(*gid);
    }
    for gid in managed_deny_wildcards.keys() {
        groups_with_advanced_rules.insert(*gid);
    }
    for gid in regex_filter_maps.allow_patterns.keys() {
        groups_with_advanced_rules.insert(*gid);
    }
    for gid in regex_filter_maps.block_patterns.keys() {
        groups_with_advanced_rules.insert(*gid);
    }

    Ok(BlockIndex {
        group_masks,
        total_blocked_domains: total_exact,
        exact,
        bloom,
        wildcard,
        patterns,
        allowlists,
        managed_denies,
        managed_deny_wildcards,
        allow_regex_patterns: regex_filter_maps.allow_patterns,
        block_regex_patterns: regex_filter_maps.block_patterns,
        groups_with_advanced_rules,
    })
}

async fn build_allowlist_index(
    pool: &SqlitePool,
    client: &reqwest::Client,
    _default_group_id: i64,
    managed_entries: &[ManagedDomainEntry],
) -> Result<AllowlistIndex, DomainError> {
    let whitelist_rows = sqlx::query("SELECT domain FROM whitelist")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    let mut allowlists = AllowlistIndex::new();

    for row in &whitelist_rows {
        let domain: String = row.get("domain");
        let domain_lc = domain.to_ascii_lowercase();
        if domain_lc.starts_with("*.") {
            allowlists.global_wildcard.insert_wildcard(&domain_lc, 1u64);
        } else {
            allowlists
                .global_exact
                .insert(CompactString::new(domain_lc));
        }
    }

    for entry in managed_entries {
        if entry.action == "allow" {
            if entry.domain.starts_with("*.") {
                allowlists
                    .group_wildcard
                    .entry(entry.group_id)
                    .or_default()
                    .insert_wildcard(&entry.domain, 1u64);
            } else {
                allowlists
                    .group_exact
                    .entry(entry.group_id)
                    .or_insert_with(|| DashSet::with_hasher(FxBuildHasher))
                    .insert(CompactString::new(&entry.domain));
            }
        }
    }

    let ws_rows = sqlx::query(
        "SELECT wsg.source_id, wsg.group_id, ws.url
         FROM whitelist_source_groups wsg
         JOIN whitelist_sources ws ON ws.id = wsg.source_id
         WHERE ws.enabled = 1 AND ws.url IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    // Deduplicate URLs: each URL is fetched once, applied to all associated groups
    let mut url_to_groups: HashMap<String, Vec<i64>> = HashMap::new();
    for row in &ws_rows {
        if let Some(url) = row.get::<Option<String>, _>("url") {
            let group_id: i64 = row.get("group_id");
            url_to_groups.entry(url).or_default().push(group_id);
        }
    }

    let deduped_tasks: Vec<(i64, String)> = url_to_groups
        .keys()
        .map(|url| (0i64, url.clone()))
        .collect();

    // Fetch each unique URL once; we'll re-map to group_ids after
    let fetched: Vec<(String, Option<String>)> = {
        let tasks: Vec<_> = deduped_tasks
            .into_iter()
            .map(|(_, url)| {
                let client = client.clone();
                let url_clone = url.clone();
                let url_for_task = url.clone();
                tokio::spawn(async move {
                    let text = match fetch_url(&url_for_task, &client).await {
                        Ok(t) => Some(t),
                        Err(e) => {
                            tracing::warn!(url = %url_for_task, error = %e, "Failed to fetch whitelist source");
                            None
                        }
                    };
                    (url_clone, text)
                })
            })
            .collect();
        join_all(tasks)
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .collect()
    };

    for (url, text_opt) in fetched {
        if let Some(text) = text_opt {
            let entries = parse_list_text(&text);
            let group_ids = url_to_groups.get(&url).cloned().unwrap_or_default();
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
                        ParsedEntry::Pattern(_) => {}
                    }
                }
            }
        }
    }

    Ok(allowlists)
}
