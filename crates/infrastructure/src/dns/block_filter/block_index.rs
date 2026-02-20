use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use fancy_regex::Regex;
use ferrous_dns_domain::BlockSource;
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;

pub type SourceBitSet = u64;

pub const MANUAL_SOURCE_BIT: u64 = 1u64 << 63;

#[derive(Debug, Clone)]
pub struct SourceMeta {
    pub group_id: i64,
    pub bit: u8,
}

pub struct AllowlistIndex {
    pub global_exact: DashSet<CompactString, FxBuildHasher>,
    pub global_wildcard: SuffixTrie,
    pub group_exact: HashMap<i64, DashSet<CompactString, FxBuildHasher>>,
    pub group_wildcard: HashMap<i64, SuffixTrie>,
}

impl AllowlistIndex {
    pub fn new() -> Self {
        Self {
            global_exact: DashSet::with_hasher(FxBuildHasher),
            global_wildcard: SuffixTrie::new(),
            group_exact: HashMap::new(),
            group_wildcard: HashMap::new(),
        }
    }

    #[inline]
    pub fn is_allowed(&self, domain: &str, group_id: i64) -> bool {
        if let Some(set) = self.group_exact.get(&group_id) {
            if set.contains(domain) {
                return true;
            }
        }
        if let Some(trie) = self.group_wildcard.get(&group_id) {
            if trie.lookup(domain) != 0 {
                return true;
            }
        }
        if self.global_exact.contains(domain) {
            return true;
        }
        if self.global_wildcard.lookup(domain) != 0 {
            return true;
        }
        false
    }
}

impl Default for AllowlistIndex {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BlockIndex {
    pub group_masks: HashMap<i64, SourceBitSet>,
    pub default_group_id: i64,
    pub total_blocked_domains: usize,
    pub exact: DashMap<CompactString, SourceBitSet, FxBuildHasher>,
    pub bloom: AtomicBloom,
    pub wildcard: SuffixTrie,
    pub patterns: Vec<(AhoCorasick, SourceBitSet)>,
    pub allowlists: AllowlistIndex,
    pub managed_denies: HashMap<i64, DashSet<CompactString, FxBuildHasher>>,
    pub managed_deny_wildcards: HashMap<i64, SuffixTrie>,
    /// User-defined regex allow rules (action=allow): group_id → compiled patterns
    pub allow_regex_patterns: HashMap<i64, Vec<Regex>>,
    /// User-defined regex block rules (action=deny): group_id → compiled patterns
    pub block_regex_patterns: HashMap<i64, Vec<Regex>>,
    /// `true` when any managed-deny or regex rule is configured for any group.
    /// When `false`, `is_blocked` skips the four per-group HashMap lookups for
    /// those rule classes, saving ~60–80 ns per query on typical home-server
    /// deployments where no custom managed/regex rules are active.
    pub has_advanced_rules: bool,
}

impl BlockIndex {
    #[inline]
    pub fn group_mask(&self, group_id: i64) -> SourceBitSet {
        self.group_masks.get(&group_id).copied().unwrap_or_else(|| {
            self.group_masks
                .get(&self.default_group_id)
                .copied()
                .unwrap_or(u64::MAX)
        })
    }

    /// Returns `None` if the domain is not blocked, or `Some(source)` identifying
    /// which filter layer caused the block.
    #[inline]
    pub fn is_blocked(&self, domain: &str, group_id: i64) -> Option<BlockSource> {
        // L0/L1: allowlists (group exact/wildcard + global exact/wildcard)
        if self.allowlists.is_allowed(domain, group_id) {
            return None;
        }

        // Managed-deny and regex rules — only evaluated when at least one such
        // rule exists across all groups.  When `has_advanced_rules` is false
        // (the common home-server case), we skip four HashMap::get calls and
        // jump straight to the bloom filter, saving ~60–80 ns per query.
        if self.has_advanced_rules {
            // Allow regex rules (user-defined, group-scoped)
            if let Some(regexes) = self.allow_regex_patterns.get(&group_id) {
                for r in regexes {
                    if r.is_match(domain).unwrap_or(false) {
                        return None;
                    }
                }
            }

            // Managed deny rules — exact match
            if let Some(set) = self.managed_denies.get(&group_id) {
                if set.contains(domain) {
                    return Some(BlockSource::ManagedDomain);
                }
            }

            // Managed deny rules — wildcard match
            if let Some(trie) = self.managed_deny_wildcards.get(&group_id) {
                if trie.lookup(domain) != 0 {
                    return Some(BlockSource::ManagedDomain);
                }
            }

            // Block regex rules (user-defined, group-scoped)
            if let Some(regexes) = self.block_regex_patterns.get(&group_id) {
                for r in regexes {
                    if r.is_match(domain).unwrap_or(false) {
                        return Some(BlockSource::RegexFilter);
                    }
                }
            }
        }

        let mask = self.group_mask(group_id);

        // Bloom filter fast-path: if miss, definitely not in blocklist
        let bloom_hit = self.bloom.check(&domain);
        if !bloom_hit {
            return None;
        }

        // Exact match from blocklist sources
        if let Some(entry) = self.exact.get(domain) {
            if entry.value() & mask != 0 {
                return Some(BlockSource::Blocklist);
            }
        }

        // Wildcard + Aho-Corasick patterns from blocklist sources
        self.check_wildcard_and_patterns(domain, mask)
    }

    #[inline]
    fn check_wildcard_and_patterns(&self, domain: &str, mask: SourceBitSet) -> Option<BlockSource> {
        let wildcard_bits = self.wildcard.lookup(domain);
        if wildcard_bits & mask != 0 {
            return Some(BlockSource::Blocklist);
        }

        for (ac, source_mask) in &self.patterns {
            if source_mask & mask != 0 && ac.is_match(domain) {
                return Some(BlockSource::Blocklist);
            }
        }

        None
    }
}
