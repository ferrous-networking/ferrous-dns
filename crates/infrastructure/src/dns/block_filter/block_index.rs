use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use fancy_regex::Regex;
use ferrous_dns_domain::BlockSource;
use rustc_hash::FxBuildHasher;
use std::collections::{HashMap, HashSet};

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
    pub allow_regex_patterns: HashMap<i64, Vec<Regex>>,
    pub block_regex_patterns: HashMap<i64, Vec<Regex>>,
    pub groups_with_advanced_rules: HashSet<i64>,
}

impl BlockIndex {
    pub fn empty(default_group_id: i64) -> Self {
        Self {
            group_masks: HashMap::new(),
            default_group_id,
            total_blocked_domains: 0,
            exact: DashMap::with_hasher(FxBuildHasher),
            bloom: AtomicBloom::new(1000, 0.001),
            wildcard: SuffixTrie::new(),
            patterns: Vec::new(),
            allowlists: AllowlistIndex::new(),
            managed_denies: HashMap::new(),
            managed_deny_wildcards: HashMap::new(),
            allow_regex_patterns: HashMap::new(),
            block_regex_patterns: HashMap::new(),
            groups_with_advanced_rules: HashSet::new(),
        }
    }

    #[inline]
    pub fn group_mask(&self, group_id: i64) -> SourceBitSet {
        self.group_masks.get(&group_id).copied().unwrap_or_else(|| {
            self.group_masks
                .get(&self.default_group_id)
                .copied()
                .unwrap_or(u64::MAX)
        })
    }

    #[inline]
    pub fn is_blocked(&self, domain: &str, group_id: i64) -> Option<BlockSource> {
        if self.allowlists.is_allowed(domain, group_id) {
            return None;
        }

        let mask = self.group_mask(group_id);

        if self.groups_with_advanced_rules.contains(&group_id) {
            if let Some(regexes) = self.allow_regex_patterns.get(&group_id) {
                for r in regexes {
                    if r.is_match(domain).unwrap_or(false) {
                        return None;
                    }
                }
            }

            if let Some(set) = self.managed_denies.get(&group_id) {
                if set.contains(domain) {
                    return Some(BlockSource::ManagedDomain);
                }
            }

            if let Some(trie) = self.managed_deny_wildcards.get(&group_id) {
                if trie.lookup(domain) != 0 {
                    return Some(BlockSource::ManagedDomain);
                }
            }

            if let Some(regexes) = self.block_regex_patterns.get(&group_id) {
                for r in regexes {
                    if r.is_match(domain).unwrap_or(false) {
                        return Some(BlockSource::RegexFilter);
                    }
                }
            }
        }

        if !self.bloom.check(&domain) {
            return None;
        }

        if let Some(entry) = self.exact.get(domain) {
            if entry.value() & mask != 0 {
                return Some(BlockSource::Blocklist);
            }
        }

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
