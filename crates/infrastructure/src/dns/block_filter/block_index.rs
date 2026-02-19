use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;
use std::sync::Arc;

pub type SourceBitSet = u64;

pub const MANUAL_SOURCE_BIT: u64 = 1u64 << 63;

#[derive(Debug, Clone)]
pub struct SourceMeta {
    #[allow(dead_code)]
    pub id: i64,
    #[allow(dead_code)]
    pub name: Arc<str>,
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
    #[allow(dead_code)]
    pub sources: Vec<SourceMeta>,
    pub group_masks: HashMap<i64, SourceBitSet>,
    pub default_group_id: i64,
    pub total_blocked_domains: usize,
    pub exact: DashMap<CompactString, SourceBitSet, FxBuildHasher>,
    pub bloom: AtomicBloom,
    pub wildcard: SuffixTrie,
    pub patterns: Vec<(AhoCorasick, SourceBitSet)>,
    pub allowlists: AllowlistIndex,
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

    #[inline]
    pub fn is_blocked(&self, domain: &str, group_id: i64) -> bool {
        if self.allowlists.is_allowed(domain, group_id) {
            return false;
        }

        let mask = self.group_mask(group_id);

        let bloom_hit = self.bloom.check(&domain);

        if bloom_hit {
            if let Some(entry) = self.exact.get(domain) {
                if entry.value() & mask != 0 {
                    return true;
                }
            }
        }

        self.check_wildcard_and_patterns(domain, mask)
    }

    #[inline]
    fn check_wildcard_and_patterns(&self, domain: &str, mask: SourceBitSet) -> bool {
        let wildcard_bits = self.wildcard.lookup(domain);
        if wildcard_bits & mask != 0 {
            return true;
        }

        for (ac, source_mask) in &self.patterns {
            if source_mask & mask != 0 && ac.is_match(domain) {
                return true;
            }
        }

        false
    }
}
