use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use fancy_regex::Regex;
use ferrous_dns_domain::{
    AllowMatch, AllowMatchKind, BlockMatch, BlockMatchKind, BlockSource, FilterExplanation,
    MatchType,
};
use rustc_hash::FxBuildHasher;
use std::collections::{HashMap, HashSet};

pub type SourceBitSet = u64;

pub const MANUAL_SOURCE_BIT: u64 = 1u64 << 63;

/// Bit index reserved for the global manual blocklist.
pub const MANUAL_SOURCE_BIT_INDEX: usize = 63;

/// How the compiled index classifies a domain.
///
/// The `Manual*` variants come from rules the operator wrote themselves — the
/// allowlist, managed domains, regex filters and the manual blocklist. They form
/// a tier of their own because they outrank the global blocking toggle and every
/// schedule override; a hit from a downloaded blocklist does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    ManualAllow,
    ManualDeny(BlockSource),
    Block(BlockSource),
    NoMatch,
}

/// A hit carrying the manual-blocklist bit was typed in by the operator, so it
/// belongs to the manual tier; anything else came from a downloaded list.
#[inline]
fn classify_deny(source: BlockSource, matched_bits: SourceBitSet) -> Verdict {
    if matched_bits & MANUAL_SOURCE_BIT != 0 {
        Verdict::ManualDeny(source)
    } else {
        Verdict::Block(source)
    }
}

#[derive(Debug, Clone)]
pub struct SourceMeta {
    pub group_id: i64,
    pub bit: u8,
}

/// Reverse mapping target for a source bit: which blocklist source owns it.
#[derive(Debug, Clone)]
pub struct SourceDescriptor {
    pub id: i64,
    pub name: String,
}

/// A compiled regex filter that retains its database identity for attribution.
#[derive(Debug, Clone)]
pub struct RegexRule {
    pub id: i64,
    pub name: String,
    pub regex: Regex,
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
    pub total_blocked_domains: usize,
    pub exact: DashMap<CompactString, SourceBitSet, FxBuildHasher>,
    pub bloom: AtomicBloom,
    pub wildcard: SuffixTrie,
    pub patterns: Vec<(AhoCorasick, SourceBitSet)>,
    pub allowlists: AllowlistIndex,
    pub managed_denies: HashMap<i64, DashSet<CompactString, FxBuildHasher>>,
    pub managed_deny_wildcards: HashMap<i64, SuffixTrie>,
    pub allow_regex_patterns: HashMap<i64, Vec<RegexRule>>,
    pub block_regex_patterns: HashMap<i64, Vec<RegexRule>>,
    pub groups_with_advanced_rules: HashSet<i64>,
    /// Reverse map from source bit index (0..=63) to the owning source.
    /// Index 63 (`MANUAL_SOURCE_BIT_INDEX`) describes the manual blocklist.
    pub bit_to_source: Vec<Option<SourceDescriptor>>,
}

impl BlockIndex {
    pub fn empty() -> Self {
        Self {
            group_masks: HashMap::new(),
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
            bit_to_source: Vec::new(),
        }
    }

    /// Returns the bitmask for a group. Groups not in the map get only the
    /// manual-blocklist bit — they are NOT promoted to the default group.
    #[inline]
    pub fn group_mask(&self, group_id: i64) -> SourceBitSet {
        self.group_masks
            .get(&group_id)
            .copied()
            .unwrap_or(MANUAL_SOURCE_BIT)
    }

    /// Classifies `domain` for `group_id`, keeping rules the operator wrote
    /// themselves in a tier of their own (see [`Verdict`]).
    #[inline]
    pub fn evaluate(&self, domain: &str, group_id: i64) -> Verdict {
        if self.allowlists.is_allowed(domain, group_id) {
            return Verdict::ManualAllow;
        }

        let mask = self.group_mask(group_id);
        let has_advanced = self.groups_with_advanced_rules.contains(&group_id);

        if has_advanced {
            if let Some(regexes) = self.allow_regex_patterns.get(&group_id) {
                for rule in regexes {
                    if rule.regex.is_match(domain).unwrap_or(false) {
                        return Verdict::ManualAllow;
                    }
                }
            }

            if let Some(set) = self.managed_denies.get(&group_id) {
                if set.contains(domain) {
                    return Verdict::ManualDeny(BlockSource::ManagedDomain);
                }
            }

            if let Some(trie) = self.managed_deny_wildcards.get(&group_id) {
                if trie.lookup(domain) != 0 {
                    return Verdict::ManualDeny(BlockSource::ManagedDomain);
                }
            }

            // Deny regexes are hand-written rules, so they have to resolve
            // ahead of the downloaded lists: a domain that matches both used to
            // come back as a plain `Block`, which the blocking toggle and any
            // bypass window would then release despite the manual rule. The
            // scan is not free, but `evaluate` runs once per domain per group
            // and is then memoized by the decision cache.
            if let Some(regexes) = self.block_regex_patterns.get(&group_id) {
                for rule in regexes {
                    if rule.regex.is_match(domain).unwrap_or(false) {
                        return Verdict::ManualDeny(BlockSource::RegexFilter);
                    }
                }
            }
        }

        // The bloom filter is built from exact entries only, so it can vouch
        // for `exact` and nothing else. A miss must NOT short-circuit the whole
        // lookup: suffix (wildcard) and substring rules are keyed on parts of
        // the name that were never inserted into the filter, so gating them on
        // it made them unreachable for every domain that was not already an
        // exact entry.
        if self.bloom.check(&domain) {
            if let Some(entry) = self.exact.get(domain) {
                let matched = entry.value() & mask;
                if matched != 0 {
                    return classify_deny(BlockSource::Blocklist, matched);
                }
            }
        }

        if self.has_suffix_or_substring_rules() {
            if let Some(matched) = self.check_wildcard_and_patterns(domain, mask) {
                return classify_deny(BlockSource::Blocklist, matched);
            }
        }

        Verdict::NoMatch
    }

    /// Whether the compiled index holds any rule that the exact-entry bloom
    /// filter cannot speak for. Both checks are O(1), and lists in hosts or
    /// plain-domain format compile to none of these, which keeps the fast
    /// reject path intact for them.
    #[inline]
    fn has_suffix_or_substring_rules(&self) -> bool {
        !self.wildcard.is_empty() || !self.patterns.is_empty()
    }

    /// Returns the source bits that matched, so the caller can tell a manual
    /// entry apart from a downloaded one. `None` means no rule matched.
    #[inline]
    fn check_wildcard_and_patterns(
        &self,
        domain: &str,
        mask: SourceBitSet,
    ) -> Option<SourceBitSet> {
        let wildcard_bits = self.wildcard.lookup(domain) & mask;
        if wildcard_bits != 0 {
            return Some(wildcard_bits);
        }

        for (ac, source_mask) in &self.patterns {
            let matched = source_mask & mask;
            if matched != 0 && ac.is_match(domain) {
                return Some(matched);
            }
        }

        None
    }

    /// Read-only, exhaustive attribution of how the static filter index evaluates
    /// `domain` for `group_id`.
    ///
    /// Unlike [`BlockIndex::is_blocked`], this collects ALL matching rules (allow
    /// and block) and resolves them to named sources. It never mutates any cache
    /// and deliberately skips the bloom short-circuit so the result is exhaustive.
    /// Dynamic runtime rules (schedule, CNAME, rebinding, …) are out of scope.
    pub fn explain(&self, domain: &str, group_id: i64) -> FilterExplanation {
        let mask = self.group_mask(group_id);

        let mut allow_reasons: Vec<AllowMatch> = Vec::new();
        let mut block_matches: Vec<BlockMatch> = Vec::new();

        self.collect_allow_matches(domain, group_id, &mut allow_reasons);

        // Managed (custom) deny domains.
        if let Some(set) = self.managed_denies.get(&group_id) {
            if set.contains(domain) {
                block_matches.push(BlockMatch {
                    kind: BlockMatchKind::ManagedDomain,
                    source_id: None,
                    name: "Managed domain".to_string(),
                    match_type: MatchType::Exact,
                });
            }
        }
        if let Some(trie) = self.managed_deny_wildcards.get(&group_id) {
            if trie.lookup(domain) != 0 {
                block_matches.push(BlockMatch {
                    kind: BlockMatchKind::ManagedDomain,
                    source_id: None,
                    name: "Managed domain".to_string(),
                    match_type: MatchType::Wildcard,
                });
            }
        }

        // Exact blocklist entries.
        if let Some(entry) = self.exact.get(domain) {
            let bits = entry.value() & mask;
            self.collect_bit_matches(bits, MatchType::Exact, &mut block_matches);
        }

        // Wildcard (suffix) blocklist entries.
        let wildcard_bits = self.wildcard.lookup(domain) & mask;
        self.collect_bit_matches(wildcard_bits, MatchType::Wildcard, &mut block_matches);

        // Aho-Corasick substring patterns.
        for (ac, source_mask) in &self.patterns {
            let bits = source_mask & mask;
            if bits != 0 && ac.is_match(domain) {
                self.collect_bit_matches(bits, MatchType::Pattern, &mut block_matches);
            }
        }

        // Deny regex filters.
        if let Some(rules) = self.block_regex_patterns.get(&group_id) {
            for rule in rules {
                if rule.regex.is_match(domain).unwrap_or(false) {
                    block_matches.push(BlockMatch {
                        kind: BlockMatchKind::Regex,
                        source_id: Some(rule.id),
                        name: rule.name.clone(),
                        match_type: MatchType::Regex,
                    });
                }
            }
        }

        let blocked = allow_reasons.is_empty() && !block_matches.is_empty();

        FilterExplanation {
            domain: domain.to_string(),
            group_id,
            blocked,
            allow_reasons,
            block_matches,
        }
    }

    /// Resolve every set bit in `bits` to a named [`BlockMatch`] and append it.
    fn collect_bit_matches(
        &self,
        bits: SourceBitSet,
        match_type: MatchType,
        out: &mut Vec<BlockMatch>,
    ) {
        let mut remaining = bits;
        while remaining != 0 {
            let idx = remaining.trailing_zeros() as usize;
            remaining &= remaining - 1;
            if idx == MANUAL_SOURCE_BIT_INDEX {
                out.push(BlockMatch {
                    kind: BlockMatchKind::Manual,
                    source_id: None,
                    name: "Manual blocklist".to_string(),
                    match_type,
                });
            } else if let Some(Some(desc)) = self.bit_to_source.get(idx) {
                out.push(BlockMatch {
                    kind: BlockMatchKind::Blocklist,
                    source_id: Some(desc.id),
                    name: desc.name.clone(),
                    match_type,
                });
            } else {
                out.push(BlockMatch {
                    kind: BlockMatchKind::Blocklist,
                    source_id: None,
                    name: format!("source bit {idx}"),
                    match_type,
                });
            }
        }
    }

    /// Collect every allow rule (allowlist exact/wildcard, allow regex) matching `domain`.
    fn collect_allow_matches(&self, domain: &str, group_id: i64, out: &mut Vec<AllowMatch>) {
        let al = &self.allowlists;
        if let Some(set) = al.group_exact.get(&group_id) {
            if set.contains(domain) {
                out.push(AllowMatch {
                    kind: AllowMatchKind::Allowlist,
                    source_id: None,
                    name: "Group allowlist".to_string(),
                    match_type: MatchType::Exact,
                });
            }
        }
        if let Some(trie) = al.group_wildcard.get(&group_id) {
            if trie.lookup(domain) != 0 {
                out.push(AllowMatch {
                    kind: AllowMatchKind::Allowlist,
                    source_id: None,
                    name: "Group allowlist".to_string(),
                    match_type: MatchType::Wildcard,
                });
            }
        }
        if al.global_exact.contains(domain) {
            out.push(AllowMatch {
                kind: AllowMatchKind::Allowlist,
                source_id: None,
                name: "Global allowlist".to_string(),
                match_type: MatchType::Exact,
            });
        }
        if al.global_wildcard.lookup(domain) != 0 {
            out.push(AllowMatch {
                kind: AllowMatchKind::Allowlist,
                source_id: None,
                name: "Global allowlist".to_string(),
                match_type: MatchType::Wildcard,
            });
        }
        if let Some(rules) = self.allow_regex_patterns.get(&group_id) {
            for rule in rules {
                if rule.regex.is_match(domain).unwrap_or(false) {
                    out.push(AllowMatch {
                        kind: AllowMatchKind::Regex,
                        source_id: Some(rule.id),
                        name: rule.name.clone(),
                        match_type: MatchType::Regex,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // `BlockIndex` and its attribution maps are private to this module, so the
    // explain logic is exercised here rather than as an integration test.
    use super::*;
    use ferrous_dns_domain::{AllowMatchKind, BlockMatchKind, MatchType};

    fn idx_with_sources() -> BlockIndex {
        let mut idx = BlockIndex::empty();
        idx.bit_to_source = vec![None; 64];
        idx.bit_to_source[0] = Some(SourceDescriptor {
            id: 10,
            name: "EasyList".to_string(),
        });
        idx.bit_to_source[1] = Some(SourceDescriptor {
            id: 20,
            name: "StevenBlack".to_string(),
        });
        // group 1 sees source bits 0 and 1 plus the manual bit
        idx.group_masks
            .insert(1, MANUAL_SOURCE_BIT | (1 << 0) | (1 << 1));
        // group 2 sees only source bit 1
        idx.group_masks.insert(2, 1 << 1);
        idx
    }

    #[test]
    fn explain_attributes_exact_blocklist_source_by_name() {
        let idx = idx_with_sources();
        idx.exact
            .insert(CompactString::new("ads.example.com"), 1 << 0);

        let exp = idx.explain("ads.example.com", 1);
        assert!(exp.blocked);
        assert_eq!(exp.block_matches.len(), 1);
        let m = &exp.block_matches[0];
        assert_eq!(m.kind, BlockMatchKind::Blocklist);
        assert_eq!(m.source_id, Some(10));
        assert_eq!(m.name, "EasyList");
        assert_eq!(m.match_type, MatchType::Exact);
    }

    #[test]
    fn explain_respects_group_mask() {
        let idx = idx_with_sources();
        idx.exact
            .insert(CompactString::new("ads.example.com"), 1 << 0);
        // group 2's mask excludes bit 0 → not blocked there
        let exp = idx.explain("ads.example.com", 2);
        assert!(!exp.blocked);
        assert!(exp.block_matches.is_empty());
    }

    #[test]
    fn explain_attributes_manual_blocklist() {
        let idx = idx_with_sources();
        idx.exact
            .insert(CompactString::new("manual.test"), MANUAL_SOURCE_BIT);
        let exp = idx.explain("manual.test", 1);
        assert!(exp.blocked);
        assert_eq!(exp.block_matches.len(), 1);
        assert_eq!(exp.block_matches[0].kind, BlockMatchKind::Manual);
        assert_eq!(exp.block_matches[0].source_id, None);
    }

    #[test]
    fn explain_attributes_wildcard_match() {
        let mut idx = idx_with_sources();
        idx.wildcard.insert_wildcard("ads.net", 1 << 1);
        let exp = idx.explain("tracker.ads.net", 1);
        assert!(exp.blocked);
        assert_eq!(exp.block_matches.len(), 1);
        assert_eq!(exp.block_matches[0].name, "StevenBlack");
        assert_eq!(exp.block_matches[0].match_type, MatchType::Wildcard);
    }

    #[test]
    fn explain_allowlist_overrides_block() {
        let idx = idx_with_sources();
        idx.exact
            .insert(CompactString::new("allowed.example.com"), 1 << 0);
        idx.allowlists
            .global_exact
            .insert(CompactString::new("allowed.example.com"));
        let exp = idx.explain("allowed.example.com", 1);
        assert!(!exp.blocked);
        assert_eq!(exp.allow_reasons.len(), 1);
        assert_eq!(exp.allow_reasons[0].kind, AllowMatchKind::Allowlist);
        // the matched block rule is still reported for transparency
        assert_eq!(exp.block_matches.len(), 1);
    }

    #[test]
    fn explain_attributes_deny_regex_by_name() {
        let mut idx = idx_with_sources();
        idx.groups_with_advanced_rules.insert(1);
        idx.block_regex_patterns.insert(
            1,
            vec![RegexRule {
                id: 7,
                name: "block-ads".to_string(),
                regex: Regex::new("(?i)^ads\\.").unwrap(),
            }],
        );
        let exp = idx.explain("ads.tracker.io", 1);
        assert!(exp.blocked);
        assert!(exp
            .block_matches
            .iter()
            .any(|m| m.kind == BlockMatchKind::Regex
                && m.name == "block-ads"
                && m.source_id == Some(7)));
    }
}
