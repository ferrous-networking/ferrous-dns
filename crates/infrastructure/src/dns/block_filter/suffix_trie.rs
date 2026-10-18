use compact_str::CompactString;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;
use std::collections::HashMap;

#[derive(Default)]
struct TrieNode {
    children: HashMap<CompactString, TrieNode, FxBuildHasher>,
    wildcard_mask: u64,
}

#[derive(Default)]
pub struct SuffixTrie {
    root: TrieNode,
    len: usize,
}

impl SuffixTrie {
    /// True when no wildcard was ever inserted. Callers use this to skip the
    /// suffix lookup entirely on indexes built from exact-only lists.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty()
    }

    /// Number of distinct suffixes carrying a rule. The same pattern arriving
    /// from two sources counts once, matching how `exact` deduplicates.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the suffix carried no rule before this insert.
    pub fn insert_wildcard(&mut self, pattern: &str, source_mask: u64) -> bool {
        let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
        let mut node = &mut self.root;
        for label in domain.split('.').rev() {
            node = node.children.entry(CompactString::new(label)).or_default();
        }
        let is_new = node.wildcard_mask == 0;
        node.wildcard_mask |= source_mask;
        if is_new {
            self.len += 1;
        }
        is_new
    }

    #[inline]
    pub fn lookup(&self, domain: &str) -> u64 {
        let labels: SmallVec<[&str; 8]> = domain.split('.').rev().collect();
        let n = labels.len();
        let mut node = &self.root;
        let mut result: u64 = 0;

        for (i, label) in labels.iter().enumerate() {
            match node.children.get(*label) {
                Some(child) => {
                    if child.wildcard_mask != 0 && i + 1 < n {
                        result |= child.wildcard_mask;
                    }
                    node = child;
                }
                None => break,
            }
        }

        result
    }
}
