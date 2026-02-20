use compact_str::CompactString;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;
use std::collections::HashMap;

#[derive(Default)]
struct TrieNode {
    children: HashMap<CompactString, TrieNode, FxBuildHasher>,
    wildcard_mask: u64,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::with_hasher(FxBuildHasher),
            wildcard_mask: 0,
        }
    }
}

#[derive(Default)]
pub struct SuffixTrie {
    root: TrieNode,
}

impl SuffixTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
        }
    }

    pub fn insert_wildcard(&mut self, pattern: &str, source_mask: u64) {
        let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
        let mut node = &mut self.root;
        for label in domain.split('.').rev() {
            node = node.children.entry(CompactString::new(label)).or_default();
        }
        node.wildcard_mask |= source_mask;
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
