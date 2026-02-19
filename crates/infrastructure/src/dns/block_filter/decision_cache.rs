use compact_str::CompactString;
use dashmap::DashMap;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(60);
const L0_CAPACITY: usize = 256;

type BlockL0Cache = LruCache<(CompactString, i64), (bool, Instant), FxBuildHasher>;

thread_local! {
    static BLOCK_L0: RefCell<BlockL0Cache> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(L0_CAPACITY).unwrap(),
            FxBuildHasher,
        ));
}

#[inline]
pub fn decision_l0_get(domain: &str, group_id: i64) -> Option<bool> {
    BLOCK_L0.with(|c| {
        let mut c = c.borrow_mut();
        let key = (CompactString::new(domain), group_id);
        if let Some((blocked, inserted_at)) = c.get(&key) {
            if inserted_at.elapsed() < TTL {
                return Some(*blocked);
            }
            c.pop(&key);
        }
        None
    })
}

#[inline]
pub fn decision_l0_set(domain: &str, group_id: i64, blocked: bool) {
    BLOCK_L0.with(|c| {
        c.borrow_mut().put(
            (CompactString::new(domain), group_id),
            (blocked, Instant::now()),
        );
    });
}

pub fn decision_l0_clear() {
    BLOCK_L0.with(|c| c.borrow_mut().clear());
}

pub struct BlockDecisionCache {
    inner: DashMap<(CompactString, i64), (bool, Instant), FxBuildHasher>,
}

impl BlockDecisionCache {
    pub fn new() -> Self {
        Self {
            inner: DashMap::with_hasher(FxBuildHasher),
        }
    }

    #[inline]
    pub fn get(&self, domain: &str, group_id: i64) -> Option<bool> {
        let key = (CompactString::new(domain), group_id);
        if let Some(entry) = self.inner.get(&key) {
            let (blocked, inserted_at) = *entry;
            if inserted_at.elapsed() < TTL {
                return Some(blocked);
            }
            drop(entry);
            self.inner.remove(&key);
        }
        None
    }

    #[inline]
    pub fn set(&self, domain: &str, group_id: i64, blocked: bool) {
        self.inner.insert(
            (CompactString::new(domain), group_id),
            (blocked, Instant::now()),
        );
    }

    pub fn clear(&self) {
        self.inner.clear();
    }
}

impl Default for BlockDecisionCache {
    fn default() -> Self {
        Self::new()
    }
}
