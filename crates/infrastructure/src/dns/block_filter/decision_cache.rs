use crate::dns::cache::coarse_clock::coarse_now_secs;
use lru::LruCache;
use rustc_hash::{FxBuildHasher, FxHasher};
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Mutex;

const TTL_SECS: u64 = 60;
const L0_CAPACITY: usize = 256;
const L1_CAPACITY: usize = 100_000;

fn decision_key(domain: &str, group_id: i64) -> u64 {
    let mut h = FxHasher::default();
    domain.hash(&mut h);
    group_id.hash(&mut h);
    h.finish()
}

type BlockL0Cache = LruCache<u64, (bool, u64), FxBuildHasher>;

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
        let key = decision_key(domain, group_id);
        if let Some(&(blocked, inserted_at)) = c.get(&key) {
            if coarse_now_secs().saturating_sub(inserted_at) < TTL_SECS {
                return Some(blocked);
            }
            c.pop(&key);
        }
        None
    })
}

#[inline]
pub fn decision_l0_set(domain: &str, group_id: i64, blocked: bool) {
    BLOCK_L0.with(|c| {
        c.borrow_mut()
            .put(decision_key(domain, group_id), (blocked, coarse_now_secs()));
    });
}

pub fn decision_l0_clear() {
    BLOCK_L0.with(|c| c.borrow_mut().clear());
}

pub struct BlockDecisionCache {
    inner: Mutex<LruCache<u64, (bool, u64), FxBuildHasher>>,
}

impl BlockDecisionCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(LruCache::with_hasher(
                NonZeroUsize::new(L1_CAPACITY).unwrap(),
                FxBuildHasher,
            )),
        }
    }

    #[inline]
    pub fn get(&self, domain: &str, group_id: i64) -> Option<bool> {
        let key = decision_key(domain, group_id);
        let mut cache = self.inner.lock().unwrap();
        let result = cache.get(&key).copied();
        match result {
            Some((blocked, inserted_at))
                if coarse_now_secs().saturating_sub(inserted_at) < TTL_SECS =>
            {
                Some(blocked)
            }
            Some(_) => {
                cache.pop(&key);
                None
            }
            None => None,
        }
    }

    #[inline]
    pub fn set(&self, domain: &str, group_id: i64, blocked: bool) {
        self.inner
            .lock()
            .unwrap()
            .put(decision_key(domain, group_id), (blocked, coarse_now_secs()));
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}

impl Default for BlockDecisionCache {
    fn default() -> Self {
        Self::new()
    }
}
