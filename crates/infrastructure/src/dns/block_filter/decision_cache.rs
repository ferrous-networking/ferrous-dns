use crate::dns::cache::coarse_clock::coarse_now_secs;
use ahash::RandomState as AHashRandomState;
use dashmap::DashMap;
use ferrous_dns_domain::BlockSource;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::hash::{BuildHasher, Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::OnceLock;

const TTL_SECS: u64 = 60;
const L0_CAPACITY: usize = 256;
const L1_CAPACITY: usize = 100_000;
const EVICTION_BATCH_SIZE: usize = 64;

const CACHE_ALLOW: u8 = 0;

fn encode_source(source: Option<BlockSource>) -> u8 {
    match source {
        None => CACHE_ALLOW,
        Some(s) => s.as_u8() + 1,
    }
}

fn decode_source(val: u8) -> Option<BlockSource> {
    if val == CACHE_ALLOW {
        None
    } else {
        BlockSource::from_u8(val - 1)
    }
}

static DECISION_HASH_STATE: OnceLock<AHashRandomState> = OnceLock::new();

#[inline]
fn decision_hash_state() -> &'static AHashRandomState {
    DECISION_HASH_STATE.get_or_init(|| {
        AHashRandomState::with_seeds(
            0xf4a5_f3e1_c2b0_a9d7,
            0x8e6b_4c2a_0f1d_e3c9,
            0x7a2c_1e5b_9d4f_6a8e,
            0x3c7a_2e4b_6f8d_0a1c,
        )
    })
}

#[inline]
pub fn decision_key(domain: &str, group_id: i64) -> u64 {
    let mut h = decision_hash_state().build_hasher();
    domain.hash(&mut h);
    group_id.hash(&mut h);
    h.finish()
}

type BlockL0Cache = LruCache<u64, (u8, u64), FxBuildHasher>;

thread_local! {
    static BLOCK_L0: RefCell<BlockL0Cache> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(L0_CAPACITY).unwrap(),
            FxBuildHasher,
        ));
}

#[inline]
pub fn decision_l0_get_by_key(key: u64) -> Option<Option<BlockSource>> {
    BLOCK_L0.with(|c| {
        let mut c = c.borrow_mut();
        if let Some(&(encoded, inserted_at)) = c.get(&key) {
            if coarse_now_secs().saturating_sub(inserted_at) < TTL_SECS {
                return Some(decode_source(encoded));
            }
            c.pop(&key);
        }
        None
    })
}

#[inline]
pub fn decision_l0_set_by_key(key: u64, source: Option<BlockSource>) {
    BLOCK_L0.with(|c| {
        c.borrow_mut()
            .put(key, (encode_source(source), coarse_now_secs()));
    });
}

pub fn decision_l0_clear() {
    BLOCK_L0.with(|c| c.borrow_mut().clear());
}

pub struct BlockDecisionCache {
    inner: DashMap<u64, (u8, u64), FxBuildHasher>,
}

impl BlockDecisionCache {
    pub fn new() -> Self {
        Self {
            inner: DashMap::with_capacity_and_hasher(L1_CAPACITY, FxBuildHasher),
        }
    }

    #[inline]
    pub fn get_by_key(&self, key: u64) -> Option<Option<BlockSource>> {
        match self.inner.entry(key) {
            dashmap::Entry::Vacant(_) => None,
            dashmap::Entry::Occupied(e) => {
                let (encoded, inserted_at) = *e.get();
                if coarse_now_secs().saturating_sub(inserted_at) < TTL_SECS {
                    Some(decode_source(encoded))
                } else {
                    e.remove();
                    None
                }
            }
        }
    }

    #[inline]
    pub fn set_by_key(&self, key: u64, source: Option<BlockSource>) {
        if self.inner.len() >= L1_CAPACITY {
            let now = coarse_now_secs();
            let expired: Vec<u64> = self
                .inner
                .iter()
                .filter(|e| now.saturating_sub(e.value().1) >= TTL_SECS)
                .map(|e| *e.key())
                .take(EVICTION_BATCH_SIZE)
                .collect();
            for k in &expired {
                self.inner.remove(k);
            }
            if self.inner.len() >= L1_CAPACITY {
                if let Some(k) = self.inner.iter().map(|e| *e.key()).next() {
                    self.inner.remove(&k);
                }
            }
        }
        self.inner
            .insert(key, (encode_source(source), coarse_now_secs()));
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
