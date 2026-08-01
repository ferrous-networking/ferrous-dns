use super::block_index::Verdict;
use crate::dns::cache::coarse_clock::coarse_now_secs;
use ahash::RandomState as AHashRandomState;
use ferrous_dns_domain::BlockSource;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::hash::{BuildHasher, Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

pub const TTL_SECS: u64 = 60;
const L0_CAPACITY: usize = 256;

/// Monotonic counter bumped when decision caches should be invalidated.
/// Thread-local L0 entries written under an older epoch are treated as stale.
static DECISION_EPOCH: AtomicU64 = AtomicU64::new(0);
const L1_CAPACITY: usize = 100_000;

/// Number of independently locked shards. Sized so the DNS worker threads
/// rarely contend for the same lock.
const L1_SHARDS: usize = 64;

const CACHE_ALLOW: u8 = 0;

/// High bit of the cached byte: the verdict came from a rule the operator wrote
/// themselves, which outranks the blocking toggle and schedule overrides.
/// `BlockSource` has 11 variants, so the low bits have room to spare.
const CACHE_MANUAL: u8 = 0x80;

fn encode_verdict(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::NoMatch => CACHE_ALLOW,
        Verdict::ManualAllow => CACHE_MANUAL,
        Verdict::Block(s) => s.as_u8() + 1,
        Verdict::ManualDeny(s) => CACHE_MANUAL | (s.as_u8() + 1),
    }
}

fn decode_verdict(val: u8) -> Verdict {
    let manual = val & CACHE_MANUAL != 0;
    match val & !CACHE_MANUAL {
        CACHE_ALLOW if manual => Verdict::ManualAllow,
        CACHE_ALLOW => Verdict::NoMatch,
        encoded => match BlockSource::from_u8(encoded - 1) {
            Some(s) if manual => Verdict::ManualDeny(s),
            Some(s) => Verdict::Block(s),
            None => Verdict::NoMatch,
        },
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

/// Cached entry: (encoded_verdict, inserted_at_secs, epoch_at_insert).
type BlockL0Cache = LruCache<u64, (u8, u64, u64), FxBuildHasher>;

thread_local! {
    static BLOCK_L0: RefCell<BlockL0Cache> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(L0_CAPACITY).unwrap(),
            FxBuildHasher,
        ));
}

#[inline]
pub fn decision_l0_get_by_key(key: u64) -> Option<Verdict> {
    let current_epoch = DECISION_EPOCH.load(Ordering::Acquire);
    BLOCK_L0.with(|c| {
        let mut c = c.borrow_mut();
        if let Some(&(encoded, inserted_at, epoch)) = c.get(&key) {
            if epoch == current_epoch && coarse_now_secs().saturating_sub(inserted_at) < TTL_SECS {
                return Some(decode_verdict(encoded));
            }
            c.pop(&key);
        }
        None
    })
}

#[inline]
pub fn decision_l0_set_by_key(key: u64, verdict: Verdict) {
    let current_epoch = DECISION_EPOCH.load(Ordering::Acquire);
    BLOCK_L0.with(|c| {
        c.borrow_mut().put(
            key,
            (encode_verdict(verdict), coarse_now_secs(), current_epoch),
        );
    });
}

pub fn decision_l0_clear() {
    DECISION_EPOCH.fetch_add(1, Ordering::Release);
}

type L1Shard = Mutex<LruCache<u64, (u8, u64), FxBuildHasher>>;

/// Shared L1 decision cache: `(domain, group)` hash -> `(encoded verdict, expiry)`.
///
/// Sharded LRU, so lookup, insert and eviction are all O(1). The previous
/// implementation evicted by scanning the whole map for expired entries and
/// then scanning it again for the single oldest one. Once the cache was full
/// and nothing had expired yet — the steady state whenever the working set is
/// larger than the cache — that cost two full passes over 100k entries per
/// insert, holding shard locks throughout.
pub struct BlockDecisionCache {
    shards: Box<[L1Shard]>,
    shard_mask: u64,
}

impl BlockDecisionCache {
    pub fn new() -> Self {
        Self::with_capacity(L1_CAPACITY)
    }

    /// `total_capacity` is divided evenly across the shards, rounding up, so the
    /// effective total is the next multiple of `L1_SHARDS`.
    fn with_capacity(total_capacity: usize) -> Self {
        const _: () = assert!(L1_SHARDS.is_power_of_two());
        let per_shard = NonZeroUsize::new(total_capacity.div_ceil(L1_SHARDS).max(1))
            .expect("per-shard capacity is at least 1");
        Self {
            shards: (0..L1_SHARDS)
                .map(|_| Mutex::new(LruCache::with_hasher(per_shard, FxBuildHasher)))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            shard_mask: (L1_SHARDS - 1) as u64,
        }
    }

    /// Mixes before slicing. Slicing `key` directly would be wrong for any
    /// caller passing low-entropy values — sequential keys have all-zero high
    /// bits and would land every entry in a single shard.
    #[inline]
    fn shard(&self, key: u64) -> &L1Shard {
        let mixed = key.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        &self.shards[((mixed >> 56) & self.shard_mask) as usize]
    }

    /// A panic elsewhere while a shard lock was held must not disable block
    /// filtering for the rest of the process, so poisoning is recovered from.
    #[inline]
    fn lock_shard(&self, key: u64) -> MutexGuard<'_, LruCache<u64, (u8, u64), FxBuildHasher>> {
        self.shard(key)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[inline]
    pub fn get_by_key(&self, key: u64) -> Option<Verdict> {
        let mut shard = self.lock_shard(key);
        let (encoded, expires_at) = *shard.get(&key)?;
        if coarse_now_secs() < expires_at {
            return Some(decode_verdict(encoded));
        }
        shard.pop(&key);
        None
    }

    #[inline]
    pub fn set_by_key(&self, key: u64, verdict: Verdict) {
        self.set_by_key_with_ttl(key, verdict, TTL_SECS);
    }

    #[inline]
    pub fn set_by_key_with_ttl(&self, key: u64, verdict: Verdict, ttl_secs: u64) {
        self.lock_shard(key)
            .put(key, (encode_verdict(verdict), coarse_now_secs() + ttl_secs));
    }

    pub fn clear(&self) {
        for shard in self.shards.iter() {
            shard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|p| p.into_inner()).len())
            .sum()
    }
}

impl Default for BlockDecisionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const ALL_SOURCES: [BlockSource; 11] = [
        BlockSource::Blocklist,
        BlockSource::ManagedDomain,
        BlockSource::RegexFilter,
        BlockSource::CnameCloaking,
        BlockSource::Schedule,
        BlockSource::DnsRebinding,
        BlockSource::RateLimit,
        BlockSource::DnsTunneling,
        BlockSource::NxdomainHijack,
        BlockSource::ResponseIpFilter,
        BlockSource::DgaDetection,
    ];

    #[test]
    fn roundtrips_every_verdict() {
        let cache = BlockDecisionCache::with_capacity(4096);

        cache.set_by_key(1, Verdict::NoMatch);
        assert_eq!(
            cache.get_by_key(1),
            Some(Verdict::NoMatch),
            "no-match must survive a roundtrip"
        );

        cache.set_by_key(2, Verdict::ManualAllow);
        assert_eq!(
            cache.get_by_key(2),
            Some(Verdict::ManualAllow),
            "an explicit allow must survive a roundtrip"
        );

        for (i, source) in ALL_SOURCES.iter().enumerate() {
            let key = 100 + i as u64;
            cache.set_by_key(key, Verdict::Block(*source));
            assert_eq!(
                cache.get_by_key(key),
                Some(Verdict::Block(*source)),
                "{source:?} must survive a roundtrip"
            );

            let manual_key = 200 + i as u64;
            cache.set_by_key(manual_key, Verdict::ManualDeny(*source));
            assert_eq!(
                cache.get_by_key(manual_key),
                Some(Verdict::ManualDeny(*source)),
                "manual {source:?} must not decode as a plain block"
            );
        }
    }

    #[test]
    fn missing_key_reads_as_absent_not_as_allow() {
        let cache = BlockDecisionCache::with_capacity(64);
        assert_eq!(cache.get_by_key(999), None);
    }

    #[test]
    fn expired_entry_is_dropped_on_read() {
        let cache = BlockDecisionCache::with_capacity(64);
        cache.set_by_key_with_ttl(7, Verdict::Block(BlockSource::Blocklist), 0);
        assert_eq!(
            cache.get_by_key(7),
            None,
            "a zero-TTL entry is already expired"
        );
        assert_eq!(
            cache.len(),
            0,
            "reading an expired entry must reclaim its slot"
        );
    }

    #[test]
    fn overwriting_a_key_does_not_grow_the_cache() {
        let cache = BlockDecisionCache::with_capacity(4096);
        for _ in 0..1000 {
            cache.set_by_key(42, Verdict::Block(BlockSource::Blocklist));
        }
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.get_by_key(42),
            Some(Verdict::Block(BlockSource::Blocklist))
        );
    }

    #[test]
    fn capacity_stays_bounded_under_churn() {
        let capacity = 6_400;
        let cache = BlockDecisionCache::with_capacity(capacity);

        // Twenty times the capacity in distinct keys: the cache must evict, not grow.
        for k in 0..(capacity as u64 * 20) {
            cache.set_by_key(k.wrapping_mul(2_654_435_761), Verdict::NoMatch);
        }

        let effective = capacity.div_ceil(L1_SHARDS) * L1_SHARDS;
        assert!(
            cache.len() <= effective,
            "cache grew past its capacity: {} > {effective}",
            cache.len()
        );
    }

    #[test]
    fn sequential_keys_spread_across_shards() {
        // Regression guard: selecting the shard from raw high bits of the key
        // (`key >> 40`) sends every sequential key to shard 0, which silently
        // shrinks the usable cache to one shard's worth of entries.
        let capacity = 6_400;
        let cache = BlockDecisionCache::with_capacity(capacity);
        for k in 0..capacity as u64 {
            cache.set_by_key(k, Verdict::NoMatch);
        }

        let one_shard = capacity.div_ceil(L1_SHARDS);
        assert!(
            cache.len() > capacity / 2,
            "sequential keys collapsed into too few shards: held {} of {capacity} \
             (a single shard holds {one_shard})",
            cache.len()
        );
    }

    #[test]
    fn entries_survive_eviction_pressure_in_other_shards() {
        let cache = BlockDecisionCache::with_capacity(6_400);
        let pinned = 0xdead_beef_u64;
        cache.set_by_key(pinned, Verdict::Block(BlockSource::Blocklist));

        // Churn far more keys than the cache holds, re-reading the pinned entry so
        // it stays the most recently used in its shard.
        for k in 0..100_000u64 {
            cache.set_by_key(k.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1, Verdict::NoMatch);
            if k % 1_000 == 0 {
                assert_eq!(
                    cache.get_by_key(pinned),
                    Some(Verdict::Block(BlockSource::Blocklist)),
                    "a recently used entry was evicted while its shard had room"
                );
            }
        }
    }

    #[test]
    fn clear_empties_every_shard() {
        let cache = BlockDecisionCache::with_capacity(4096);
        for k in 0..2_000u64 {
            cache.set_by_key(k.wrapping_mul(2_654_435_761), Verdict::NoMatch);
        }
        assert!(cache.len() > 0);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    /// The regression this whole structure exists to prevent: eviction used to
    /// scan every entry twice per insert once the cache was full, costing ~2.4ms
    /// per insert at this capacity. O(1) eviction keeps it in the nanoseconds.
    /// The bound below is ~1000x looser than the measured cost and still ~48x
    /// below the scanning implementation, so it discriminates without being
    /// sensitive to machine load.
    #[test]
    fn insert_cost_stays_flat_when_the_cache_is_full() {
        let cache = BlockDecisionCache::with_capacity(L1_CAPACITY);
        for k in 0..L1_CAPACITY as u64 {
            cache.set_by_key(k.wrapping_mul(0x9E37_79B9_7F4A_7C15), Verdict::NoMatch);
        }

        let samples = 2_000u64;
        let start = Instant::now();
        for k in 0..samples {
            cache.set_by_key(
                (u64::MAX - k).wrapping_mul(0x9E37_79B9_7F4A_7C15),
                Verdict::Block(BlockSource::Blocklist),
            );
        }
        let per_insert = start.elapsed() / samples as u32;

        assert!(
            per_insert < std::time::Duration::from_micros(50),
            "insert into a full cache took {per_insert:?}, which suggests eviction \
             is scanning the cache instead of evicting in constant time"
        );
    }
}
