use crate::dns::cache::coarse_clock::coarse_now_secs;
use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;

type L1Hit = (Arc<Vec<IpAddr>>, u32);

struct L1Entry {
    addresses: Arc<Vec<IpAddr>>,
    expires_secs: u64,
}

struct L1State {
    cache: LruCache<CompactString, L1Entry, FxBuildHasher>,
    generation: u64,
}

static L1_GLOBAL_GENERATION: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static L1_CACHE: RefCell<L1State> =
        RefCell::new(L1State {
            cache: LruCache::with_hasher(
                NonZeroUsize::new(1024).unwrap(),
                FxBuildHasher
            ),
            generation: 0,
        });
}

/// Looks up a domain in the thread-local L1 cache, returning addresses and remaining TTL.
#[inline]
pub fn l1_get(domain: &str, record_type: &RecordType) -> Option<L1Hit> {
    let type_str = record_type.as_str();
    let type_len = type_str.len();
    let dom_len = domain.len();
    let total = type_len + 1 + dom_len;

    let mut buf = [0u8; 260];
    if total <= buf.len() {
        buf[..type_len].copy_from_slice(type_str.as_bytes());
        buf[type_len] = b':';
        buf[type_len + 1..total].copy_from_slice(domain.as_bytes());
        // SAFETY: composed from valid UTF-8 slices (type_str, ':', domain)
        let key_str = unsafe { std::str::from_utf8_unchecked(&buf[..total]) };
        lookup_l1(key_str)
    } else {
        let mut key = CompactString::with_capacity(total);
        key.push_str(type_str);
        key.push(':');
        key.push_str(domain);
        lookup_l1(&key)
    }
}

#[inline]
fn lookup_l1(key_str: &str) -> Option<L1Hit> {
    L1_CACHE.with(|state| {
        let mut state = state.borrow_mut();
        let global_gen = L1_GLOBAL_GENERATION.load(AtomicOrdering::Acquire);
        if state.generation != global_gen {
            state.cache.clear();
            state.generation = global_gen;
            return None;
        }
        if let Some(entry) = state.cache.get(key_str) {
            let now = coarse_now_secs();
            if now < entry.expires_secs {
                let remaining = (entry.expires_secs - now).min(u32::MAX as u64) as u32;
                return Some((Arc::clone(&entry.addresses), remaining));
            }
            state.cache.pop(key_str);
        }

        None
    })
}

/// Inserts a resolved entry into the thread-local L1 cache with an expiration timestamp.
#[inline]
pub fn l1_insert(
    domain: &str,
    record_type: &RecordType,
    addresses: Arc<Vec<IpAddr>>,
    expires_secs: u64,
) {
    let type_str = record_type.as_str();
    let type_len = type_str.len();
    let dom_len = domain.len();
    let total = type_len + 1 + dom_len;

    let mut buf = [0u8; 260];
    let key = if total <= buf.len() {
        buf[..type_len].copy_from_slice(type_str.as_bytes());
        buf[type_len] = b':';
        buf[type_len + 1..total].copy_from_slice(domain.as_bytes());
        // SAFETY: composed from valid UTF-8 slices (type_str, ':', domain)
        CompactString::from(unsafe { std::str::from_utf8_unchecked(&buf[..total]) })
    } else {
        let mut key = CompactString::with_capacity(total);
        key.push_str(type_str);
        key.push(':');
        key.push_str(domain);
        key
    };

    L1_CACHE.with(|state| {
        state.borrow_mut().cache.put(
            key,
            L1Entry {
                addresses,
                expires_secs,
            },
        );
    });
}

/// Clears this thread's L1 cache and bumps the global generation
/// so all other threads invalidate on next access.
#[inline]
pub fn l1_clear() {
    L1_GLOBAL_GENERATION.fetch_add(1, AtomicOrdering::Release);
    L1_CACHE.with(|state| {
        let mut state = state.borrow_mut();
        state.cache.clear();
        state.generation = L1_GLOBAL_GENERATION.load(AtomicOrdering::Acquire);
    });
}
