use super::data::CachedDnssecStatus;
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

/// Addresses, DNSSEC status, whether the local DNS server answered, remaining
/// TTL, and the hits this entry has batched for its L2 record (0 most of the
/// time; see [`L1Entry::pending_hits`]). Kept at 16 bytes so it still comes
/// back in two registers on the hottest call in the resolver.
type L1Hit = (Arc<Vec<IpAddr>>, CachedDnssecStatus, bool, u32, u16);

struct L1Entry {
    addresses: Arc<Vec<IpAddr>>,
    dnssec_status: CachedDnssecStatus,
    // Packs with `dnssec_status` and the counters below: the entry is 32
    // bytes, and a thread holds at most `L1_CAPACITY` of them.
    local_dns: bool,
    /// Hits served here and not yet counted on the L2 record. A hit served
    /// by L1 never reaches L2, which holds the counters refresh eligibility
    /// and eviction read, so they are handed over in batches: at most once
    /// per second per thread, or as soon as the batch fills a `u16`. That
    /// keeps a hot name from bouncing one shared cache line between every
    /// worker thread, and no hit is lost.
    pending_hits: u16,
    expires_secs: u64,
    /// Low 32 bits of the coarse second the last batch was handed over in;
    /// only compared for equality, so the truncation is harmless.
    flushed_at_secs: u32,
}

struct L1State {
    cache: LruCache<CompactString, L1Entry, FxBuildHasher>,
    generation: u64,
}

static L1_GLOBAL_GENERATION: AtomicU64 = AtomicU64::new(0);

const L1_CAPACITY: NonZeroUsize = match NonZeroUsize::new(1024) {
    Some(capacity) => capacity,
    None => NonZeroUsize::MIN,
};

/// Longest `"Type:domain"` key built on the stack; longer ones use the heap.
const STACK_KEY_LEN: usize = 260;

thread_local! {
    static L1_CACHE: RefCell<L1State> =
        RefCell::new(L1State {
            cache: LruCache::with_hasher(L1_CAPACITY, FxBuildHasher),
            generation: 0,
        });
}

/// Writes the `"Type:domain"` key into `buf`, ASCII-lowercasing the domain so
/// every case variant shares an entry (RFC 1035 §2.3.3). `None` if it does
/// not fit.
#[inline(always)]
fn stack_key<'b>(
    buf: &'b mut [u8; STACK_KEY_LEN],
    type_str: &str,
    domain: &str,
) -> Option<&'b str> {
    let type_len = type_str.len();
    let key = buf.get_mut(..type_len + 1 + domain.len())?;
    key[..type_len].copy_from_slice(type_str.as_bytes());
    key[type_len] = b':';
    for (dst, &b) in key[type_len + 1..].iter_mut().zip(domain.as_bytes()) {
        *dst = b.to_ascii_lowercase();
    }
    // SAFETY: `type_str` and `domain` are valid UTF-8 and ASCII lowercasing
    // rewrites only single-byte scalars, so `key` is valid UTF-8 as well.
    Some(unsafe { std::str::from_utf8_unchecked(key) })
}

/// [`stack_key`] for a key too long for the stack buffer.
fn heap_key(type_str: &str, domain: &str) -> CompactString {
    let mut key = CompactString::with_capacity(type_str.len() + 1 + domain.len());
    key.push_str(type_str);
    key.push(':');
    key.push_str(domain);
    key.as_mut_str()[type_str.len() + 1..].make_ascii_lowercase();
    key
}

/// Looks up a domain in the thread-local L1 cache, returning addresses and remaining TTL.
#[inline]
pub fn l1_get(domain: &str, record_type: &RecordType) -> Option<L1Hit> {
    let type_str = record_type.as_str();
    let mut buf = [0u8; STACK_KEY_LEN];
    match stack_key(&mut buf, type_str, domain) {
        Some(key) => lookup_l1(key),
        None => lookup_l1(&heap_key(type_str, domain)),
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
        if let Some(entry) = state.cache.get_mut(key_str) {
            let now = coarse_now_secs();
            if now < entry.expires_secs {
                let remaining = (entry.expires_secs - now).min(u32::MAX as u64) as u32;
                entry.pending_hits += 1;
                let second = now as u32;
                let flushed = if entry.flushed_at_secs == second && entry.pending_hits < u16::MAX {
                    0
                } else {
                    entry.flushed_at_secs = second;
                    std::mem::take(&mut entry.pending_hits)
                };
                return Some((
                    Arc::clone(&entry.addresses),
                    entry.dnssec_status,
                    entry.local_dns,
                    remaining,
                    flushed,
                ));
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
    dnssec_status: CachedDnssecStatus,
    local_dns: bool,
    expires_secs: u64,
) {
    let type_str = record_type.as_str();
    let mut buf = [0u8; STACK_KEY_LEN];
    let key = match stack_key(&mut buf, type_str, domain) {
        Some(key) => CompactString::from(key),
        None => heap_key(type_str, domain),
    };

    L1_CACHE.with(|state| {
        state.borrow_mut().cache.put(
            key,
            L1Entry {
                addresses,
                dnssec_status,
                local_dns,
                pending_hits: 0,
                expires_secs,
                flushed_at_secs: coarse_now_secs() as u32,
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
