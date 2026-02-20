use crate::dns::cache::coarse_clock::coarse_now_secs;
use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

struct L1Entry {
    addresses: Arc<Vec<IpAddr>>,
    expires_secs: u64,
}

thread_local! {
    static L1_CACHE: RefCell<LruCache<(CompactString, RecordType), L1Entry, FxBuildHasher>> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(512).unwrap(),
            FxBuildHasher
        ));
}

#[inline]
pub fn l1_get(domain: &str, record_type: &RecordType) -> Option<(Arc<Vec<IpAddr>>, u32)> {
    L1_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (CompactString::from(domain), *record_type);

        if let Some(entry) = cache.get(&key) {
            let now = coarse_now_secs();
            if now < entry.expires_secs {
                let remaining = (entry.expires_secs - now) as u32;
                return Some((Arc::clone(&entry.addresses), remaining));
            }
            cache.pop(&key);
        }

        None
    })
}

#[inline]
pub fn l1_insert(
    domain: &str,
    record_type: &RecordType,
    addresses: Arc<Vec<IpAddr>>,
    ttl_secs: u32,
) {
    L1_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (CompactString::from(domain), *record_type);
        let entry = L1Entry {
            addresses,
            expires_secs: coarse_now_secs() + ttl_secs as u64,
        };
        cache.put(key, entry);
    });
}
