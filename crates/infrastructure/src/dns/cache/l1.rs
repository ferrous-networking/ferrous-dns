use crate::dns::cache::coarse_clock::coarse_now_secs;
use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

type L1Hit = (Arc<Vec<IpAddr>>, u32);

struct L1Entry {
    addresses: Arc<Vec<IpAddr>>,
    expires_secs: u64,
}

thread_local! {
    static L1_CACHE: RefCell<LruCache<CompactString, L1Entry, FxBuildHasher>> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(1024).unwrap(),
            FxBuildHasher
        ));
}

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
    L1_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(entry) = cache.get(key_str) {
            let now = coarse_now_secs();
            if now < entry.expires_secs {
                let remaining = (entry.expires_secs - now).min(u32::MAX as u64) as u32;
                return Some((Arc::clone(&entry.addresses), remaining));
            }
            cache.pop(key_str);
        }

        None
    })
}

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

    L1_CACHE.with(|cache| {
        cache.borrow_mut().put(
            key,
            L1Entry {
                addresses,
                expires_secs,
            },
        );
    });
}

#[inline]
pub fn l1_clear() {
    L1_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
}
