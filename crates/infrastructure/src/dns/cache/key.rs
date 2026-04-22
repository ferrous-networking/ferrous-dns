use compact_str::CompactString;
use equivalent::Equivalent;
use ferrous_dns_domain::RecordType;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Eq)]
pub struct CacheKey {
    pub domain: CompactString,
    pub record_type: RecordType,
}

impl CacheKey {
    /// Creates a new cache key, normalizing `domain` to ASCII-lowercase
    /// (RFC 1035: DNS names are case-insensitive).
    ///
    /// Fast path: when the input is already lowercase, the bytes are moved
    /// directly into a `CompactString` with no extra allocation. If any byte
    /// is uppercase, a stack buffer holds the lowercased copy before it is
    /// materialized into the `CompactString`.
    #[inline]
    pub fn new(domain: &str, record_type: RecordType) -> Self {
        let domain = normalize_domain_to_compact(domain);
        Self {
            domain,
            record_type,
        }
    }
}

/// Builds a lowercased `CompactString` from `domain` with zero heap allocation
/// on the fast path (when the input is already lowercase).
#[inline]
fn normalize_domain_to_compact(domain: &str) -> CompactString {
    if domain.bytes().all(|b| !b.is_ascii_uppercase()) {
        return CompactString::from(domain);
    }

    // Slow path: copy bytes into a stack buffer while lowercasing; most
    // DNS domains fit in 253 bytes (RFC 1035 §2.3.4).
    const MAX_DOMAIN_LEN: usize = 253;
    let bytes = domain.as_bytes();
    if bytes.len() <= MAX_DOMAIN_LEN {
        let mut buf = [0u8; MAX_DOMAIN_LEN];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }
        // SAFETY: input was valid UTF-8 and ASCII lowercasing preserves UTF-8.
        let s = unsafe { std::str::from_utf8_unchecked(&buf[..bytes.len()]) };
        CompactString::from(s)
    } else {
        // Domains longer than the RFC 1035 cap are accepted but fall back to
        // a heap-allocated owned string during normalization.
        let mut owned = String::with_capacity(bytes.len());
        for &b in bytes {
            owned.push(b.to_ascii_lowercase() as char);
        }
        CompactString::from(owned)
    }
}

impl Hash for CacheKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.as_str().hash(state);
        std::mem::discriminant(&self.record_type).hash(state);
    }
}

impl PartialEq for CacheKey {
    #[inline]
    fn eq(&self, other: &CacheKey) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}

#[derive(Debug)]
pub struct BorrowedKey<'a> {
    pub domain: &'a str,
    pub record_type: RecordType,
}

impl<'a> BorrowedKey<'a> {
    /// Creates a zero-copy key view. Callers must pass an already
    /// ASCII-lowercased `domain`, because `BorrowedKey` is equivalent
    /// (under `Equivalent<CacheKey>`) to `CacheKey`, which stores its
    /// domain lowercased.
    #[inline]
    pub fn new(domain: &'a str, record_type: RecordType) -> Self {
        debug_assert!(
            domain.bytes().all(|b| !b.is_ascii_uppercase()),
            "BorrowedKey domain must be ASCII-lowercased by the caller; got `{}`",
            domain
        );
        Self {
            domain,
            record_type,
        }
    }
}

impl<'a> Hash for BorrowedKey<'a> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
        std::mem::discriminant(&self.record_type).hash(state);
    }
}

impl<'a> PartialEq for BorrowedKey<'a> {
    #[inline]
    fn eq(&self, other: &BorrowedKey<'a>) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}

impl<'a> Eq for BorrowedKey<'a> {}

impl<'a> PartialEq<CacheKey> for BorrowedKey<'a> {
    #[inline]
    fn eq(&self, other: &CacheKey) -> bool {
        self.record_type == other.record_type && self.domain == other.domain.as_str()
    }
}

impl<'a> PartialEq<BorrowedKey<'a>> for CacheKey {
    #[inline]
    fn eq(&self, other: &BorrowedKey<'a>) -> bool {
        self.record_type == other.record_type && self.domain.as_str() == other.domain
    }
}

impl<'a> Equivalent<CacheKey> for BorrowedKey<'a> {
    #[inline]
    fn equivalent(&self, key: &CacheKey) -> bool {
        self.record_type == key.record_type && self.domain == key.domain.as_str()
    }
}
