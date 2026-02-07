//! Cache key types optimized for zero-allocation lookups.
//!
//! `CacheKey` uses `CompactString` instead of `String` to store domain names.
//! CompactString stores strings up to 24 bytes inline on the stack without
//! heap allocation. Since most DNS domains are under 24 bytes (e.g.,
//! "google.com" = 10, "api.github.com" = 14), this eliminates heap allocation
//! for the vast majority of cache operations.

use compact_str::CompactString;
use ferrous_dns_domain::RecordType;
use std::hash::{Hash, Hasher};

/// Cache key with inline domain storage.
#[derive(Clone, Debug, Eq)]
pub struct CacheKey {
    pub domain: CompactString,
    pub record_type: RecordType,
}

impl CacheKey {
    #[inline]
    pub fn new(domain: impl Into<CompactString>, record_type: RecordType) -> Self {
        Self {
            domain: domain.into(),
            record_type,
        }
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

/// Borrowed key for zero-allocation lookups in bloom filter and L1 cache.
#[derive(Debug)]
pub struct BorrowedKey<'a> {
    pub domain: &'a str,
    pub record_type: RecordType,
}

impl<'a> BorrowedKey<'a> {
    #[inline]
    pub fn new(domain: &'a str, record_type: RecordType) -> Self {
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
