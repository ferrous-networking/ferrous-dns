use ferrous_dns_domain::RecordType;
use std::hash::{Hash, Hasher};

/// Cache key - Simple owned version (no lifetime issues!)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub domain: String,
    pub record_type: RecordType,
}

impl CacheKey {
    #[inline]
    pub fn new(domain: String, record_type: RecordType) -> Self {
        Self {
            domain,
            record_type,
        }
    }
}

/// Borrowed key for zero-allocation lookups
#[derive(Debug)]
pub struct BorrowedKey<'a> {
    pub domain: &'a str,
    pub record_type: RecordType,
}

impl<'a> Hash for BorrowedKey<'a> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
        std::mem::discriminant(&self.record_type).hash(state);
    }
}

impl<'a> PartialEq<CacheKey> for BorrowedKey<'a> {
    #[inline]
    fn eq(&self, other: &CacheKey) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}

impl<'a> PartialEq<BorrowedKey<'a>> for CacheKey {
    #[inline]
    fn eq(&self, other: &BorrowedKey<'a>) -> bool {
        self.record_type == other.record_type && self.domain == other.domain
    }
}
