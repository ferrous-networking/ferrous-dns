use ferrous_dns_domain::RecordType;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[derive(Clone, Debug, Eq)]
pub struct CacheKey {
    pub domain: Arc<str>,
    pub record_type: RecordType,
}

impl CacheKey {
    #[inline]
    pub fn new(domain: Arc<str>, record_type: RecordType) -> Self {
        Self {
            domain,
            record_type,
        }
    }

    #[inline]
    pub fn from_str(domain: &str, record_type: RecordType) -> Self {
        Self {
            domain: Arc::from(domain),
            record_type,
        }
    }
}

impl Hash for CacheKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        let s: &str = &self.domain;
        s.hash(state);
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
        self.record_type == other.record_type && self.domain == other.domain.as_ref()
    }
}

impl<'a> PartialEq<BorrowedKey<'a>> for CacheKey {
    #[inline]
    fn eq(&self, other: &BorrowedKey<'a>) -> bool {
        self.record_type == other.record_type && self.domain.as_ref() == other.domain
    }
}
