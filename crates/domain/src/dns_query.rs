use super::RecordType;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub domain: Arc<str>,
    pub record_type: RecordType,
}

impl DnsQuery {
    pub fn new(domain: impl Into<Arc<str>>, record_type: RecordType) -> Self {
        Self {
            domain: domain.into(),
            record_type,
        }
    }
}
