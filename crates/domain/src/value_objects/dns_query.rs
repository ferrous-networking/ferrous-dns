use crate::dns_record::RecordType;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    /// The asking client's group, which picks the conditional pools routed for
    /// it. `None` for a query no client asked, such as a cache refresh of an
    /// answer every client shares.
    pub group_id: Option<i64>,
}

impl DnsQuery {
    pub fn new(domain: impl Into<Arc<str>>, record_type: RecordType) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            group_id: None,
        }
    }

    pub fn with_group(mut self, group_id: Option<i64>) -> Self {
        self.group_id = group_id;
        self
    }
}
