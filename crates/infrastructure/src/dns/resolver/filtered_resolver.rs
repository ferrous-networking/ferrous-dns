use super::filters::QueryFilters;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use std::sync::Arc;

pub struct FilteredResolver {
    inner: Arc<dyn DnsResolver>,
    filters: QueryFilters,
}

impl FilteredResolver {
    pub fn new(inner: Arc<dyn DnsResolver>, filters: QueryFilters) -> Self {
        Self { inner, filters }
    }
}

#[async_trait]
impl DnsResolver for FilteredResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        let filtered_query = self.filters.apply(query.clone()).ok()?;
        self.inner.try_cache(&filtered_query)
    }

    fn try_cache_str(&self, domain: &str, record_type: RecordType) -> Option<DnsResolution> {
        let transformed = self.filters.apply_str(domain)?;
        self.inner.try_cache_str(transformed.as_ref(), record_type)
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let filtered_query = self.filters.apply(query.clone())?;

        self.inner.resolve(&filtered_query).await
    }
}
