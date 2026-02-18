use super::filters::QueryFilters;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tracing::debug;

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
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let filtered_query = self.filters.apply(query.clone())?;

        if filtered_query.domain != query.domain {
            debug!(
                original = %query.domain,
                filtered = %filtered_query.domain,
                "Query domain modified by filters"
            );
        }

        self.inner.resolve(&filtered_query).await
    }
}
