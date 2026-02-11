use super::filters::QueryFilters;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tracing::debug;

/// Filtered resolver decorator
///
/// Applies query filters before passing to inner resolver
pub struct FilteredResolver {
    inner: Arc<dyn DnsResolver>,
    filters: QueryFilters,
}

impl FilteredResolver {
    /// Wrap a resolver with filters
    pub fn new(inner: Arc<dyn DnsResolver>, filters: QueryFilters) -> Self {
        Self { inner, filters }
    }
}

#[async_trait]
impl DnsResolver for FilteredResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // Apply filters first
        let filtered_query = self.filters.apply(query.clone())?;

        if filtered_query.domain != query.domain {
            debug!(
                original = %query.domain,
                filtered = %filtered_query.domain,
                "Query domain modified by filters"
            );
        }

        // Pass to inner resolver
        self.inner.resolve(&filtered_query).await
    }
}
