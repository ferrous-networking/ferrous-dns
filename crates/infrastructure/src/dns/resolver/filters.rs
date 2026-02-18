use ferrous_dns_domain::{DnsQuery, DomainError, FqdnFilter, PrivateIpFilter};
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct QueryFilters {
    pub block_private_ptr: bool,
    pub block_non_fqdn: bool,
    pub local_domain: Option<String>,
}

impl QueryFilters {
    
    pub fn new(
        block_private_ptr: bool,
        block_non_fqdn: bool,
        local_domain: Option<String>,
    ) -> Self {
        Self {
            block_private_ptr,
            block_non_fqdn,
            local_domain,
        }
    }

    pub fn apply(&self, mut query: DnsQuery) -> Result<DnsQuery, DomainError> {
        
        if self.block_private_ptr && PrivateIpFilter::is_private_ptr_query(&query.domain) {
            return Err(DomainError::FilteredQuery(format!(
                "Private PTR query blocked: {}",
                query.domain
            )));
        }

        if self.block_non_fqdn {
            if FqdnFilter::is_local_hostname(&query.domain) {
                return Err(DomainError::FilteredQuery(format!(
                    "Non-FQDN query blocked: {}",
                    query.domain
                )));
            }
        } else if let Some(ref domain) = self.local_domain {
            
            if !query.domain.contains('.') {
                debug!(
                    original = %query.domain,
                    local_domain = %domain,
                    "Appending local domain to non-FQDN query"
                );
                query.domain = Arc::from(format!("{}.{}", query.domain, domain));
            }
        }

        Ok(query)
    }

    pub fn is_enabled(&self) -> bool {
        self.block_private_ptr || self.block_non_fqdn || self.local_domain.is_some()
    }
}

impl Default for QueryFilters {
    fn default() -> Self {
        Self {
            block_private_ptr: true,
            block_non_fqdn: false,
            local_domain: None,
        }
    }
}
