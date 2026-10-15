use crate::dns::load_balancer::UpstreamRouter;
use ferrous_dns_domain::{DnsQuery, DomainError, FqdnFilter, PrivateIpFilter};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

/// What happens to a single-label (non-FQDN) query name.
#[derive(Clone)]
pub enum NonFqdn {
    Block,
    /// Append this local domain.
    Qualify(String),
    Pass,
}

#[derive(Clone)]
pub struct QueryFilters {
    block_private_ptr: bool,
    non_fqdn: NonFqdn,
    /// Lets a private reverse zone a conditional pool answers through
    /// `block_private_ptr`, as an office's own server answers it.
    router: Option<Arc<dyn UpstreamRouter>>,
}

impl QueryFilters {
    /// `block_private_ptr` must already be off when a local DNS server answers
    /// private PTRs.
    pub fn new(block_private_ptr: bool, non_fqdn: NonFqdn) -> Self {
        Self {
            block_private_ptr,
            non_fqdn,
            router: None,
        }
    }

    pub fn with_router(mut self, router: Arc<dyn UpstreamRouter>) -> Self {
        self.router = Some(router);
        self
    }

    pub fn apply(&self, mut query: DnsQuery) -> Result<DnsQuery, DomainError> {
        match self.decide(&query.domain, query.group_id) {
            Ok(Cow::Borrowed(_)) => Ok(query),
            Ok(Cow::Owned(qualified)) => {
                debug!(
                    original = %query.domain,
                    qualified = %qualified,
                    "Appending local domain to non-FQDN query"
                );
                query.domain = Arc::from(qualified);
                Ok(query)
            }
            Err(reason) => Err(DomainError::FilteredQuery(format!(
                "{reason}: {}",
                query.domain
            ))),
        }
    }

    /// Same decision as [`apply`](Self::apply) on a borrowed name, so the cache
    /// fast path pays no `Arc` allocation. `None` means the query is dropped.
    /// `group_id` is the asking client's group.
    pub fn apply_str<'a>(&self, domain: &'a str, group_id: Option<i64>) -> Option<Cow<'a, str>> {
        self.decide(domain, group_id).ok()
    }

    fn decide<'a>(
        &self,
        domain: &'a str,
        group_id: Option<i64>,
    ) -> Result<Cow<'a, str>, &'static str> {
        if self.block_private_ptr
            && PrivateIpFilter::is_private_ptr_query(domain)
            && !self.is_routed(domain, group_id)
        {
            return Err("Private PTR query blocked");
        }

        match &self.non_fqdn {
            NonFqdn::Block if FqdnFilter::is_local_hostname(domain) => {
                Err("Non-FQDN query blocked")
            }
            NonFqdn::Qualify(local_domain) if !domain.contains('.') => {
                Ok(Cow::Owned(format!("{domain}.{local_domain}")))
            }
            NonFqdn::Block | NonFqdn::Qualify(_) | NonFqdn::Pass => Ok(Cow::Borrowed(domain)),
        }
    }

    fn is_routed(&self, domain: &str, group_id: Option<i64>) -> bool {
        self.router
            .as_ref()
            .is_some_and(|router| router.route(domain, group_id).is_some())
    }
}
