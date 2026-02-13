use ferrous_dns_domain::{DomainError, SubnetMatcher};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::ports::ClientSubnetRepository;

/// Service that maintains cached subnet matcher for fast lookups
pub struct SubnetMatcherService {
    subnet_repo: Arc<dyn ClientSubnetRepository>,
    matcher: Arc<RwLock<Option<SubnetMatcher>>>,
}

impl SubnetMatcherService {
    pub fn new(subnet_repo: Arc<dyn ClientSubnetRepository>) -> Self {
        Self {
            subnet_repo,
            matcher: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize/refresh the matcher from database
    #[instrument(skip(self))]
    pub async fn refresh(&self) -> Result<(), DomainError> {
        let subnets = self.subnet_repo.get_all().await?;
        let new_matcher = SubnetMatcher::new(subnets).map_err(DomainError::InvalidCidr)?;

        *self.matcher.write().await = Some(new_matcher);
        debug!("Subnet matcher refreshed");
        Ok(())
    }

    /// Find group_id for IP address, returns None if no match
    #[instrument(skip(self))]
    pub async fn find_group_for_ip(&self, ip: IpAddr) -> Option<i64> {
        let matcher = self.matcher.read().await;
        matcher.as_ref().and_then(|m| m.find_group_for_ip(ip))
    }
}
