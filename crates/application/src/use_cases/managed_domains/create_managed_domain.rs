use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, ManagedDomain};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{
    BlockFilterEnginePort, GroupRepository, ManagedDomainRepository, NewManagedDomain,
};

pub struct CreateManagedDomainUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl CreateManagedDomainUseCase {
    pub fn new(
        repo: Arc<dyn ManagedDomainRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            repo,
            group_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, new: NewManagedDomain) -> Result<ManagedDomain, DomainError> {
        ManagedDomain::validate_name(&new.name).map_err(DomainError::InvalidManagedDomain)?;
        ManagedDomain::validate_domain(&new.domain).map_err(DomainError::InvalidManagedDomain)?;
        validate_comment(new.comment.as_deref()).map_err(DomainError::InvalidManagedDomain)?;
        if let Some(expires_in) = new.expires_in {
            ManagedDomain::validate_expiry(expires_in)
                .map_err(DomainError::InvalidManagedDomain)?;
        }

        require_group(self.group_repo.as_ref(), new.group_id).await?;

        let managed_domain = self.repo.create(new).await?;

        info!(
            domain_id = ?managed_domain.id,
            name = %managed_domain.name,
            domain = %managed_domain.domain,
            action = %managed_domain.action.to_str(),
            group_id = managed_domain.group_id,
            expires_at = ?managed_domain.expires_at,
            "Managed domain created successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after managed domain creation");
        }

        Ok(managed_domain)
    }
}
