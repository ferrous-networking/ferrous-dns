use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{
    BlockFilterEnginePort, BulkManagedDomain, CreateManyOutcome, GroupRepository,
    ManagedDomainRepository, NewManagedDomain,
};

/// Domains to add as permanent rules that share an action, a group, a
/// comment and an enabled state.
#[derive(Debug, Clone)]
pub struct BulkNewManagedDomains {
    pub domains: Vec<String>,
    pub action: DomainAction,
    pub group_id: i64,
    pub comment: Option<String>,
    pub enabled: bool,
}

/// What became of one entry: its domain as stored (trimmed and lowercased),
/// and the outcome, or the error the single add gives for it.
#[derive(Debug, Clone)]
pub struct BulkEntryResult {
    pub domain: String,
    pub outcome: Result<CreateManyOutcome, DomainError>,
}

pub struct BulkCreateManagedDomainsUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl BulkCreateManagedDomainsUseCase {
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

    /// Validates each entry as the single add does, writes the valid ones in
    /// one transaction, and rebuilds the block filter once if any was added.
    /// The results line up with `bulk.domains`.
    #[instrument(skip(self, bulk), fields(count = bulk.domains.len()))]
    pub async fn execute(
        &self,
        bulk: BulkNewManagedDomains,
    ) -> Result<Vec<BulkEntryResult>, DomainError> {
        validate_comment(bulk.comment.as_deref()).map_err(DomainError::InvalidManagedDomain)?;
        require_group(self.group_repo.as_ref(), bulk.group_id).await?;

        let checked: Vec<(String, Result<(), DomainError>)> = bulk
            .domains
            .iter()
            .map(|entry| {
                let domain = entry.trim().to_ascii_lowercase();
                let check = ManagedDomain::validate_domain(&domain)
                    .and_then(|()| ManagedDomain::validate_name(&domain))
                    .map_err(DomainError::InvalidManagedDomain);
                (domain, check)
            })
            .collect();

        let batch = checked
            .iter()
            .filter(|(_, check)| check.is_ok())
            .map(|(domain, _)| BulkManagedDomain {
                rule: NewManagedDomain {
                    name: domain.clone(),
                    domain: domain.clone(),
                    action: bulk.action,
                    group_id: bulk.group_id,
                    comment: bulk.comment.clone(),
                    enabled: bulk.enabled,
                    expires_in: None,
                },
                fallback_name: Some(ManagedDomain::fallback_name(domain, bulk.action))
                    .filter(|name| ManagedDomain::validate_name(name).is_ok()),
            })
            .collect();
        let mut stored = self.repo.create_many(batch).await?.into_iter();

        let mut results = Vec::with_capacity(checked.len());
        for (domain, check) in checked {
            let outcome = match check {
                Ok(()) => Ok(stored.next().ok_or_else(|| {
                    DomainError::DatabaseError(
                        "bulk create returned fewer outcomes than entries".to_string(),
                    )
                })?),
                Err(e) => Err(e),
            };
            results.push(BulkEntryResult { domain, outcome });
        }

        let added = results
            .iter()
            .filter(|r| matches!(r.outcome, Ok(CreateManyOutcome::Created(_))))
            .count();
        info!(
            added,
            entries = results.len(),
            action = %bulk.action.to_str(),
            group_id = bulk.group_id,
            "Managed domains created in bulk"
        );

        if added > 0 {
            if let Err(e) = self.block_filter_engine.reload().await {
                error!(error = %e, "Failed to reload block filter after bulk managed domain creation");
            }
        }

        Ok(results)
    }
}
