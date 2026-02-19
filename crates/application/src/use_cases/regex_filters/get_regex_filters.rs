use ferrous_dns_domain::{DomainError, RegexFilter};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::RegexFilterRepository;

pub struct GetRegexFiltersUseCase {
    repo: Arc<dyn RegexFilterRepository>,
}

impl GetRegexFiltersUseCase {
    pub fn new(repo: Arc<dyn RegexFilterRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<RegexFilter>, DomainError> {
        self.repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<RegexFilter>, DomainError> {
        self.repo.get_by_id(id).await
    }
}
