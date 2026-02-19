use async_trait::async_trait;
use ferrous_dns_domain::{DomainAction, DomainError, RegexFilter};

#[async_trait]
pub trait RegexFilterRepository: Send + Sync {
    async fn create(
        &self,
        name: String,
        pattern: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<RegexFilter, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<RegexFilter>, DomainError>;

    async fn get_all(&self) -> Result<Vec<RegexFilter>, DomainError>;

    #[allow(clippy::too_many_arguments)]
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        pattern: Option<String>,
        action: Option<DomainAction>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<RegexFilter, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    async fn get_enabled(&self) -> Result<Vec<RegexFilter>, DomainError>;
}
