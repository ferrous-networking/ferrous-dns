use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, WhitelistSource};

#[async_trait]
pub trait WhitelistSourceRepository: Send + Sync {
    async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<WhitelistSource, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<WhitelistSource>, DomainError>;

    async fn get_all(&self) -> Result<Vec<WhitelistSource>, DomainError>;

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<WhitelistSource, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;
}
