use async_trait::async_trait;
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};

/// Fields to change on a managed domain; `None` keeps the stored value, and
/// `comment: Some(None)` clears it.
#[derive(Debug, Clone, Default)]
pub struct ManagedDomainUpdate {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub action: Option<DomainAction>,
    pub group_id: Option<i64>,
    pub comment: Option<Option<String>>,
    pub enabled: Option<bool>,
}

#[async_trait]
pub trait ManagedDomainRepository: Send + Sync {
    async fn create(
        &self,
        name: String,
        domain: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<ManagedDomain, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<ManagedDomain>, DomainError>;

    async fn get_all(&self) -> Result<Vec<ManagedDomain>, DomainError>;

    /// One page sorted by name, then group. `search` keeps only the domains whose
    /// name or domain contains it, ignoring ASCII case; the total counts those.
    async fn get_all_paged(
        &self,
        limit: u32,
        offset: u32,
        search: Option<&str>,
    ) -> Result<(Vec<ManagedDomain>, u64), DomainError>;

    async fn update(
        &self,
        id: i64,
        update: ManagedDomainUpdate,
    ) -> Result<ManagedDomain, DomainError>;

    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    async fn bulk_create_for_service(
        &self,
        service_id: &str,
        group_id: i64,
        domains: Vec<(String, String)>,
    ) -> Result<usize, DomainError>;

    async fn delete_by_service(&self, service_id: &str, group_id: i64) -> Result<u64, DomainError>;

    async fn delete_all_by_service(&self, service_id: &str) -> Result<u64, DomainError>;
}
