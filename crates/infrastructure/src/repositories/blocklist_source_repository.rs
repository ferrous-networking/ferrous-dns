use super::list_source_sql::{SourceRecord, SourceStore, BLOCKLIST};
use async_trait::async_trait;
use ferrous_dns_application::ports::BlocklistSourceRepository;
use ferrous_dns_domain::{BlocklistSource, DomainError};
use sqlx::SqlitePool;

pub struct SqliteBlocklistSourceRepository {
    store: SourceStore,
}

impl SqliteBlocklistSourceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            store: SourceStore::new(pool, &BLOCKLIST),
        }
    }
}

impl From<SourceRecord> for BlocklistSource {
    fn from(r: SourceRecord) -> Self {
        Self {
            id: Some(r.id),
            name: r.name,
            url: r.url,
            group_ids: r.group_ids,
            comment: r.comment,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_synced_at: r.last_synced_at,
            last_status: r.last_status,
        }
    }
}

#[async_trait]
impl BlocklistSourceRepository for SqliteBlocklistSourceRepository {
    async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        self.store
            .create(name, url, group_ids, comment, enabled)
            .await
            .map(Into::into)
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<BlocklistSource>, DomainError> {
        Ok(self.store.get_by_id(id).await?.map(Into::into))
    }

    async fn get_all(&self) -> Result<Vec<BlocklistSource>, DomainError> {
        Ok(self
            .store
            .get_all()
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_ids: Option<Vec<i64>>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<BlocklistSource, DomainError> {
        self.store
            .update(id, name, url, group_ids, comment, enabled)
            .await
            .map(Into::into)
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        self.store.delete(id).await
    }
}
