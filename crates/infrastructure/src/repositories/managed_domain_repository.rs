use crate::repositories::{
    contains_pattern, db_err, is_fk_violation, is_unique_violation, parse_db_action, sql_now,
};
use async_trait::async_trait;
use ferrous_dns_application::ports::{ManagedDomainRepository, ManagedDomainUpdate};
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::instrument;

type ManagedDomainRow = (
    i64,
    String,
    String,
    String,
    i64,
    Option<String>,
    bool,
    Option<String>,
    String,
    String,
);

pub struct SqliteManagedDomainRepository {
    pool: SqlitePool,
}

impl SqliteManagedDomainRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_domain(row: ManagedDomainRow) -> ManagedDomain {
        let (
            id,
            name,
            domain,
            action,
            group_id,
            comment,
            enabled,
            service_id,
            created_at,
            updated_at,
        ) = row;
        ManagedDomain {
            id: Some(id),
            name: Arc::from(name.as_str()),
            domain: Arc::from(domain.as_str()),
            action: parse_db_action(&action),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            enabled,
            service_id: service_id.map(|s| Arc::from(s.as_str())),
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl ManagedDomainRepository for SqliteManagedDomainRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        domain: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<ManagedDomain, DomainError> {
        let now = sql_now();

        let row = sqlx::query_as::<_, ManagedDomainRow>(
            "INSERT INTO managed_domains (name, domain, action, group_id, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             RETURNING id, name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at",
        )
        .bind(&name)
        .bind(&domain)
        .bind(action.to_str())
        .bind(group_id)
        .bind(&comment)
        .bind(enabled)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::AlreadyExists(format!(
                    "Managed domain '{name}' already exists in group {group_id}"
                ))
            } else if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to create managed domain")(e)
            }
        })?;

        Ok(Self::row_to_domain(row))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<ManagedDomain>, DomainError> {
        let row = sqlx::query_as::<_, ManagedDomainRow>(
            "SELECT id, name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at
             FROM managed_domains WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query managed domain by id"))?;

        Ok(row.map(Self::row_to_domain))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<ManagedDomain>, DomainError> {
        let rows = sqlx::query_as::<_, ManagedDomainRow>(
            "SELECT id, name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at
             FROM managed_domains ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all managed domains"))?;

        Ok(rows.into_iter().map(Self::row_to_domain).collect())
    }

    #[instrument(skip(self))]
    async fn get_all_paged(
        &self,
        limit: u32,
        offset: u32,
        search: Option<&str>,
    ) -> Result<(Vec<ManagedDomain>, u64), DomainError> {
        let pattern = search.map(contains_pattern);
        // Static SQL either way; the search only ever reaches the query as a bind.
        let where_clause = if pattern.is_some() {
            " WHERE name LIKE ? ESCAPE '\\' OR domain LIKE ? ESCAPE '\\'"
        } else {
            ""
        };

        let count_sql = format!("SELECT COUNT(*) FROM managed_domains{where_clause}");
        let mut count_query = sqlx::query_as::<_, (i64,)>(&count_sql);
        if let Some(pattern) = &pattern {
            count_query = count_query.bind(pattern).bind(pattern);
        }
        let count_row = count_query
            .fetch_one(&self.pool)
            .await
            .map_err(db_err("Failed to count managed domains"))?;
        let total = count_row.0 as u64;

        // A name is unique only within its group, so the group breaks ties and
        // every page boundary falls in the same place on every request.
        let page_sql = format!(
            "SELECT id, name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at
             FROM managed_domains{where_clause} ORDER BY name ASC, group_id ASC LIMIT ? OFFSET ?"
        );
        let mut page_query = sqlx::query_as::<_, ManagedDomainRow>(&page_sql);
        if let Some(pattern) = &pattern {
            page_query = page_query.bind(pattern).bind(pattern);
        }
        let rows = page_query
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await
            .map_err(db_err("Failed to query managed domains paged"))?;

        Ok((rows.into_iter().map(Self::row_to_domain).collect(), total))
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        update: ManagedDomainUpdate,
    ) -> Result<ManagedDomain, DomainError> {
        let ManagedDomainUpdate {
            name,
            domain,
            action,
            group_id,
            comment,
            enabled,
        } = update;
        let replace_comment = comment.is_some();
        let comment = comment.flatten();
        let row = sqlx::query_as::<_, ManagedDomainRow>(
            "UPDATE managed_domains
             SET name = COALESCE(?, name),
                 domain = COALESCE(?, domain),
                 action = COALESCE(?, action),
                 group_id = COALESCE(?, group_id),
                 comment = CASE WHEN ? THEN ? ELSE comment END,
                 enabled = COALESCE(?, enabled),
                 updated_at = ?
             WHERE id = ?
             RETURNING id, name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at",
        )
        .bind(&name)
        .bind(&domain)
        .bind(action.map(|a| a.to_str()))
        .bind(group_id)
        .bind(replace_comment)
        .bind(&comment)
        .bind(enabled)
        .bind(sql_now())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::AlreadyExists(format!(
                    "Managed domain '{}' already exists in the target group",
                    name.as_deref().unwrap_or_default()
                ))
            } else if let Some(gid) = group_id.filter(|_| is_fk_violation(&e)) {
                DomainError::GroupNotFound(gid)
            } else {
                db_err("Failed to update managed domain")(e)
            }
        })?;

        row.map(Self::row_to_domain)
            .ok_or(DomainError::ManagedDomainNotFound(id))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM managed_domains WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete managed domain"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ManagedDomainNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self, domains))]
    async fn bulk_create_for_service(
        &self,
        service_id: &str,
        group_id: i64,
        domains: Vec<(String, String)>,
    ) -> Result<usize, DomainError> {
        let now = sql_now();
        let mut count = 0usize;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(db_err("Failed to begin transaction for bulk create"))?;

        for (name, domain) in &domains {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO managed_domains
                 (name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at)
                 VALUES (?, ?, 'deny', ?, NULL, 1, ?, ?, ?)",
            )
            .bind(name)
            .bind(domain)
            .bind(group_id)
            .bind(service_id)
            .bind(&now)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(db_err("Failed to bulk create managed domain"))?;

            if result.rows_affected() > 0 {
                count += 1;
            }
        }

        tx.commit()
            .await
            .map_err(db_err("Failed to commit bulk create transaction"))?;

        Ok(count)
    }

    #[instrument(skip(self))]
    async fn delete_by_service(&self, service_id: &str, group_id: i64) -> Result<u64, DomainError> {
        let result =
            sqlx::query("DELETE FROM managed_domains WHERE service_id = ? AND group_id = ?")
                .bind(service_id)
                .bind(group_id)
                .execute(&self.pool)
                .await
                .map_err(db_err("Failed to delete managed domains by service"))?;

        Ok(result.rows_affected())
    }

    #[instrument(skip(self))]
    async fn delete_all_by_service(&self, service_id: &str) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM managed_domains WHERE service_id = ?")
            .bind(service_id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete all managed domains by service"))?;

        Ok(result.rows_affected())
    }
}
