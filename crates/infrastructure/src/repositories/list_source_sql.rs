//! SQL shared by the blocklist and whitelist source repositories; the schemas differ only in table names.

use super::{db_err, is_unique_violation, sql_now};
use ferrous_dns_domain::{DomainError, ListSyncStatus};
use sqlx::{SqliteExecutor, SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::instrument;

pub(super) struct SourceTables {
    pub sources: &'static str,
    pub groups: &'static str,
    /// Capitalized list kind used in user-facing messages.
    pub label: &'static str,
    pub not_found: fn(i64) -> DomainError,
}

pub(super) static BLOCKLIST: SourceTables = SourceTables {
    sources: "blocklist_sources",
    groups: "blocklist_source_groups",
    label: "Blocklist",
    not_found: DomainError::BlocklistSourceNotFound,
};

pub(super) static WHITELIST: SourceTables = SourceTables {
    sources: "whitelist_sources",
    groups: "whitelist_source_groups",
    label: "Whitelist",
    not_found: DomainError::WhitelistSourceNotFound,
};

/// Field set shared by `BlocklistSource` and `WhitelistSource`.
pub(super) struct SourceRecord {
    pub id: i64,
    pub name: Arc<str>,
    pub url: Option<Arc<str>>,
    pub group_ids: Vec<i64>,
    pub comment: Option<Arc<str>>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_synced_at: Option<String>,
    pub last_status: Option<ListSyncStatus>,
}

type SourceRow = (
    i64,
    String,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
);

const COLUMNS: &str =
    "id, name, url, comment, enabled, created_at, updated_at, last_synced_at, last_status";

fn record(row: SourceRow, group_ids: Vec<i64>) -> SourceRecord {
    let (id, name, url, comment, enabled, created_at, updated_at, last_synced_at, last_status) =
        row;
    SourceRecord {
        id,
        name: Arc::from(name),
        url: url.map(Arc::from),
        group_ids,
        comment: comment.map(Arc::from),
        enabled,
        created_at,
        updated_at,
        last_synced_at,
        last_status: last_status.and_then(ListSyncStatus::from_code),
    }
}

/// Canonical order matches what reads return; duplicates would violate the pivot's primary key.
fn normalize(mut group_ids: Vec<i64>) -> Vec<i64> {
    group_ids.sort_unstable();
    group_ids.dedup();
    group_ids
}

async fn fetch_group_ids<'e>(
    exec: impl SqliteExecutor<'e>,
    t: &SourceTables,
    source_id: i64,
) -> Result<Vec<i64>, DomainError> {
    sqlx::query_scalar(&format!(
        "SELECT group_id FROM {} WHERE source_id = ? ORDER BY group_id",
        t.groups
    ))
    .bind(source_id)
    .fetch_all(exec)
    .await
    .map_err(db_err("Failed to fetch source group_ids"))
}

async fn insert_group_ids(
    conn: &mut sqlx::SqliteConnection,
    t: &SourceTables,
    source_id: i64,
    group_ids: &[i64],
) -> Result<(), DomainError> {
    let sql = format!(
        "INSERT INTO {} (source_id, group_id) VALUES (?, ?)",
        t.groups
    );
    for &gid in group_ids {
        sqlx::query(&sql)
            .bind(source_id)
            .bind(gid)
            .execute(&mut *conn)
            .await
            .map_err(db_err("Failed to insert source groups"))?;
    }
    Ok(())
}

pub(super) struct SourceStore {
    pool: SqlitePool,
    t: &'static SourceTables,
}

impl SourceStore {
    pub(super) fn new(pool: SqlitePool, t: &'static SourceTables) -> Self {
        Self { pool, t }
    }

    #[instrument(skip(self), fields(table = self.t.sources))]
    pub(super) async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<SourceRecord, DomainError> {
        let now = sql_now();
        let group_ids = normalize(group_ids);

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(db_err("Failed to begin transaction"))?;

        let row = sqlx::query_as::<_, SourceRow>(&format!(
            "INSERT INTO {} (name, url, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING {COLUMNS}",
            self.t.sources
        ))
        .bind(&name)
        .bind(&url)
        .bind(&comment)
        .bind(enabled)
        .bind(&now)
        .bind(&now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::AlreadyExists(format!(
                    "{} source '{}' already exists",
                    self.t.label, name
                ))
            } else {
                db_err("Failed to create source")(e)
            }
        })?;

        insert_group_ids(&mut tx, self.t, row.0, &group_ids).await?;

        tx.commit()
            .await
            .map_err(db_err("Failed to commit source creation"))?;

        Ok(record(row, group_ids))
    }

    #[instrument(skip(self), fields(table = self.t.sources))]
    pub(super) async fn get_by_id(&self, id: i64) -> Result<Option<SourceRecord>, DomainError> {
        let row = sqlx::query_as::<_, SourceRow>(&format!(
            "SELECT {COLUMNS} FROM {} WHERE id = ?",
            self.t.sources
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query source by id"))?;

        match row {
            None => Ok(None),
            Some(row) => {
                let group_ids = fetch_group_ids(&self.pool, self.t, row.0).await?;
                Ok(Some(record(row, group_ids)))
            }
        }
    }

    #[instrument(skip(self), fields(table = self.t.sources))]
    pub(super) async fn get_all(&self) -> Result<Vec<SourceRecord>, DomainError> {
        let rows = sqlx::query_as::<_, SourceRow>(&format!(
            "SELECT {COLUMNS} FROM {} ORDER BY name ASC",
            self.t.sources
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all sources"))?;

        let pivot = sqlx::query_as::<_, (i64, i64)>(&format!(
            "SELECT source_id, group_id FROM {} ORDER BY source_id, group_id",
            self.t.groups
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to fetch source group_ids"))?;

        let mut groups_by_source: HashMap<i64, Vec<i64>> = HashMap::with_capacity(rows.len());
        for (source_id, group_id) in pivot {
            groups_by_source
                .entry(source_id)
                .or_default()
                .push(group_id);
        }

        Ok(rows
            .into_iter()
            .map(|row| {
                let group_ids = groups_by_source.remove(&row.0).unwrap_or_default();
                record(row, group_ids)
            })
            .collect())
    }

    /// Merges in the UPDATE itself so concurrent partial updates never write back stale fields.
    #[instrument(skip(self), fields(table = self.t.sources))]
    pub(super) async fn update(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_ids: Option<Vec<i64>>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<SourceRecord, DomainError> {
        let now = sql_now();
        let group_ids = group_ids.map(normalize);
        let replace_url = url.is_some();
        let url = url.flatten();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(db_err("Failed to begin transaction"))?;

        let row = sqlx::query_as::<_, SourceRow>(&format!(
            "UPDATE {}
             SET name = COALESCE(?, name),
                 url = CASE WHEN ? THEN ? ELSE url END,
                 comment = COALESCE(?, comment),
                 enabled = COALESCE(?, enabled),
                 updated_at = ?
             WHERE id = ?
             RETURNING {COLUMNS}",
            self.t.sources
        ))
        .bind(&name)
        .bind(replace_url)
        .bind(&url)
        .bind(&comment)
        .bind(enabled)
        .bind(&now)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| match &name {
            Some(name) if is_unique_violation(&e) => DomainError::AlreadyExists(format!(
                "{} source '{}' already exists",
                self.t.label, name
            )),
            _ => db_err("Failed to update source")(e),
        })?
        .ok_or_else(|| (self.t.not_found)(id))?;

        let group_ids = match group_ids {
            Some(group_ids) => {
                sqlx::query(&format!(
                    "DELETE FROM {} WHERE source_id = ?",
                    self.t.groups
                ))
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db_err("Failed to delete old source groups"))?;
                insert_group_ids(&mut tx, self.t, id, &group_ids).await?;
                group_ids
            }
            None => fetch_group_ids(&mut *tx, self.t, id).await?,
        };

        tx.commit()
            .await
            .map_err(db_err("Failed to commit source update"))?;

        Ok(record(row, group_ids))
    }

    #[instrument(skip(self), fields(table = self.t.sources))]
    pub(super) async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query(&format!("DELETE FROM {} WHERE id = ?", self.t.sources))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete source"))?;

        if result.rows_affected() == 0 {
            return Err((self.t.not_found)(id));
        }
        Ok(())
    }
}
