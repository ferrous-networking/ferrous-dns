use async_trait::async_trait;
use ferrous_dns_application::ports::ScheduleProfileRepository;
use ferrous_dns_domain::{DomainError, ScheduleAction, ScheduleProfile, TimeSlot};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::warn;

pub struct SqliteScheduleProfileRepository {
    pool: SqlitePool,
}

impl SqliteScheduleProfileRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_profile(
        id: i64,
        name: String,
        timezone: String,
        comment: Option<String>,
        created_at: String,
        updated_at: String,
    ) -> ScheduleProfile {
        ScheduleProfile {
            id: Some(id),
            name: Arc::from(name.as_str()),
            timezone: Arc::from(timezone.as_str()),
            comment: comment.as_deref().map(Arc::from),
            created_at: Some(Arc::from(created_at.as_str())),
            updated_at: Some(Arc::from(updated_at.as_str())),
        }
    }

    fn row_to_slot(
        id: i64,
        profile_id: i64,
        days: i64,
        start_time: String,
        end_time: String,
        action_str: String,
        created_at: String,
    ) -> Option<TimeSlot> {
        let action = action_str.parse::<ScheduleAction>().map_err(|_| {
            warn!(action = %action_str, slot_id = id, "Unknown schedule action in database, skipping slot");
        }).ok()?;
        Some(TimeSlot {
            id: Some(id),
            profile_id,
            days: days as u8,
            start_time: Arc::from(start_time.as_str()),
            end_time: Arc::from(end_time.as_str()),
            action,
            created_at: Some(Arc::from(created_at.as_str())),
        })
    }
}

#[async_trait]
impl ScheduleProfileRepository for SqliteScheduleProfileRepository {
    async fn create(
        &self,
        name: String,
        timezone: String,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();

        let row = sqlx::query_as::<_, (i64, String, String, Option<String>, String, String)>(
            "INSERT INTO schedule_profiles (name, timezone, comment, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)
             RETURNING id, name, timezone, comment, created_at, updated_at",
        )
        .bind(&name)
        .bind(&timezone)
        .bind(&comment)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::DuplicateScheduleProfileName(name.clone())
            } else {
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        Ok(Self::row_to_profile(
            row.0, row.1, row.2, row.3, row.4, row.5,
        ))
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<ScheduleProfile>, DomainError> {
        let row = sqlx::query_as::<_, (i64, String, String, Option<String>, String, String)>(
            "SELECT id, name, timezone, comment, created_at, updated_at
             FROM schedule_profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Ok(row.map(|(id, name, tz, comment, ca, ua)| {
            Self::row_to_profile(id, name, tz, comment, ca, ua)
        }))
    }

    async fn get_all(&self) -> Result<Vec<ScheduleProfile>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, String, String, Option<String>, String, String)>(
            "SELECT id, name, timezone, comment, created_at, updated_at
             FROM schedule_profiles ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|(id, name, tz, comment, ca, ua)| {
                Self::row_to_profile(id, name, tz, comment, ca, ua)
            })
            .collect())
    }

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        timezone: Option<String>,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();

        let row = sqlx::query_as::<_, (i64, String, String, Option<String>, String, String)>(
            "UPDATE schedule_profiles
             SET name       = COALESCE(?, name),
                 timezone   = COALESCE(?, timezone),
                 comment    = CASE WHEN ? IS NOT NULL THEN ? ELSE comment END,
                 updated_at = ?
             WHERE id = ?
             RETURNING id, name, timezone, comment, created_at, updated_at",
        )
        .bind(&name)
        .bind(&timezone)
        .bind(&comment)
        .bind(&comment)
        .bind(&now)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::DuplicateScheduleProfileName(name.clone().unwrap_or_default())
            } else {
                DomainError::DatabaseError(e.to_string())
            }
        })?
        .ok_or(DomainError::ScheduleProfileNotFound(id))?;

        Ok(Self::row_to_profile(
            row.0, row.1, row.2, row.3, row.4, row.5,
        ))
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM schedule_profiles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ScheduleProfileNotFound(id));
        }
        Ok(())
    }

    async fn get_slots(&self, profile_id: i64) -> Result<Vec<TimeSlot>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, i64, i64, String, String, String, String)>(
            "SELECT id, profile_id, days, start_time, end_time, action, created_at
             FROM time_slots
             WHERE profile_id = ?
             ORDER BY days, start_time",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .filter_map(|(id, pid, days, start, end, action, ca)| {
                Self::row_to_slot(id, pid, days, start, end, action, ca)
            })
            .collect())
    }

    async fn add_slot(
        &self,
        profile_id: i64,
        days: u8,
        start_time: String,
        end_time: String,
        action: ScheduleAction,
    ) -> Result<TimeSlot, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();
        let action_str = action.to_str();

        let row = sqlx::query_as::<_, (i64, i64, i64, String, String, String, String)>(
            "INSERT INTO time_slots (profile_id, days, start_time, end_time, action, created_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING id, profile_id, days, start_time, end_time, action, created_at",
        )
        .bind(profile_id)
        .bind(days as i64)
        .bind(&start_time)
        .bind(&end_time)
        .bind(action_str)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Self::row_to_slot(row.0, row.1, row.2, row.3, row.4, row.5, row.6)
            .ok_or_else(|| DomainError::DatabaseError("Invalid time slot row".into()))
    }

    async fn delete_slot(&self, slot_id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM time_slots WHERE id = ?")
            .bind(slot_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::TimeSlotNotFound(slot_id));
        }
        Ok(())
    }

    async fn assign_to_group(&self, group_id: i64, profile_id: i64) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO group_schedule_profiles (group_id, profile_id)
             VALUES (?, ?)
             ON CONFLICT(group_id) DO UPDATE SET profile_id = excluded.profile_id",
        )
        .bind(group_id)
        .bind(profile_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn unassign_from_group(&self, group_id: i64) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM group_schedule_profiles WHERE group_id = ?")
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_group_assignment(&self, group_id: i64) -> Result<Option<i64>, DomainError> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT profile_id FROM group_schedule_profiles WHERE group_id = ?",
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Ok(row.map(|(pid,)| pid))
    }

    async fn get_all_group_assignments(&self) -> Result<Vec<(i64, i64)>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, i64)>(
            "SELECT group_id, profile_id FROM group_schedule_profiles",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Ok(rows)
    }
}
