use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{instrument, warn};

use ferrous_dns_application::ports::{MfaRepository, PendingChallengeCounter};
use ferrous_dns_domain::{
    DomainError, MfaChallenge, MfaMethod, RecoveryCode, UserMfa, WebauthnCredential,
};

use crate::repositories::{db_err, sql_now};

/// SQLite-backed multi-factor store (TOTP, recovery codes, login challenges,
/// WebAuthn credentials), all keyed by username.
pub struct SqliteMfaRepository {
    pool: SqlitePool,
}

impl SqliteMfaRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

type MfaRow = (String, String, bool, String, Option<String>);
type RecoveryRow = (i64, String, String, Option<String>);
type ChallengeRow = (String, String, bool, String, Option<String>, String);
type CredentialRow = (
    i64,
    String,
    String,
    Option<String>,
    String,
    i64,
    String,
    Option<String>,
);

macro_rules! credential_select {
    ($tail:literal) => {
        concat!(
            "SELECT id, username, credential_id, label, passkey, sign_count, created_at, last_used_at
             FROM webauthn_credentials",
            $tail
        )
    };
}

fn row_to_credential(
    (id, username, credential_id, label, passkey, sign_count, created_at, last_used_at): CredentialRow,
) -> WebauthnCredential {
    WebauthnCredential {
        id: Some(id),
        username: Arc::from(username.as_str()),
        credential_id: Arc::from(credential_id.as_str()),
        label: label.map(|l| Arc::from(l.as_str())),
        passkey,
        sign_count,
        created_at: Some(created_at),
        last_used_at,
    }
}

/// A challenge whose kind is unreadable is unusable; dropping it fails the login closed.
fn row_to_challenge(
    (token, username, remember_me, kind, state, expires_at): ChallengeRow,
) -> Option<MfaChallenge> {
    let kind = match kind.parse::<MfaMethod>() {
        Ok(kind) => kind,
        Err(e) => {
            warn!(error = %e, "Invalid MFA challenge kind in DB, ignoring challenge");
            return None;
        }
    };
    Some(MfaChallenge {
        token: Arc::from(token.as_str()),
        username: Arc::from(username.as_str()),
        remember_me,
        kind,
        state,
        expires_at,
    })
}

#[async_trait]
impl MfaRepository for SqliteMfaRepository {
    #[instrument(skip(self))]
    async fn get(&self, username: &str) -> Result<Option<UserMfa>, DomainError> {
        let row: Option<MfaRow> = sqlx::query_as(
            "SELECT username, totp_secret, totp_enabled, created_at, confirmed_at
             FROM user_mfa WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("get user_mfa"))?;

        Ok(row.map(
            |(username, totp_secret, totp_enabled, created_at, confirmed_at)| UserMfa {
                username: Arc::from(username.as_str()),
                totp_secret: Arc::from(totp_secret.as_str()),
                totp_enabled,
                created_at: Some(created_at),
                confirmed_at,
            },
        ))
    }

    #[instrument(skip(self, secret))]
    async fn upsert_secret(&self, username: &str, secret: &str) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO user_mfa (username, totp_secret, totp_enabled)
             VALUES (?, ?, 0)
             ON CONFLICT(username) DO UPDATE SET totp_secret = excluded.totp_secret,
                                                 totp_enabled = 0,
                                                 confirmed_at = NULL,
                                                 totp_last_step = NULL",
        )
        .bind(username)
        .bind(secret)
        .execute(&self.pool)
        .await
        .map_err(db_err("upsert user_mfa secret"))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn enable(&self, username: &str) -> Result<(), DomainError> {
        sqlx::query("UPDATE user_mfa SET totp_enabled = 1, confirmed_at = ? WHERE username = ?")
            .bind(sql_now())
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(db_err("enable user_mfa"))?;
        Ok(())
    }

    /// Compare-and-set in SQL so two concurrent submissions of one code cannot both pass.
    #[instrument(skip(self))]
    async fn advance_totp_step(&self, username: &str, step: u64) -> Result<bool, DomainError> {
        let step = i64::try_from(step).map_err(|_| DomainError::InvalidMfaCode)?;
        let result = sqlx::query(
            "UPDATE user_mfa SET totp_last_step = ?
             WHERE username = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
        )
        .bind(step)
        .bind(username)
        .bind(step)
        .execute(&self.pool)
        .await
        .map_err(db_err("advance totp step"))?;
        Ok(result.rows_affected() == 1)
    }

    #[instrument(skip(self))]
    async fn delete_all(&self, username: &str) -> Result<(), DomainError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(db_err("begin delete_all"))?;
        for stmt in [
            "DELETE FROM user_mfa WHERE username = ?",
            "DELETE FROM mfa_recovery_codes WHERE username = ?",
            "DELETE FROM webauthn_credentials WHERE username = ?",
            "DELETE FROM mfa_challenges WHERE username = ?",
        ] {
            sqlx::query(stmt)
                .bind(username)
                .execute(&mut *tx)
                .await
                .map_err(db_err("delete_all mfa"))?;
        }
        tx.commit().await.map_err(db_err("commit delete_all"))?;
        Ok(())
    }

    #[instrument(skip(self, code_hashes))]
    async fn replace_recovery_codes(
        &self,
        username: &str,
        code_hashes: &[String],
    ) -> Result<(), DomainError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(db_err("begin replace_recovery"))?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE username = ?")
            .bind(username)
            .execute(&mut *tx)
            .await
            .map_err(db_err("clear recovery codes"))?;
        for hash in code_hashes {
            sqlx::query("INSERT INTO mfa_recovery_codes (username, code_hash) VALUES (?, ?)")
                .bind(username)
                .bind(hash)
                .execute(&mut *tx)
                .await
                .map_err(db_err("insert recovery code"))?;
        }
        tx.commit()
            .await
            .map_err(db_err("commit replace_recovery"))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_unused_recovery_codes(
        &self,
        username: &str,
    ) -> Result<Vec<RecoveryCode>, DomainError> {
        let rows: Vec<RecoveryRow> = sqlx::query_as(
            "SELECT id, username, code_hash, used_at
             FROM mfa_recovery_codes WHERE username = ? AND used_at IS NULL",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("list recovery codes"))?;

        Ok(rows
            .into_iter()
            .map(|(id, username, code_hash, used_at)| RecoveryCode {
                id,
                username: Arc::from(username.as_str()),
                code_hash: Arc::from(code_hash.as_str()),
                used_at,
            })
            .collect())
    }

    /// Conditional on `used_at IS NULL` so two concurrent logins cannot spend the same code.
    #[instrument(skip(self))]
    async fn mark_recovery_code_used(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query(
            "UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
        )
        .bind(sql_now())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db_err("mark recovery used"))?;
        if result.rows_affected() == 0 {
            return Err(DomainError::InvalidMfaCode);
        }
        Ok(())
    }

    #[instrument(skip(self, challenge))]
    async fn create_challenge(&self, challenge: &MfaChallenge) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO mfa_challenges (token, username, remember_me, kind, state, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(challenge.token.as_ref())
        .bind(challenge.username.as_ref())
        .bind(challenge.remember_me)
        .bind(challenge.kind.as_str())
        .bind(challenge.state.as_deref())
        .bind(&challenge.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_err("create mfa challenge"))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_challenge(&self, token: &str) -> Result<Option<MfaChallenge>, DomainError> {
        let row: Option<ChallengeRow> = sqlx::query_as(
            "SELECT token, username, remember_me, kind, state, expires_at
             FROM mfa_challenges WHERE token = ?",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("get mfa challenge"))?;

        Ok(row.and_then(row_to_challenge))
    }

    /// Errors when nothing was deleted, so a challenge raced by a concurrent request mints at most one session.
    #[instrument(skip(self))]
    async fn delete_challenge(&self, token: &str) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM mfa_challenges WHERE token = ?")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(db_err("delete mfa challenge"))?;
        if result.rows_affected() == 0 {
            return Err(DomainError::MfaChallengeExpired);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM mfa_challenges WHERE expires_at < ?")
            .bind(sql_now())
            .execute(&self.pool)
            .await
            .map_err(db_err("delete expired challenges"))?;
        Ok(result.rows_affected())
    }

    #[instrument(skip(self, cred))]
    async fn add_credential(&self, cred: &WebauthnCredential) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO webauthn_credentials
             (username, credential_id, label, passkey, sign_count)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(cred.username.as_ref())
        .bind(cred.credential_id.as_ref())
        .bind(cred.label.as_deref())
        .bind(&cred.passkey)
        .bind(cred.sign_count)
        .execute(&self.pool)
        .await
        .map_err(db_err("add webauthn credential"))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_credentials(
        &self,
        username: &str,
    ) -> Result<Vec<WebauthnCredential>, DomainError> {
        let rows: Vec<CredentialRow> =
            sqlx::query_as(credential_select!(" WHERE username = ? ORDER BY id"))
                .bind(username)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err("list webauthn credentials"))?;

        Ok(rows.into_iter().map(row_to_credential).collect())
    }

    #[instrument(skip(self))]
    async fn find_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError> {
        let row: Option<CredentialRow> =
            sqlx::query_as(credential_select!(" WHERE credential_id = ?"))
                .bind(credential_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err("find webauthn credential by id"))?;

        Ok(row.map(row_to_credential))
    }

    /// The counter guard stays in SQL so two concurrent assertions cannot both advance from one baseline.
    #[instrument(skip(self, passkey_json))]
    async fn update_credential(
        &self,
        credential_id: &str,
        sign_count: i64,
        passkey_json: &str,
    ) -> Result<(), DomainError> {
        let result = sqlx::query(
            "UPDATE webauthn_credentials SET sign_count = ?, passkey = ?, last_used_at = ?
             WHERE credential_id = ? AND (? > sign_count OR (? = 0 AND sign_count = 0))",
        )
        .bind(sign_count)
        .bind(passkey_json)
        .bind(sql_now())
        .bind(credential_id)
        .bind(sign_count)
        .bind(sign_count)
        .execute(&self.pool)
        .await
        .map_err(db_err("update credential"))?;
        if result.rows_affected() == 0 {
            warn!(
                credential_id,
                sign_count, "WebAuthn counter did not increase or credential missing"
            );
            return Err(DomainError::WebauthnError(
                "signature counter did not increase; possible cloned authenticator".into(),
            ));
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_credential(&self, id: i64, username: &str) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM webauthn_credentials WHERE id = ? AND username = ?")
            .bind(id)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(db_err("delete credential"))?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound(format!("passkey {id}")));
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn has_credentials(&self, username: &str) -> Result<bool, DomainError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM webauthn_credentials WHERE username = ? LIMIT 1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err("has_credentials"))?;
        Ok(row.is_some())
    }
}

#[async_trait]
impl PendingChallengeCounter for SqliteMfaRepository {
    /// A passwordless ceremony is stored with no username until `finish`.
    #[instrument(skip(self))]
    async fn count_pending_anonymous(&self) -> Result<u64, DomainError> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mfa_challenges WHERE username = '' AND expires_at >= ?",
        )
        .bind(sql_now())
        .fetch_one(&self.pool)
        .await
        .map_err(db_err("count pending challenges"))?;
        Ok(count as u64)
    }
}
