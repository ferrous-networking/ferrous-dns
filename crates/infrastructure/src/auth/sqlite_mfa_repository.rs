use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{error, instrument};

use ferrous_dns_application::ports::MfaRepository;
use ferrous_dns_domain::{
    DomainError, MfaChallenge, MfaMethod, RecoveryCode, UserMfa, WebauthnCredential,
};

/// SQLite-backed multi-factor store (TOTP, recovery codes, login challenges,
/// WebAuthn credentials), all keyed by username.
pub struct SqliteMfaRepository {
    pool: Arc<SqlitePool>,
}

impl SqliteMfaRepository {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

fn db_err(context: &str, e: sqlx::Error) -> DomainError {
    error!("{context}: {e}");
    DomainError::DatabaseError(e.to_string())
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

#[async_trait]
impl MfaRepository for SqliteMfaRepository {
    #[instrument(skip(self))]
    async fn get(&self, username: &str) -> Result<Option<UserMfa>, DomainError> {
        let row: Option<MfaRow> = sqlx::query_as(
            "SELECT username, totp_secret, totp_enabled, created_at, confirmed_at
             FROM user_mfa WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| db_err("get user_mfa", e))?;

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
                                                 confirmed_at = NULL",
        )
        .bind(username)
        .bind(secret)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| db_err("upsert user_mfa secret", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn enable(&self, username: &str) -> Result<(), DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        sqlx::query("UPDATE user_mfa SET totp_enabled = 1, confirmed_at = ? WHERE username = ?")
            .bind(&now)
            .bind(username)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| db_err("enable user_mfa", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_all(&self, username: &str) -> Result<(), DomainError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| db_err("begin delete_all", e))?;
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
                .map_err(|e| db_err("delete_all mfa", e))?;
        }
        tx.commit()
            .await
            .map_err(|e| db_err("commit delete_all", e))?;
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
            .map_err(|e| db_err("begin replace_recovery", e))?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE username = ?")
            .bind(username)
            .execute(&mut *tx)
            .await
            .map_err(|e| db_err("clear recovery codes", e))?;
        for hash in code_hashes {
            sqlx::query("INSERT INTO mfa_recovery_codes (username, code_hash) VALUES (?, ?)")
                .bind(username)
                .bind(hash)
                .execute(&mut *tx)
                .await
                .map_err(|e| db_err("insert recovery code", e))?;
        }
        tx.commit()
            .await
            .map_err(|e| db_err("commit replace_recovery", e))?;
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
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| db_err("list recovery codes", e))?;

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

    #[instrument(skip(self))]
    async fn mark_recovery_code_used(&self, id: i64) -> Result<(), DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        sqlx::query("UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| db_err("mark recovery used", e))?;
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
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| db_err("create mfa challenge", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_challenge(&self, token: &str) -> Result<Option<MfaChallenge>, DomainError> {
        let row: Option<ChallengeRow> = sqlx::query_as(
            "SELECT token, username, remember_me, kind, state, expires_at
             FROM mfa_challenges WHERE token = ?",
        )
        .bind(token)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| db_err("get mfa challenge", e))?;

        Ok(row.map(
            |(token, username, remember_me, kind, state, expires_at)| MfaChallenge {
                token: Arc::from(token.as_str()),
                username: Arc::from(username.as_str()),
                remember_me,
                kind: MfaMethod::parse(&kind).unwrap_or(MfaMethod::Totp),
                state,
                expires_at,
            },
        ))
    }

    #[instrument(skip(self))]
    async fn delete_challenge(&self, token: &str) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM mfa_challenges WHERE token = ?")
            .bind(token)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| db_err("delete mfa challenge", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let result = sqlx::query("DELETE FROM mfa_challenges WHERE expires_at < ?")
            .bind(&now)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| db_err("delete expired challenges", e))?;
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
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| db_err("add webauthn credential", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_credentials(
        &self,
        username: &str,
    ) -> Result<Vec<WebauthnCredential>, DomainError> {
        let rows: Vec<CredentialRow> = sqlx::query_as(
            "SELECT id, username, credential_id, label, passkey, sign_count, created_at, last_used_at
             FROM webauthn_credentials WHERE username = ? ORDER BY id",
        )
        .bind(username)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| db_err("list webauthn credentials", e))?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    username,
                    credential_id,
                    label,
                    passkey,
                    sign_count,
                    created_at,
                    last_used_at,
                )| {
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
                },
            )
            .collect())
    }

    #[instrument(skip(self))]
    async fn find_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError> {
        let row: Option<CredentialRow> = sqlx::query_as(
            "SELECT id, username, credential_id, label, passkey, sign_count, created_at, last_used_at
             FROM webauthn_credentials WHERE credential_id = ?",
        )
        .bind(credential_id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| db_err("find webauthn credential by id", e))?;

        Ok(row.map(
            |(
                id,
                username,
                credential_id,
                label,
                passkey,
                sign_count,
                created_at,
                last_used_at,
            )| {
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
            },
        ))
    }

    #[instrument(skip(self))]
    async fn update_credential_counter(
        &self,
        credential_id: &str,
        sign_count: i64,
    ) -> Result<(), DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        sqlx::query(
            "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ?
             WHERE credential_id = ?",
        )
        .bind(sign_count)
        .bind(&now)
        .bind(credential_id)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| db_err("update credential counter", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_credential(&self, id: i64, username: &str) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM webauthn_credentials WHERE id = ? AND username = ?")
            .bind(id)
            .bind(username)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| db_err("delete credential", e))?;
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
                .fetch_optional(self.pool.as_ref())
                .await
                .map_err(|e| db_err("has_credentials", e))?;
        Ok(row.is_some())
    }
}
