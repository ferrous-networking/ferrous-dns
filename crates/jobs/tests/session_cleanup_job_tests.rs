use async_trait::async_trait;
use ferrous_dns_application::ports::{MfaRepository, SessionRepository};
use ferrous_dns_domain::{
    AuthSession, DomainError, MfaChallenge, RecoveryCode, UserMfa, WebauthnCredential,
};
use ferrous_dns_jobs::SessionCleanupJob;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Counts the expiry sweeps; every other call is unused by the job.
#[derive(Default)]
struct CountingSweeps {
    session_sweeps: AtomicUsize,
    challenge_sweeps: AtomicUsize,
}

#[async_trait]
impl SessionRepository for CountingSweeps {
    async fn create(&self, _: &AuthSession) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_by_id(&self, _: &str) -> Result<Option<AuthSession>, DomainError> {
        Ok(None)
    }
    async fn update_last_seen(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        self.session_sweeps.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
    async fn delete_other_sessions(&self, _: &str, _: &str) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        Ok(vec![])
    }
}

#[async_trait]
impl MfaRepository for CountingSweeps {
    async fn get(&self, _: &str) -> Result<Option<UserMfa>, DomainError> {
        Ok(None)
    }
    async fn upsert_secret(&self, _: &str, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn enable(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn advance_totp_step(&self, _: &str, _: u64) -> Result<bool, DomainError> {
        Ok(true)
    }
    async fn delete_all(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn replace_recovery_codes(&self, _: &str, _: &[String]) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_unused_recovery_codes(&self, _: &str) -> Result<Vec<RecoveryCode>, DomainError> {
        Ok(vec![])
    }
    async fn mark_recovery_code_used(&self, _: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn create_challenge(&self, _: &MfaChallenge) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_challenge(&self, _: &str) -> Result<Option<MfaChallenge>, DomainError> {
        Ok(None)
    }
    async fn delete_challenge(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        self.challenge_sweeps.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
    async fn add_credential(&self, _: &WebauthnCredential) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_credentials(&self, _: &str) -> Result<Vec<WebauthnCredential>, DomainError> {
        Ok(vec![])
    }
    async fn find_credential_by_id(
        &self,
        _: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError> {
        Ok(None)
    }
    async fn update_credential(&self, _: &str, _: i64, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_credential(&self, _: i64, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn has_credentials(&self, _: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
}

const ONE_HOUR: Duration = Duration::from_secs(3600);

/// Expired login challenges are swept with the sessions: nothing else deletes
/// them, and the public passwordless start writes one per call.
#[tokio::test(start_paused = true)]
async fn test_session_cleanup_job_sweeps_expired_challenges_with_the_sessions() {
    let store = Arc::new(CountingSweeps::default());
    SessionCleanupJob::new(store.clone(), store.clone()).spawn();

    sleep(Duration::from_secs(1)).await;
    assert_eq!(store.session_sweeps.load(Ordering::SeqCst), 1);
    assert_eq!(store.challenge_sweeps.load(Ordering::SeqCst), 1);

    sleep(ONE_HOUR).await;
    assert_eq!(store.session_sweeps.load(Ordering::SeqCst), 2);
    assert_eq!(store.challenge_sweeps.load(Ordering::SeqCst), 2);
}
