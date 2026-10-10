use async_trait::async_trait;
use ferrous_dns_application::ports::SessionRepository;
use ferrous_dns_application::use_cases::ValidateSessionUseCase;
use ferrous_dns_domain::{AuthSession, DomainError, UserRole};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

const TIMESTAMP_FMT: &str = "%Y-%m-%d %H:%M:%S";

fn timestamp(offset: chrono::TimeDelta) -> String {
    (chrono::Utc::now() + offset)
        .format(TIMESTAMP_FMT)
        .to_string()
}

/// Stores one session and counts the `last_seen_at` writes, applying each like SQLite does.
struct CountingSessionRepo {
    session: RwLock<AuthSession>,
    last_seen_writes: AtomicUsize,
}

impl CountingSessionRepo {
    fn with_last_seen(last_seen_at: String) -> Arc<Self> {
        Arc::new(Self {
            session: RwLock::new(AuthSession {
                id: Arc::from("session-1"),
                username: Arc::from("admin"),
                role: UserRole::Admin,
                ip_address: Arc::from("127.0.0.1"),
                user_agent: Arc::from("test"),
                remember_me: false,
                created_at: timestamp(chrono::TimeDelta::hours(-1)),
                last_seen_at,
                expires_at: timestamp(chrono::TimeDelta::hours(1)),
            }),
            last_seen_writes: AtomicUsize::new(0),
        })
    }

    fn writes(&self) -> usize {
        self.last_seen_writes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SessionRepository for CountingSessionRepo {
    async fn create(&self, _: &AuthSession) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError> {
        let session = self.session.read().await;
        Ok((session.id.as_ref() == id).then(|| session.clone()))
    }
    async fn update_last_seen(&self, _: &str) -> Result<(), DomainError> {
        self.last_seen_writes.fetch_add(1, Ordering::SeqCst);
        self.session.write().await.last_seen_at = timestamp(chrono::TimeDelta::zero());
        Ok(())
    }
    async fn delete(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn delete_other_sessions(&self, _: &str, _: &str) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        Ok(vec![self.session.read().await.clone()])
    }
}

#[tokio::test]
async fn test_validate_session_refreshes_last_seen_once_per_minute_not_per_request() {
    let repo = CountingSessionRepo::with_last_seen(timestamp(chrono::TimeDelta::minutes(-5)));
    let validate = ValidateSessionUseCase::new(repo.clone());

    validate.execute("session-1").await.unwrap();
    validate.execute("session-1").await.unwrap();
    validate.execute("session-1").await.unwrap();

    assert_eq!(
        repo.writes(),
        1,
        "every dashboard request wrote last_seen_at, competing for the write lock"
    );
}

#[tokio::test]
async fn test_validate_session_refreshes_an_unparseable_last_seen() {
    let repo = CountingSessionRepo::with_last_seen("not a timestamp".to_string());
    let validate = ValidateSessionUseCase::new(repo.clone());

    validate.execute("session-1").await.unwrap();

    assert_eq!(repo.writes(), 1);
}
