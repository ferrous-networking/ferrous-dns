use ferrous_dns_application::ports::{PasswordHasher, SessionRepository, UserProvider};
use ferrous_dns_application::use_cases::{
    GetAuthStatusUseCase, LoginUseCase, ValidateSessionUseCase,
};
use ferrous_dns_domain::config::auth::AdminConfig;
use ferrous_dns_domain::{
    AuthConfig, AuthSession, Config, DomainError, User, UserRole, UserSource,
};
use std::sync::Arc;
use tokio::sync::RwLock;

// --- In-memory test implementations ---

struct TestUserProvider {
    admin: User,
}

#[async_trait::async_trait]
impl UserProvider for TestUserProvider {
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        if username == self.admin.username.as_ref() {
            Ok(Some(self.admin.clone()))
        } else {
            Ok(None)
        }
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        Ok(vec![self.admin.clone()])
    }
    async fn update_password(
        &self,
        _username: &str,
        _password_hash: &str,
    ) -> Result<(), DomainError> {
        Ok(())
    }
}

struct TestPasswordHasher;

impl PasswordHasher for TestPasswordHasher {
    fn hash(&self, _password: &str) -> Result<String, DomainError> {
        Ok("$hashed$".to_string())
    }
    fn verify(&self, password: &str, _hash: &str) -> Result<bool, DomainError> {
        Ok(password == "correct-password")
    }
}

struct InMemorySessionRepository {
    sessions: tokio::sync::Mutex<Vec<AuthSession>>,
}

impl InMemorySessionRepository {
    fn new() -> Self {
        Self {
            sessions: tokio::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl SessionRepository for InMemorySessionRepository {
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError> {
        self.sessions.lock().await.push(session.clone());
        Ok(())
    }
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError> {
        let sessions = self.sessions.lock().await;
        Ok(sessions.iter().find(|s| s.id.as_ref() == id).cloned())
    }
    async fn update_last_seen(&self, _id: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete(&self, id: &str) -> Result<(), DomainError> {
        self.sessions.lock().await.retain(|s| s.id.as_ref() != id);
        Ok(())
    }
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        Ok(self.sessions.lock().await.clone())
    }
}

fn make_admin_user(password_hash: &str) -> User {
    User {
        id: Some(1),
        username: Arc::from("admin"),
        display_name: None,
        password_hash: Arc::from(password_hash),
        role: UserRole::Admin,
        source: UserSource::Toml,
        enabled: true,
        created_at: None,
        updated_at: None,
    }
}

/// GetAuthStatusUseCase returns correct enabled/configured state.
#[tokio::test]
async fn auth_status_reflects_config() {
    let config_enabled = Arc::new(RwLock::new(Config {
        auth: AuthConfig {
            enabled: true,
            admin: AdminConfig {
                username: "admin".to_string(),
                password_hash: Some("$argon2id$test".to_string()),
            },
            ..AuthConfig::default()
        },
        ..Config::default()
    }));
    let uc = GetAuthStatusUseCase::new(config_enabled);
    let status = uc.execute().await;
    assert!(status.auth_enabled);
    assert!(status.password_configured);

    let config_disabled = Arc::new(RwLock::new(Config {
        auth: AuthConfig {
            enabled: false,
            ..AuthConfig::default()
        },
        ..Config::default()
    }));
    let uc2 = GetAuthStatusUseCase::new(config_disabled);
    let status2 = uc2.execute().await;
    assert!(!status2.auth_enabled);
}

/// Empty password hash is treated as not configured.
#[tokio::test]
async fn auth_status_empty_hash_means_not_configured() {
    let config = Arc::new(RwLock::new(Config {
        auth: AuthConfig {
            enabled: true,
            admin: AdminConfig {
                username: "admin".to_string(),
                password_hash: Some(String::new()),
            },
            ..AuthConfig::default()
        },
        ..Config::default()
    }));
    let uc = GetAuthStatusUseCase::new(config);
    let status = uc.execute().await;
    assert!(status.auth_enabled);
    assert!(!status.password_configured, "empty hash = not configured");
}

/// None password hash is treated as not configured.
#[tokio::test]
async fn auth_status_none_hash_means_not_configured() {
    let config = Arc::new(RwLock::new(Config {
        auth: AuthConfig {
            enabled: true,
            admin: AdminConfig {
                username: "admin".to_string(),
                password_hash: None,
            },
            ..AuthConfig::default()
        },
        ..Config::default()
    }));
    let uc = GetAuthStatusUseCase::new(config);
    let status = uc.execute().await;
    assert!(!status.password_configured, "None hash = not configured");
}

/// Config changes via RwLock are visible immediately.
#[tokio::test]
async fn auth_status_reflects_live_config_changes() {
    let config = Arc::new(RwLock::new(Config {
        auth: AuthConfig {
            enabled: true,
            admin: AdminConfig {
                username: "admin".to_string(),
                password_hash: None,
            },
            ..AuthConfig::default()
        },
        ..Config::default()
    }));
    let uc = GetAuthStatusUseCase::new(config.clone());

    let before = uc.execute().await;
    assert!(!before.password_configured);

    {
        let mut cfg = config.write().await;
        cfg.auth.admin.password_hash = Some("$argon2id$newhash".to_string());
    }

    let after = uc.execute().await;
    assert!(
        after.password_configured,
        "should see updated hash immediately"
    );
}

/// Login with correct credentials creates a session.
#[tokio::test]
async fn login_with_correct_password_creates_session() {
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: make_admin_user("$hashed$"),
    });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(TestPasswordHasher);
    let config = Arc::new(AuthConfig {
        enabled: true,
        session_ttl_hours: 24,
        ..AuthConfig::default()
    });

    let login_uc = LoginUseCase::new(
        user_provider.clone(),
        session_repo.clone(),
        hasher.clone(),
        config,
    );

    let result = login_uc
        .execute(
            "admin",
            "correct-password",
            false,
            "127.0.0.1",
            "test-agent",
        )
        .await;

    assert!(result.is_ok());
    let session = result.unwrap();
    assert_eq!(session.username.as_ref(), "admin");
    assert!(!session.remember_me);

    // Session should be stored
    let stored = session_repo.get_all_active().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, session.id);
}

/// Login with wrong password returns InvalidCredentials.
#[tokio::test]
async fn login_with_wrong_password_fails() {
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: make_admin_user("$hashed$"),
    });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(TestPasswordHasher);
    let config = Arc::new(AuthConfig::default());

    let login_uc = LoginUseCase::new(user_provider, session_repo, hasher, config);

    let result = login_uc
        .execute("admin", "wrong-password", false, "127.0.0.1", "test-agent")
        .await;

    assert!(result.is_err());
}

/// Login with nonexistent user returns error.
#[tokio::test]
async fn login_with_unknown_user_fails() {
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: make_admin_user("$hashed$"),
    });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(TestPasswordHasher);
    let config = Arc::new(AuthConfig::default());

    let login_uc = LoginUseCase::new(user_provider, session_repo, hasher, config);

    let result = login_uc
        .execute(
            "nobody",
            "correct-password",
            false,
            "127.0.0.1",
            "test-agent",
        )
        .await;

    assert!(result.is_err());
}

/// ValidateSessionUseCase validates stored sessions.
#[tokio::test]
async fn validate_session_succeeds_for_valid_session() {
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: make_admin_user("$hashed$"),
    });
    let session_repo = Arc::new(InMemorySessionRepository::new());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(TestPasswordHasher);
    let config = Arc::new(AuthConfig {
        enabled: true,
        session_ttl_hours: 24,
        ..AuthConfig::default()
    });

    let login_uc = LoginUseCase::new(
        user_provider,
        session_repo.clone() as Arc<dyn SessionRepository>,
        hasher,
        config,
    );

    let session = login_uc
        .execute(
            "admin",
            "correct-password",
            false,
            "127.0.0.1",
            "test-agent",
        )
        .await
        .unwrap();

    let validate_uc = ValidateSessionUseCase::new(session_repo as Arc<dyn SessionRepository>);
    let result = validate_uc.execute(&session.id).await;

    assert!(result.is_ok());
    let validated = result.unwrap();
    assert_eq!(validated.username.as_ref(), "admin");
}

/// ValidateSessionUseCase rejects unknown session IDs.
#[tokio::test]
async fn validate_session_fails_for_unknown_id() {
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let validate_uc = ValidateSessionUseCase::new(session_repo);

    let result = validate_uc.execute("nonexistent-session-id").await;
    assert!(result.is_err());
}

/// Constant-time comparison works correctly (uses subtle crate directly).
#[test]
fn timing_safe_eq_basic_correctness() {
    use subtle::ConstantTimeEq;
    let eq = |a: &[u8], b: &[u8]| -> bool { a.ct_eq(b).into() };
    assert!(eq(b"token123", b"token123"));
    assert!(!eq(b"token123", b"token456"));
    assert!(!eq(b"short", b"longer-value"));
    assert!(eq(b"", b""));
}
