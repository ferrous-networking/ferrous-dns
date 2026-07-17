use ferrous_dns_application::ports::{
    AuthenticatedCredential, MfaRepository, PasswordHasher, RegisteredCredential,
    SessionRepository, UserProvider, WebauthnService,
};
use ferrous_dns_application::use_cases::{
    DiscoverablePasskeyLoginUseCase, GetAuthStatusUseCase, LoginOutcome, LoginUseCase,
    RegisterPasskeyUseCase, ValidateSessionUseCase,
};
use ferrous_dns_domain::config::auth::AdminConfig;
use ferrous_dns_domain::{
    AuthConfig, AuthSession, Config, DomainError, MfaChallenge, MfaMethod, RecoveryCode, User,
    UserMfa, UserRole, UserSource, WebauthnCredential,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// MFA repository double: no factors enrolled (login stays single-factor).
struct NoMfaRepository;

#[async_trait::async_trait]
impl MfaRepository for NoMfaRepository {
    async fn get(&self, _u: &str) -> Result<Option<UserMfa>, DomainError> {
        Ok(None)
    }
    async fn upsert_secret(&self, _u: &str, _s: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn enable(&self, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_all(&self, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn replace_recovery_codes(&self, _u: &str, _h: &[String]) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_unused_recovery_codes(&self, _u: &str) -> Result<Vec<RecoveryCode>, DomainError> {
        Ok(vec![])
    }
    async fn mark_recovery_code_used(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn create_challenge(&self, _c: &MfaChallenge) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_challenge(&self, _t: &str) -> Result<Option<MfaChallenge>, DomainError> {
        Ok(None)
    }
    async fn delete_challenge(&self, _t: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn add_credential(&self, _c: &WebauthnCredential) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_credentials(&self, _u: &str) -> Result<Vec<WebauthnCredential>, DomainError> {
        Ok(vec![])
    }
    async fn find_credential_by_id(
        &self,
        _c: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError> {
        Ok(None)
    }
    async fn update_credential_counter(&self, _c: &str, _n: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_credential(&self, _id: i64, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn has_credentials(&self, _u: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
}

fn no_mfa() -> Arc<dyn MfaRepository> {
    Arc::new(NoMfaRepository)
}

/// Unwraps a login outcome that must be a completed session.
fn expect_session(outcome: LoginOutcome) -> AuthSession {
    match outcome {
        LoginOutcome::Authenticated(s) => s,
        LoginOutcome::MfaRequired { .. } => panic!("expected authenticated, got MfaRequired"),
    }
}

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
        no_mfa(),
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
    let session = expect_session(result.unwrap());
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

    let login_uc = LoginUseCase::new(user_provider, session_repo, hasher, no_mfa(), config);

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

    let login_uc = LoginUseCase::new(user_provider, session_repo, hasher, no_mfa(), config);

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
        no_mfa(),
        config,
    );

    let session = expect_session(
        login_uc
            .execute(
                "admin",
                "correct-password",
                false,
                "127.0.0.1",
                "test-agent",
            )
            .await
            .unwrap(),
    );

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

/// Stateful MFA repository double: TOTP enrolled, challenge held in memory.
struct TotpEnrolledMfaRepository {
    challenge: std::sync::Mutex<Option<MfaChallenge>>,
}

impl TotpEnrolledMfaRepository {
    fn new() -> Self {
        Self {
            challenge: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl MfaRepository for TotpEnrolledMfaRepository {
    async fn get(&self, u: &str) -> Result<Option<UserMfa>, DomainError> {
        Ok(Some(UserMfa {
            username: Arc::from(u),
            totp_secret: Arc::from("SECRET"),
            totp_enabled: true,
            created_at: None,
            confirmed_at: None,
        }))
    }
    async fn upsert_secret(&self, _u: &str, _s: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn enable(&self, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_all(&self, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn replace_recovery_codes(&self, _u: &str, _h: &[String]) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_unused_recovery_codes(&self, _u: &str) -> Result<Vec<RecoveryCode>, DomainError> {
        Ok(vec![])
    }
    async fn mark_recovery_code_used(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn create_challenge(&self, c: &MfaChallenge) -> Result<(), DomainError> {
        *self.challenge.lock().unwrap() = Some(c.clone());
        Ok(())
    }
    async fn get_challenge(&self, t: &str) -> Result<Option<MfaChallenge>, DomainError> {
        Ok(self
            .challenge
            .lock()
            .unwrap()
            .clone()
            .filter(|c| c.token.as_ref() == t))
    }
    async fn delete_challenge(&self, _t: &str) -> Result<(), DomainError> {
        *self.challenge.lock().unwrap() = None;
        Ok(())
    }
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn add_credential(&self, _c: &WebauthnCredential) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_credentials(&self, _u: &str) -> Result<Vec<WebauthnCredential>, DomainError> {
        Ok(vec![])
    }
    async fn find_credential_by_id(
        &self,
        _c: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError> {
        Ok(None)
    }
    async fn update_credential_counter(&self, _c: &str, _n: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_credential(&self, _id: i64, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn has_credentials(&self, _u: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
}

/// TOTP double that accepts exactly one fixed code.
struct FixedTotpService;

impl ferrous_dns_application::ports::TotpService for FixedTotpService {
    fn generate_secret(&self) -> String {
        "SECRET".to_string()
    }
    fn provisioning_uri(&self, _s: &str, _a: &str) -> Result<String, DomainError> {
        Ok("otpauth://totp/x".to_string())
    }
    fn qr_svg(&self, _u: &str) -> Result<String, DomainError> {
        Ok("<svg/>".to_string())
    }
    fn verify(&self, _secret: &str, code: &str) -> Result<bool, DomainError> {
        Ok(code == "123456")
    }
}

/// Full two-phase flow: password login yields an MFA challenge; a correct TOTP
/// code then mints the session.
#[tokio::test]
async fn totp_enrolled_login_requires_and_accepts_second_factor() {
    use ferrous_dns_application::use_cases::VerifyMfaUseCase;

    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: make_admin_user("$hashed$"),
    });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(TestPasswordHasher);
    let mfa_repo: Arc<dyn MfaRepository> = Arc::new(TotpEnrolledMfaRepository::new());
    let totp: Arc<dyn ferrous_dns_application::ports::TotpService> = Arc::new(FixedTotpService);
    let config = Arc::new(AuthConfig {
        enabled: true,
        session_ttl_hours: 24,
        ..AuthConfig::default()
    });

    let login_uc = LoginUseCase::new(
        user_provider.clone(),
        session_repo.clone(),
        hasher.clone(),
        mfa_repo.clone(),
        config.clone(),
    );

    // Phase 1: correct password → MFA challenge, no session yet.
    let outcome = login_uc
        .execute("admin", "correct-password", true, "127.0.0.1", "agent")
        .await
        .unwrap();
    let challenge_token = match outcome {
        LoginOutcome::MfaRequired {
            challenge_token,
            methods,
        } => {
            assert!(methods.contains(&"totp"));
            challenge_token
        }
        LoginOutcome::Authenticated(_) => panic!("expected MfaRequired"),
    };
    assert!(session_repo.get_all_active().await.unwrap().is_empty());

    let verify_uc = VerifyMfaUseCase::new(
        mfa_repo.clone(),
        totp,
        hasher,
        user_provider,
        session_repo.clone(),
        config,
    );

    // Wrong code is rejected; challenge survives for retry.
    assert!(verify_uc
        .execute(&challenge_token, "000000", "127.0.0.1", "agent")
        .await
        .is_err());

    // Phase 2: correct code → session honoring remember_me.
    let session = verify_uc
        .execute(&challenge_token, "123456", "127.0.0.1", "agent")
        .await
        .unwrap();
    assert_eq!(session.username.as_ref(), "admin");
    assert!(session.remember_me);
    assert_eq!(session_repo.get_all_active().await.unwrap().len(), 1);
}

/// WebAuthn service double that reports "not configured" (rp_id/rp_origin unset).
struct UnconfiguredWebauthnService;

impl WebauthnService for UnconfiguredWebauthnService {
    fn is_configured(&self) -> bool {
        false
    }
    fn start_registration(
        &self,
        _u: &str,
        _d: &str,
        _e: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_registration(
        &self,
        _r: serde_json::Value,
        _s: &str,
    ) -> Result<RegisteredCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn start_authentication(
        &self,
        _p: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_authentication(
        &self,
        _r: serde_json::Value,
        _s: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn start_discoverable(&self) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn identify_discoverable(&self, _r: serde_json::Value) -> Result<String, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_discoverable(
        &self,
        _r: serde_json::Value,
        _s: &str,
        _p: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
}

/// Passkey registration is refused (before touching the repo) when WebAuthn has
/// no relying-party configured — the universal-TOTP-only deployment case.
#[tokio::test]
async fn passkey_registration_rejected_when_webauthn_not_configured() {
    let webauthn: Arc<dyn WebauthnService> = Arc::new(UnconfiguredWebauthnService);
    let uc = RegisterPasskeyUseCase::new(webauthn, no_mfa(), 300);

    match uc.start("admin", "Admin").await {
        Err(DomainError::WebauthnNotConfigured) => {}
        Err(other) => panic!("expected WebauthnNotConfigured, got {other:?}"),
        Ok(_) => panic!("registration must be refused when WebAuthn is unconfigured"),
    }
}

/// WebAuthn double for a *successful* usernameless ceremony: identify resolves a
/// known resident credential id, finish returns an authenticated credential with
/// a bumped signature counter.
struct DiscoverableOkWebauthnService;

impl WebauthnService for DiscoverableOkWebauthnService {
    fn is_configured(&self) -> bool {
        true
    }
    fn start_registration(
        &self,
        _u: &str,
        _d: &str,
        _e: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_registration(
        &self,
        _r: serde_json::Value,
        _s: &str,
    ) -> Result<RegisteredCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn start_authentication(
        &self,
        _p: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_authentication(
        &self,
        _r: serde_json::Value,
        _s: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn start_discoverable(&self) -> Result<(serde_json::Value, String), DomainError> {
        Ok((serde_json::json!({"publicKey": {}}), "state".to_string()))
    }
    fn identify_discoverable(&self, _r: serde_json::Value) -> Result<String, DomainError> {
        Ok("cred-1".to_string())
    }
    fn finish_discoverable(
        &self,
        _r: serde_json::Value,
        _s: &str,
        _p: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        Ok(AuthenticatedCredential {
            credential_id: "cred-1".to_string(),
            sign_count: 99,
        })
    }
}

/// MFA repository double serving one stored resident credential owned by `owner`
/// plus a live (far-future) discoverable challenge; records the persisted counter.
struct DiscoverableMfaRepo {
    owner: &'static str,
    persisted_count: Arc<std::sync::atomic::AtomicI64>,
}

#[async_trait::async_trait]
impl MfaRepository for DiscoverableMfaRepo {
    async fn get(&self, _u: &str) -> Result<Option<UserMfa>, DomainError> {
        Ok(None)
    }
    async fn upsert_secret(&self, _u: &str, _s: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn enable(&self, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_all(&self, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn replace_recovery_codes(&self, _u: &str, _h: &[String]) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_unused_recovery_codes(&self, _u: &str) -> Result<Vec<RecoveryCode>, DomainError> {
        Ok(vec![])
    }
    async fn mark_recovery_code_used(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn create_challenge(&self, _c: &MfaChallenge) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_challenge(&self, t: &str) -> Result<Option<MfaChallenge>, DomainError> {
        Ok(Some(MfaChallenge {
            token: Arc::from(t),
            username: Arc::from(""),
            remember_me: false,
            kind: MfaMethod::Webauthn,
            state: Some("state".to_string()),
            expires_at: "2999-01-01 00:00:00".to_string(),
        }))
    }
    async fn delete_challenge(&self, _t: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn add_credential(&self, _c: &WebauthnCredential) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_credentials(&self, _u: &str) -> Result<Vec<WebauthnCredential>, DomainError> {
        Ok(vec![])
    }
    async fn find_credential_by_id(
        &self,
        c: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError> {
        Ok(Some(WebauthnCredential {
            id: Some(1),
            username: Arc::from(self.owner),
            credential_id: Arc::from(c),
            label: None,
            passkey: "{}".into(),
            sign_count: 0,
            created_at: None,
            last_used_at: None,
        }))
    }
    async fn update_credential_counter(&self, _c: &str, n: i64) -> Result<(), DomainError> {
        self.persisted_count
            .store(n, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn delete_credential(&self, _id: i64, _u: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn has_credentials(&self, _u: &str) -> Result<bool, DomainError> {
        Ok(true)
    }
}

/// Happy path: a resident passkey alone mints a full session — no username, no
/// password — and the bumped signature counter is persisted.
#[tokio::test]
async fn discoverable_passkey_login_mints_session_and_persists_counter() {
    let persisted = Arc::new(std::sync::atomic::AtomicI64::new(-1));
    let mfa_repo: Arc<dyn MfaRepository> = Arc::new(DiscoverableMfaRepo {
        owner: "admin",
        persisted_count: persisted.clone(),
    });
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: make_admin_user("$hashed$"),
    });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let uc = DiscoverablePasskeyLoginUseCase::new(
        Arc::new(DiscoverableOkWebauthnService),
        mfa_repo,
        user_provider,
        session_repo.clone(),
        Arc::new(AuthConfig::default()),
        300,
    );

    let session = uc
        .finish("tok", serde_json::json!({}), true, "1.2.3.4", "agent")
        .await
        .expect("passwordless login mints a session");

    assert_eq!(session.username.as_ref(), "admin");
    assert_eq!(session.role, UserRole::Admin);
    // finish_discoverable reported sign_count 99 — it must be persisted.
    assert_eq!(persisted.load(std::sync::atomic::Ordering::SeqCst), 99);
    // The session was actually stored.
    assert!(session_repo
        .get_by_id(session.id.as_ref())
        .await
        .unwrap()
        .is_some());
}

/// A disabled account holding a registered resident passkey must NOT be able to
/// log in passwordlessly — discoverable login is the entry point, so it enforces
/// the `!user.enabled` gate itself.
#[tokio::test]
async fn discoverable_passkey_login_rejects_disabled_user() {
    let mut disabled = make_admin_user("$hashed$");
    disabled.enabled = false;
    let mfa_repo: Arc<dyn MfaRepository> = Arc::new(DiscoverableMfaRepo {
        owner: "admin",
        persisted_count: Arc::new(std::sync::atomic::AtomicI64::new(0)),
    });
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider { admin: disabled });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let uc = DiscoverablePasskeyLoginUseCase::new(
        Arc::new(DiscoverableOkWebauthnService),
        mfa_repo,
        user_provider,
        session_repo,
        Arc::new(AuthConfig::default()),
        300,
    );

    match uc
        .finish("tok", serde_json::json!({}), false, "1.2.3.4", "agent")
        .await
    {
        Err(DomainError::InvalidCredentials) => {}
        Err(other) => panic!("expected InvalidCredentials, got {other:?}"),
        Ok(_) => panic!("disabled user must not obtain a session via passwordless passkey"),
    }
}

/// Usernameless (passwordless) passkey login refuses to start when WebAuthn has
/// no relying-party configured.
#[tokio::test]
async fn discoverable_passkey_login_rejected_when_webauthn_not_configured() {
    let webauthn: Arc<dyn WebauthnService> = Arc::new(UnconfiguredWebauthnService);
    let user_provider: Arc<dyn UserProvider> = Arc::new(TestUserProvider {
        admin: make_admin_user("$hashed$"),
    });
    let session_repo: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::new());
    let uc = DiscoverablePasskeyLoginUseCase::new(
        webauthn,
        no_mfa(),
        user_provider,
        session_repo,
        Arc::new(AuthConfig::default()),
        300,
    );

    match uc.start().await {
        Err(DomainError::WebauthnNotConfigured) => {}
        Err(other) => panic!("expected WebauthnNotConfigured, got {other:?}"),
        Ok(_) => panic!("discoverable login must not start when WebAuthn is unconfigured"),
    }
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
