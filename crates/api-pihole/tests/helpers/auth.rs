//! In-memory auth doubles for the Pi-hole API tests: one enabled `admin` whose
//! password is [`ADMIN_PASSWORD`], one API token [`APP_PASSWORD`], and — when
//! enrolled — a TOTP second factor that accepts only [`TOTP_CODE`].

use async_trait::async_trait;
use ferrous_dns_api_pihole::state::PiholeAuthState;
use ferrous_dns_application::ports::{
    ApiKeyMaterial, ApiTokenRepository, MfaRepository, PasswordHasher, SessionRepository,
    TotpService, UserProvider,
};
use ferrous_dns_application::use_cases::{
    AppPasswordLoginUseCase, CreateApiTokenUseCase, GetActiveSessionsUseCase, GetMfaStatusUseCase,
    LoginRateLimiter, LoginUseCase, LogoutUseCase, ValidateApiTokenUseCase, ValidateSessionUseCase,
    VerifyMfaUseCase,
};
use ferrous_dns_domain::{
    ApiToken, AuthConfig, AuthSession, DomainError, MfaChallenge, RecoveryCode, User, UserMfa,
    UserRole, UserSource, WebauthnCredential,
};
use std::sync::{Arc, Mutex};

pub const ADMIN_PASSWORD: &str = "correct-password";
pub const APP_PASSWORD: &str = "app-password-0123456789abcdef";
pub const TOTP_CODE: &str = "123456";

/// The auth use cases wired the way `cli/src/wiring/auth.rs` wires them: one
/// login lockout shared by password, app password and second factor.
pub async fn build_auth_state(totp_enrolled: bool) -> PiholeAuthState {
    let config = Arc::new(AuthConfig::default());
    let users: Arc<dyn UserProvider> = Arc::new(AdminUserProvider);
    let sessions: Arc<dyn SessionRepository> = Arc::new(InMemorySessionRepository::default());
    let hasher: Arc<dyn PasswordHasher> = Arc::new(PlainPasswordHasher);
    let mfa: Arc<dyn MfaRepository> = Arc::new(InMemoryMfaRepository::new(totp_enrolled));
    let totp: Arc<dyn TotpService> = Arc::new(FixedTotpService);
    let rate_limiter = Arc::new(LoginRateLimiter::from_config(&config));

    let tokens: Arc<dyn ApiTokenRepository> = Arc::new(InMemoryApiTokenRepository::default());
    CreateApiTokenUseCase::new(tokens.clone())
        .execute("pihole-app", Some(APP_PASSWORD))
        .await
        .expect("failed to seed the app password");

    PiholeAuthState {
        login: Arc::new(
            LoginUseCase::new(
                users.clone(),
                sessions.clone(),
                hasher.clone(),
                mfa.clone(),
                config.clone(),
            )
            .with_rate_limiter(rate_limiter.clone()),
        ),
        verify_mfa: Arc::new(
            VerifyMfaUseCase::new(
                mfa.clone(),
                totp,
                hasher,
                users.clone(),
                sessions.clone(),
                config.clone(),
            )
            .with_rate_limiter(rate_limiter.clone()),
        ),
        app_password_login: Arc::new(AppPasswordLoginUseCase::new(
            Arc::new(ValidateApiTokenUseCase::new(tokens)),
            users,
            sessions.clone(),
            config,
            rate_limiter,
        )),
        logout: Arc::new(LogoutUseCase::new(sessions.clone())),
        validate_session: Arc::new(ValidateSessionUseCase::new(sessions.clone())),
        get_active_sessions: Arc::new(GetActiveSessionsUseCase::new(sessions)),
        get_mfa_status: Arc::new(GetMfaStatusUseCase::new(mfa)),
    }
}

struct AdminUserProvider;

#[async_trait]
impl UserProvider for AdminUserProvider {
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        Ok((username == "admin").then(|| User {
            id: Some(1),
            username: Arc::from("admin"),
            display_name: None,
            password_hash: Arc::from("$hashed$"),
            role: UserRole::Admin,
            source: UserSource::Toml,
            enabled: true,
            created_at: None,
            updated_at: None,
        }))
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        Ok(Vec::new())
    }
    async fn update_password(&self, _: &str, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

struct PlainPasswordHasher;

#[async_trait]
impl PasswordHasher for PlainPasswordHasher {
    async fn hash(&self, _: &str) -> Result<String, DomainError> {
        Ok("$hashed$".to_string())
    }
    async fn verify(&self, password: &str, _: &str) -> Result<bool, DomainError> {
        Ok(password == ADMIN_PASSWORD)
    }
    async fn hash_many(&self, passwords: &[String]) -> Result<Vec<String>, DomainError> {
        Ok(passwords.iter().map(|_| "$hashed$".to_string()).collect())
    }
    async fn verify_any(&self, _: &str, _: Vec<Arc<str>>) -> Result<Option<usize>, DomainError> {
        Ok(None)
    }
}

#[derive(Default)]
struct InMemorySessionRepository {
    sessions: Mutex<Vec<AuthSession>>,
}

#[async_trait]
impl SessionRepository for InMemorySessionRepository {
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError> {
        self.sessions.lock().unwrap().push(session.clone());
        Ok(())
    }
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.iter().find(|s| s.id.as_ref() == id).cloned())
    }
    async fn update_last_seen(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete(&self, id: &str) -> Result<(), DomainError> {
        self.sessions
            .lock()
            .unwrap()
            .retain(|s| s.id.as_ref() != id);
        Ok(())
    }
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn delete_other_sessions(
        &self,
        username: &str,
        keep_id: &str,
    ) -> Result<u64, DomainError> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = sessions.len();
        sessions.retain(|s| s.username.as_ref() != username || s.id.as_ref() == keep_id);
        Ok((before - sessions.len()) as u64)
    }
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        Ok(self.sessions.lock().unwrap().clone())
    }
}

/// Holds the one pending second-factor challenge; TOTP is enrolled or not for
/// the whole test.
struct InMemoryMfaRepository {
    totp_enrolled: bool,
    challenge: Mutex<Option<MfaChallenge>>,
}

impl InMemoryMfaRepository {
    fn new(totp_enrolled: bool) -> Self {
        Self {
            totp_enrolled,
            challenge: Mutex::new(None),
        }
    }
}

#[async_trait]
impl MfaRepository for InMemoryMfaRepository {
    async fn get(&self, username: &str) -> Result<Option<UserMfa>, DomainError> {
        Ok(self.totp_enrolled.then(|| UserMfa {
            username: Arc::from(username),
            totp_secret: Arc::from("SECRET"),
            totp_enabled: true,
            created_at: None,
            confirmed_at: None,
        }))
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
        Ok(Vec::new())
    }
    async fn mark_recovery_code_used(&self, _: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn create_challenge(&self, challenge: &MfaChallenge) -> Result<(), DomainError> {
        *self.challenge.lock().unwrap() = Some(challenge.clone());
        Ok(())
    }
    async fn get_challenge(&self, token: &str) -> Result<Option<MfaChallenge>, DomainError> {
        let challenge = self.challenge.lock().unwrap();
        Ok(challenge
            .clone()
            .filter(|challenge| challenge.token.as_ref() == token))
    }
    async fn delete_challenge(&self, _: &str) -> Result<(), DomainError> {
        *self.challenge.lock().unwrap() = None;
        Ok(())
    }
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn add_credential(&self, _: &WebauthnCredential) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_credentials(&self, _: &str) -> Result<Vec<WebauthnCredential>, DomainError> {
        Ok(Vec::new())
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

struct FixedTotpService;

impl TotpService for FixedTotpService {
    fn generate_secret(&self) -> String {
        "SECRET".to_string()
    }
    fn provisioning_uri(&self, _: &str, _: &str) -> Result<String, DomainError> {
        Ok("otpauth://totp/x".to_string())
    }
    fn qr_svg(&self, _: &str) -> Result<String, DomainError> {
        Ok("<svg/>".to_string())
    }
    fn verify(&self, _: &str, code: &str) -> Result<Option<u64>, DomainError> {
        Ok((code == TOTP_CODE).then_some(1))
    }
}

/// Stores only what login needs: token hashes looked up by value.
#[derive(Default)]
struct InMemoryApiTokenRepository {
    hashes: Mutex<Vec<String>>,
}

#[async_trait]
impl ApiTokenRepository for InMemoryApiTokenRepository {
    async fn create(
        &self,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
        _: &str,
    ) -> Result<ApiToken, DomainError> {
        let mut hashes = self.hashes.lock().unwrap();
        hashes.push(key_hash.to_string());
        Ok(ApiToken {
            id: Some(hashes.len() as i64),
            name: Arc::from(name),
            key_prefix: Arc::from(key_prefix),
            key_hash: Arc::from(key_hash),
            key_raw: None,
            created_at: None,
            last_used_at: None,
        })
    }
    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError> {
        Ok(Vec::new())
    }
    async fn get_by_id(&self, _: i64) -> Result<Option<ApiToken>, DomainError> {
        Ok(None)
    }
    async fn get_by_name(&self, _: &str) -> Result<Option<ApiToken>, DomainError> {
        Ok(None)
    }
    async fn update(
        &self,
        id: i64,
        _: &str,
        _: Option<ApiKeyMaterial<'_>>,
    ) -> Result<ApiToken, DomainError> {
        Err(DomainError::ApiTokenNotFound(id))
    }
    async fn delete(&self, _: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn update_last_used(&self, _: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_id_by_hash(&self, key_hash: &str) -> Result<Option<i64>, DomainError> {
        let hashes = self.hashes.lock().unwrap();
        Ok(hashes
            .iter()
            .position(|hash| hash == key_hash)
            .map(|index| index as i64 + 1))
    }
}
