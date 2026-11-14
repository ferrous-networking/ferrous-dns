use async_trait::async_trait;
use ferrous_dns_application::ports::{
    ApiKeyMaterial, ApiTokenRepository, SessionRepository, UserProvider,
};
use ferrous_dns_application::use_cases::{
    AppPasswordLoginUseCase, CreateApiTokenUseCase, LoginRateLimiter, UpdateApiTokenUseCase,
    ValidateApiTokenUseCase,
};
use ferrous_dns_domain::{
    ApiToken, AuthConfig, AuthSession, DomainError, User, UserRole, UserSource,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

struct MockApiTokenRepo {
    tokens: RwLock<Vec<ApiToken>>,
    next_id: RwLock<i64>,
}

impl MockApiTokenRepo {
    fn new() -> Self {
        Self {
            tokens: RwLock::new(Vec::new()),
            next_id: RwLock::new(1),
        }
    }
}

#[async_trait]
impl ApiTokenRepository for MockApiTokenRepo {
    async fn create(
        &self,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
    ) -> Result<ApiToken, DomainError> {
        let mut tokens = self.tokens.write().await;
        if tokens.iter().any(|t| t.name.as_ref() == name) {
            return Err(DomainError::DuplicateApiTokenName(name.to_string()));
        }
        let mut next = self.next_id.write().await;
        let id = *next;
        *next += 1;
        let token = ApiToken {
            id: Some(id),
            name: Arc::from(name),
            key_prefix: Arc::from(key_prefix),
            key_hash: Arc::from(key_hash),
            created_at: Some("2026-01-01 00:00:00".to_string()),
            last_used_at: None,
        };
        tokens.push(token.clone());
        Ok(token)
    }

    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError> {
        Ok(self.tokens.read().await.clone())
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<ApiToken>, DomainError> {
        Ok(self
            .tokens
            .read()
            .await
            .iter()
            .find(|t| t.id == Some(id))
            .cloned())
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DomainError> {
        Ok(self
            .tokens
            .read()
            .await
            .iter()
            .find(|t| t.name.as_ref() == name)
            .cloned())
    }

    async fn update(
        &self,
        id: i64,
        name: &str,
        new_key: Option<ApiKeyMaterial<'_>>,
    ) -> Result<ApiToken, DomainError> {
        let mut tokens = self.tokens.write().await;
        // Check name uniqueness (excluding self)
        if tokens
            .iter()
            .any(|t| t.name.as_ref() == name && t.id != Some(id))
        {
            return Err(DomainError::DuplicateApiTokenName(name.to_string()));
        }
        let token = tokens
            .iter_mut()
            .find(|t| t.id == Some(id))
            .ok_or(DomainError::ApiTokenNotFound(id))?;
        token.name = Arc::from(name);
        if let Some(key) = new_key {
            token.key_prefix = Arc::from(key.prefix);
            token.key_hash = Arc::from(key.hash);
        }
        Ok(token.clone())
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let mut tokens = self.tokens.write().await;
        let before = tokens.len();
        tokens.retain(|t| t.id != Some(id));
        if tokens.len() == before {
            return Err(DomainError::ApiTokenNotFound(id));
        }
        Ok(())
    }

    async fn update_last_used(&self, id: i64) -> Result<(), DomainError> {
        let mut tokens = self.tokens.write().await;
        if let Some(t) = tokens.iter_mut().find(|t| t.id == Some(id)) {
            t.last_used_at = Some("2026-01-01 12:00:00".to_string());
        }
        Ok(())
    }

    async fn get_id_by_hash(&self, key_hash: &str) -> Result<Option<i64>, DomainError> {
        Ok(self
            .tokens
            .read()
            .await
            .iter()
            .find(|t| t.key_hash.as_ref() == key_hash)
            .and_then(|t| t.id))
    }
}

#[tokio::test]
async fn create_token_generates_random_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo.clone());

    let result = uc.execute("my-token", None).await;
    assert!(result.is_ok());

    let created = result.unwrap();
    assert_eq!(created.token.name.as_ref(), "my-token");
    assert!(!created.raw_token.is_empty());
    assert_eq!(
        created.raw_token.len(),
        64,
        "generated token should be 64 hex chars"
    );
}

#[tokio::test]
async fn create_token_with_custom_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let custom = "my-custom-api-key-from-pihole-v5x";
    let created = uc.execute("imported", Some(custom)).await.unwrap();

    assert_eq!(created.raw_token, custom);
    assert_eq!(created.token.key_prefix.as_ref(), &custom[..8]);
}

#[tokio::test]
async fn create_token_rejects_empty_name() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let result = uc.execute("", None).await;
    assert!(matches!(result, Err(DomainError::InvalidInput(_))));
}

#[tokio::test]
async fn create_token_rejects_invalid_name() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let result = uc.execute("bad!name", None).await;
    assert!(matches!(result, Err(DomainError::InvalidInput(_))));
}

#[tokio::test]
async fn create_token_rejects_duplicate_name() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    uc.execute("unique", None).await.unwrap();
    let result = uc.execute("unique", None).await;
    assert!(matches!(result, Err(DomainError::DuplicateApiTokenName(_))));
}

#[tokio::test]
async fn test_create_token_refuses_a_custom_key_shorter_than_32_characters() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo.clone());

    for key in ["abc", "abcdefgh", &"k".repeat(31), &"é".repeat(31)] {
        let result = uc.execute("short", Some(key)).await;
        assert!(
            matches!(result, Err(DomainError::InvalidInput(_))),
            "a {}-character key was accepted",
            key.chars().count()
        );
    }
    assert!(repo.get_all().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_create_token_accepts_a_32_character_custom_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let key = "0123456789abcdef0123456789abcdef";
    let created = uc.execute("exact", Some(key)).await.unwrap();
    assert_eq!(created.raw_token, key);
    assert_eq!(created.token.key_prefix.as_ref(), "01234567");
}

#[tokio::test]
async fn test_create_token_lists_eight_characters_of_a_generated_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let created = uc.execute("generated", None).await.unwrap();
    assert_eq!(created.token.key_prefix.as_ref(), &created.raw_token[..8]);
}

#[tokio::test]
async fn create_token_prefix_stops_at_char_boundary() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    // 8 bytes fall inside the fourth 'é'.
    let key = format!("a{}", "é".repeat(31));
    let created = uc.execute("utf8", Some(&key)).await.unwrap();
    assert_eq!(created.token.key_prefix.as_ref(), "aééé");
}

#[tokio::test]
async fn update_token_name_only() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("original", None).await.unwrap();
    let id = created.token.id.unwrap();
    let original_hash = created.token.key_hash.to_string();

    let update = UpdateApiTokenUseCase::new(repo);
    let updated = update.execute(id, "renamed", None).await.unwrap();

    assert_eq!(updated.name.as_ref(), "renamed");
    assert_eq!(updated.key_hash.as_ref(), original_hash.as_str());
}

#[tokio::test]
async fn update_token_with_new_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("token", None).await.unwrap();
    let id = created.token.id.unwrap();
    let old_hash = created.token.key_hash.to_string();

    let update = UpdateApiTokenUseCase::new(repo);
    let updated = update
        .execute(id, "token", Some("new-custom-key-value-0123456789ab"))
        .await
        .unwrap();

    assert_ne!(updated.key_hash.as_ref(), old_hash.as_str());
    assert_eq!(updated.key_prefix.as_ref(), "new-cust");
}

#[tokio::test]
async fn test_update_token_refuses_a_short_replacement_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let created = CreateApiTokenUseCase::new(repo.clone())
        .execute("token", None)
        .await
        .unwrap();
    let id = created.token.id.unwrap();

    let result = UpdateApiTokenUseCase::new(repo.clone())
        .execute(id, "token", Some(&"k".repeat(31)))
        .await;

    assert!(matches!(result, Err(DomainError::InvalidInput(_))));
    let validate = ValidateApiTokenUseCase::new(repo);
    assert_eq!(validate.execute(&created.raw_token).await.unwrap(), id);
}

/// A short key made before the minimum existed keeps signing in.
#[tokio::test]
async fn test_a_short_key_created_before_the_minimum_still_validates() {
    use sha2::{Digest, Sha256};
    let repo = Arc::new(MockApiTokenRepo::new());
    let legacy = "legacy-key";
    let hash: String = Sha256::digest(legacy.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let token = repo.create("legacy", "le", &hash).await.unwrap();

    let validate = ValidateApiTokenUseCase::new(repo);
    assert_eq!(validate.execute(legacy).await.unwrap(), token.id.unwrap());
}

#[tokio::test]
async fn update_rejects_duplicate_name_from_another_token() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    create.execute("first", None).await.unwrap();
    let second = create.execute("second", None).await.unwrap();
    let id2 = second.token.id.unwrap();

    let update = UpdateApiTokenUseCase::new(repo);
    let err = update.execute(id2, "first", None).await.unwrap_err();
    assert!(matches!(err, DomainError::DuplicateApiTokenName(_)));
}

#[tokio::test]
async fn update_allows_keeping_same_name() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("keep-name", None).await.unwrap();
    let id = created.token.id.unwrap();

    let update = UpdateApiTokenUseCase::new(repo);
    let result = update.execute(id, "keep-name", None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn update_nonexistent_token_returns_error() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let update = UpdateApiTokenUseCase::new(repo);

    let err = update.execute(999, "name", None).await.unwrap_err();
    assert!(matches!(err, DomainError::ApiTokenNotFound(999)));
}

#[tokio::test]
async fn update_rejects_invalid_name() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("valid", None).await.unwrap();
    let id = created.token.id.unwrap();

    let update = UpdateApiTokenUseCase::new(repo);
    let err = update.execute(id, "", None).await.unwrap_err();
    assert!(matches!(err, DomainError::InvalidInput(_)));
}

#[tokio::test]
async fn update_with_empty_key_keeps_existing_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("token", None).await.unwrap();
    let id = created.token.id.unwrap();

    UpdateApiTokenUseCase::new(repo.clone())
        .execute(id, "token", Some(""))
        .await
        .unwrap();

    let validate = ValidateApiTokenUseCase::new(repo);
    assert_eq!(validate.execute(&created.raw_token).await.unwrap(), id);
    assert!(matches!(
        validate.execute("").await,
        Err(DomainError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn validate_correct_token_returns_id() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("auth-token", None).await.unwrap();
    let expected_id = created.token.id.unwrap();

    let validate = ValidateApiTokenUseCase::new(repo);
    let id = validate.execute(&created.raw_token).await.unwrap();
    assert_eq!(id, expected_id);
}

#[tokio::test]
async fn validate_wrong_token_returns_invalid_credentials() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    create.execute("token", None).await.unwrap();

    let validate = ValidateApiTokenUseCase::new(repo);
    let err = validate.execute("wrong-token-value").await.unwrap_err();
    assert!(matches!(err, DomainError::InvalidCredentials));
}

#[tokio::test]
async fn validate_updates_last_used_timestamp() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("track-usage", None).await.unwrap();
    let id = created.token.id.unwrap();

    assert!(repo
        .get_by_id(id)
        .await
        .unwrap()
        .unwrap()
        .last_used_at
        .is_none());

    let validate = ValidateApiTokenUseCase::new(repo.clone());
    validate.execute(&created.raw_token).await.unwrap();

    let token = repo.get_by_id(id).await.unwrap().unwrap();
    assert!(token.last_used_at.is_some());
}

#[tokio::test]
async fn validate_custom_imported_token() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let pihole_key = "abcdef1234567890abcdef1234567890";
    let created = create
        .execute("pihole-import", Some(pihole_key))
        .await
        .unwrap();

    let validate = ValidateApiTokenUseCase::new(repo);
    let id = validate.execute(pihole_key).await.unwrap();
    assert_eq!(id, created.token.id.unwrap());
}

#[tokio::test]
async fn validate_empty_repo_returns_invalid_credentials() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let validate = ValidateApiTokenUseCase::new(repo);

    let err = validate.execute("any-token").await.unwrap_err();
    assert!(matches!(err, DomainError::InvalidCredentials));
}

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

struct AdminOnlyUserProvider {
    enabled: bool,
}

#[async_trait]
impl UserProvider for AdminOnlyUserProvider {
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        Ok((username == "admin").then(|| User {
            id: Some(1),
            username: Arc::from("admin"),
            display_name: None,
            password_hash: Arc::from("$hashed$"),
            role: UserRole::Admin,
            source: UserSource::Toml,
            enabled: self.enabled,
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

#[derive(Default)]
struct InMemorySessionRepo {
    sessions: RwLock<Vec<AuthSession>>,
}

#[async_trait]
impl SessionRepository for InMemorySessionRepo {
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError> {
        self.sessions.write().await.push(session.clone());
        Ok(())
    }
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError> {
        let sessions = self.sessions.read().await;
        Ok(sessions.iter().find(|s| s.id.as_ref() == id).cloned())
    }
    async fn update_last_seen(&self, _: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete(&self, id: &str) -> Result<(), DomainError> {
        self.sessions.write().await.retain(|s| s.id.as_ref() != id);
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
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|s| s.username.as_ref() != username || s.id.as_ref() == keep_id);
        Ok((before - sessions.len()) as u64)
    }
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        Ok(self.sessions.read().await.clone())
    }
}

struct AppPasswordFixture {
    use_case: AppPasswordLoginUseCase,
    sessions: Arc<InMemorySessionRepo>,
    rate_limiter: Arc<LoginRateLimiter>,
    token: String,
}

async fn app_password_fixture(admin_enabled: bool) -> AppPasswordFixture {
    let repo = Arc::new(MockApiTokenRepo::new());
    let token = CreateApiTokenUseCase::new(repo.clone())
        .execute("pihole-app", None)
        .await
        .unwrap()
        .raw_token;
    let sessions = Arc::new(InMemorySessionRepo::default());
    let rate_limiter = Arc::new(LoginRateLimiter::new(3, Duration::from_secs(900)));
    let use_case = AppPasswordLoginUseCase::new(
        Arc::new(ValidateApiTokenUseCase::new(repo)),
        Arc::new(AdminOnlyUserProvider {
            enabled: admin_enabled,
        }),
        sessions.clone(),
        Arc::new(AuthConfig::default()),
        rate_limiter.clone(),
    );
    AppPasswordFixture {
        use_case,
        sessions,
        rate_limiter,
        token,
    }
}

#[tokio::test]
async fn app_password_login_with_valid_token_creates_session() {
    let fixture = app_password_fixture(true).await;

    let issued = fixture
        .use_case
        .execute("admin", &fixture.token, PEER, "192.0.2.10", "agent")
        .await
        .unwrap();

    assert_eq!(issued.session.username.as_ref(), "admin");
    assert_eq!(issued.session.role, UserRole::Admin);
    let stored = fixture.sessions.get_all_active().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, issued.session.id);
}

#[tokio::test]
async fn app_password_login_rejects_unknown_token() {
    let fixture = app_password_fixture(true).await;

    let err = fixture
        .use_case
        .execute("admin", "not-a-token", PEER, "192.0.2.10", "agent")
        .await
        .unwrap_err();

    assert!(matches!(err, DomainError::InvalidCredentials));
    assert!(fixture.sessions.get_all_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn app_password_login_rejects_disabled_user() {
    let fixture = app_password_fixture(false).await;

    let err = fixture
        .use_case
        .execute("admin", &fixture.token, PEER, "192.0.2.10", "agent")
        .await
        .unwrap_err();

    assert!(matches!(err, DomainError::InvalidCredentials));
}

#[tokio::test]
async fn app_password_login_is_refused_while_locked_out() {
    let fixture = app_password_fixture(true).await;
    for _ in 0..3 {
        fixture.rate_limiter.record_failure(PEER);
    }

    let err = fixture
        .use_case
        .execute("admin", &fixture.token, PEER, "192.0.2.10", "agent")
        .await
        .unwrap_err();

    assert!(matches!(err, DomainError::RateLimited));
}

#[tokio::test]
async fn app_password_login_does_not_count_wrong_tokens() {
    let fixture = app_password_fixture(true).await;

    for _ in 0..10 {
        let _ = fixture
            .use_case
            .execute("admin", "not-a-token", PEER, "192.0.2.10", "agent")
            .await;
    }

    assert!(fixture.rate_limiter.check(PEER).is_ok());
}

#[tokio::test]
async fn app_password_login_clears_earlier_failures() {
    let fixture = app_password_fixture(true).await;
    fixture.rate_limiter.record_failure(PEER);
    fixture.rate_limiter.record_failure(PEER);

    fixture
        .use_case
        .execute("admin", &fixture.token, PEER, "192.0.2.10", "agent")
        .await
        .unwrap();

    fixture.rate_limiter.record_failure(PEER);
    fixture.rate_limiter.record_failure(PEER);
    assert!(fixture.rate_limiter.check(PEER).is_ok());
}
