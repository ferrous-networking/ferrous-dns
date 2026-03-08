use async_trait::async_trait;
use ferrous_dns_application::ports::ApiTokenRepository;
use ferrous_dns_application::use_cases::{
    CreateApiTokenUseCase, DeleteApiTokenUseCase, GetApiTokensUseCase, UpdateApiTokenUseCase,
    ValidateApiTokenUseCase,
};
use ferrous_dns_domain::{ApiToken, DomainError};
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// In-memory mock
// ---------------------------------------------------------------------------

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
        key_raw: &str,
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
            key_raw: Some(Arc::from(key_raw)),
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
        key_prefix: Option<&str>,
        key_hash: Option<&str>,
        key_raw: Option<&str>,
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
        if let Some(p) = key_prefix {
            token.key_prefix = Arc::from(p);
        }
        if let Some(h) = key_hash {
            token.key_hash = Arc::from(h);
        }
        if let Some(r) = key_raw {
            token.key_raw = Some(Arc::from(r));
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

    async fn get_all_hashes(&self) -> Result<Vec<(i64, String)>, DomainError> {
        Ok(self
            .tokens
            .read()
            .await
            .iter()
            .map(|t| (t.id.unwrap(), t.key_hash.to_string()))
            .collect())
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

// ---------------------------------------------------------------------------
// CreateApiTokenUseCase
// ---------------------------------------------------------------------------

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

    let custom = "my-custom-api-key-from-pihole";
    let created = uc.execute("imported", Some(custom)).await.unwrap();

    assert_eq!(created.raw_token, custom);
    assert_eq!(created.token.key_prefix.as_ref(), &custom[..8]);
}

#[tokio::test]
async fn create_token_rejects_empty_name() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let result = uc.execute("", None).await;
    assert!(matches!(result, Err(DomainError::ConfigError(_))));
}

#[tokio::test]
async fn create_token_rejects_invalid_name() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let result = uc.execute("bad!name", None).await;
    assert!(matches!(result, Err(DomainError::ConfigError(_))));
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
async fn create_token_prefix_from_short_key() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = CreateApiTokenUseCase::new(repo);

    let created = uc.execute("short", Some("abc")).await.unwrap();
    assert_eq!(created.token.key_prefix.as_ref(), "abc");
}

// ---------------------------------------------------------------------------
// GetApiTokensUseCase
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_tokens_empty_list() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let uc = GetApiTokensUseCase::new(repo);

    let tokens = uc.execute().await.unwrap();
    assert!(tokens.is_empty());
}

#[tokio::test]
async fn get_tokens_returns_all() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    create.execute("first", None).await.unwrap();
    create.execute("second", None).await.unwrap();

    let get = GetApiTokensUseCase::new(repo);
    let tokens = get.execute().await.unwrap();
    assert_eq!(tokens.len(), 2);
}

// ---------------------------------------------------------------------------
// DeleteApiTokenUseCase
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_existing_token() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let create = CreateApiTokenUseCase::new(repo.clone());
    let created = create.execute("to-delete", None).await.unwrap();
    let id = created.token.id.unwrap();

    let delete = DeleteApiTokenUseCase::new(repo.clone());
    assert!(delete.execute(id).await.is_ok());

    let all = repo.get_all().await.unwrap();
    assert!(all.is_empty());
}

#[tokio::test]
async fn delete_nonexistent_token_returns_error() {
    let repo = Arc::new(MockApiTokenRepo::new());
    let delete = DeleteApiTokenUseCase::new(repo);

    let err = delete.execute(999).await.unwrap_err();
    assert!(matches!(err, DomainError::ApiTokenNotFound(999)));
}

// ---------------------------------------------------------------------------
// UpdateApiTokenUseCase
// ---------------------------------------------------------------------------

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
        .execute(id, "token", Some("new-custom-key-value"))
        .await
        .unwrap();

    assert_ne!(updated.key_hash.as_ref(), old_hash.as_str());
    assert_eq!(updated.key_prefix.as_ref(), "new-cust");
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
    assert!(matches!(err, DomainError::ConfigError(_)));
}

// ---------------------------------------------------------------------------
// ValidateApiTokenUseCase
// ---------------------------------------------------------------------------

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
