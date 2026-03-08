use ferrous_dns_api::AuthUseCases;
use ferrous_dns_application::ports::{
    ApiTokenRepository, PasswordHasher, SessionRepository, UserProvider, UserRepository,
};
use ferrous_dns_application::use_cases::{
    ChangePasswordUseCase, CreateApiTokenUseCase, CreateUserUseCase, DeleteApiTokenUseCase,
    DeleteUserUseCase, GetActiveSessionsUseCase, GetApiTokensUseCase, GetAuthStatusUseCase,
    GetUsersUseCase, LoginUseCase, LogoutUseCase, SetupPasswordUseCase, UpdateApiTokenUseCase,
    ValidateApiTokenUseCase, ValidateSessionUseCase,
};
use ferrous_dns_domain::{ApiToken, AuthConfig, AuthSession, Config, DomainError, User};
use std::sync::Arc;

pub struct NullSessionRepository;

#[async_trait::async_trait]
impl SessionRepository for NullSessionRepository {
    async fn create(&self, _session: &AuthSession) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_by_id(&self, _id: &str) -> Result<Option<AuthSession>, DomainError> {
        Ok(None)
    }
    async fn update_last_seen(&self, _id: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete(&self, _id: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        Ok(vec![])
    }
}

pub struct NullUserRepository;

#[async_trait::async_trait]
impl UserRepository for NullUserRepository {
    async fn create(
        &self,
        _username: &str,
        _display_name: Option<&str>,
        _password_hash: &str,
        _role: &str,
    ) -> Result<User, DomainError> {
        Err(DomainError::ConfigError("not implemented".to_string()))
    }
    async fn get_by_username(&self, _username: &str) -> Result<Option<User>, DomainError> {
        Ok(None)
    }
    async fn get_by_id(&self, _id: i64) -> Result<Option<User>, DomainError> {
        Ok(None)
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        Ok(vec![])
    }
    async fn update_password(&self, _id: i64, _password_hash: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullUserProvider;

#[async_trait::async_trait]
impl UserProvider for NullUserProvider {
    async fn get_by_username(&self, _username: &str) -> Result<Option<User>, DomainError> {
        Ok(None)
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        Ok(vec![])
    }
    async fn update_password(
        &self,
        _username: &str,
        _password_hash: &str,
    ) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullPasswordHasher;

impl PasswordHasher for NullPasswordHasher {
    fn hash(&self, _password: &str) -> Result<String, DomainError> {
        Ok("$argon2id$test".to_string())
    }
    fn verify(&self, _password: &str, _hash: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
}

pub struct NullApiTokenRepository;

#[async_trait::async_trait]
impl ApiTokenRepository for NullApiTokenRepository {
    async fn create(
        &self,
        _name: &str,
        _key_prefix: &str,
        _key_hash: &str,
        _key_raw: &str,
    ) -> Result<ApiToken, DomainError> {
        Err(DomainError::ConfigError("not implemented".to_string()))
    }
    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError> {
        Ok(vec![])
    }
    async fn get_by_id(&self, _id: i64) -> Result<Option<ApiToken>, DomainError> {
        Ok(None)
    }
    async fn get_by_name(&self, _name: &str) -> Result<Option<ApiToken>, DomainError> {
        Ok(None)
    }
    async fn update(
        &self,
        _id: i64,
        _name: &str,
        _key_prefix: Option<&str>,
        _key_hash: Option<&str>,
        _key_raw: Option<&str>,
    ) -> Result<ApiToken, DomainError> {
        Err(DomainError::ConfigError("not implemented".to_string()))
    }
    async fn delete(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn update_last_used(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_all_hashes(&self) -> Result<Vec<(i64, String)>, DomainError> {
        Ok(vec![])
    }
    async fn get_id_by_hash(&self, _key_hash: &str) -> Result<Option<i64>, DomainError> {
        Ok(None)
    }
}

pub fn build_test_auth_use_cases() -> AuthUseCases {
    let session_repo: Arc<dyn SessionRepository> = Arc::new(NullSessionRepository);
    let user_repo: Arc<dyn UserRepository> = Arc::new(NullUserRepository);
    let user_provider: Arc<dyn UserProvider> = Arc::new(NullUserProvider);
    let password_hasher: Arc<dyn PasswordHasher> = Arc::new(NullPasswordHasher);
    let api_token_repo: Arc<dyn ApiTokenRepository> = Arc::new(NullApiTokenRepository);
    let auth_config = Arc::new(AuthConfig {
        enabled: false,
        ..AuthConfig::default()
    });
    let config = Arc::new(tokio::sync::RwLock::new(Config {
        auth: (*auth_config).clone(),
        ..Config::default()
    }));

    AuthUseCases {
        login: Arc::new(LoginUseCase::new(
            user_provider.clone(),
            session_repo.clone(),
            password_hasher.clone(),
            auth_config.clone(),
        )),
        logout: Arc::new(LogoutUseCase::new(session_repo.clone())),
        validate_session: Arc::new(ValidateSessionUseCase::new(session_repo.clone())),
        setup_password: Arc::new(SetupPasswordUseCase::new(
            user_provider.clone(),
            password_hasher.clone(),
            "admin".to_string(),
        )),
        change_password: Arc::new(ChangePasswordUseCase::new(
            user_provider.clone(),
            password_hasher.clone(),
        )),
        get_auth_status: Arc::new(GetAuthStatusUseCase::new(config)),
        get_active_sessions: Arc::new(GetActiveSessionsUseCase::new(session_repo)),
        create_api_token: Arc::new(CreateApiTokenUseCase::new(api_token_repo.clone())),
        get_api_tokens: Arc::new(GetApiTokensUseCase::new(api_token_repo.clone())),
        update_api_token: Arc::new(UpdateApiTokenUseCase::new(api_token_repo.clone())),
        delete_api_token: Arc::new(DeleteApiTokenUseCase::new(api_token_repo.clone())),
        validate_api_token: Arc::new(ValidateApiTokenUseCase::new(api_token_repo)),
        create_user: Arc::new(CreateUserUseCase::new(
            user_repo.clone(),
            user_provider.clone(),
            password_hasher,
        )),
        get_users: Arc::new(GetUsersUseCase::new(user_provider)),
        delete_user: Arc::new(DeleteUserUseCase::new(user_repo)),
    }
}
