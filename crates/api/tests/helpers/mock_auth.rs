use ferrous_dns_api::AuthUseCases;
use ferrous_dns_application::ports::{
    ApiTokenRepository, AuthenticatedCredential, MfaRepository, PasswordHasher,
    RegisteredCredential, SessionRepository, TotpService, UserProvider, UserRepository,
    WebauthnService,
};
use ferrous_dns_application::use_cases::{
    AuthenticatePasskeyUseCase, ChangePasswordUseCase, ConfirmTotpUseCase, CreateApiTokenUseCase,
    CreateUserUseCase, DeleteApiTokenUseCase, DeletePasskeyUseCase, DeleteUserUseCase,
    DisableMfaUseCase, DiscoverablePasskeyLoginUseCase, GetActiveSessionsUseCase,
    GetApiTokensUseCase, GetAuthStatusUseCase, GetMfaStatusUseCase, GetUsersUseCase, LoginUseCase,
    LogoutUseCase, RegisterPasskeyUseCase, SetupPasswordUseCase, SetupTotpUseCase,
    UpdateApiTokenUseCase, ValidateApiTokenUseCase, ValidateSessionUseCase, VerifyMfaUseCase,
};
use ferrous_dns_domain::User;
use ferrous_dns_domain::{
    ApiToken, AuthConfig, AuthSession, Config, DomainError, MfaChallenge, RecoveryCode, UserMfa,
    WebauthnCredential,
};
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

pub struct NullMfaRepository;

#[async_trait::async_trait]
impl MfaRepository for NullMfaRepository {
    async fn get(&self, _username: &str) -> Result<Option<UserMfa>, DomainError> {
        Ok(None)
    }
    async fn upsert_secret(&self, _username: &str, _secret: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn enable(&self, _username: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_all(&self, _username: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn replace_recovery_codes(
        &self,
        _username: &str,
        _code_hashes: &[String],
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_unused_recovery_codes(
        &self,
        _username: &str,
    ) -> Result<Vec<RecoveryCode>, DomainError> {
        Ok(vec![])
    }
    async fn mark_recovery_code_used(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn create_challenge(&self, _challenge: &MfaChallenge) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_challenge(&self, _token: &str) -> Result<Option<MfaChallenge>, DomainError> {
        Ok(None)
    }
    async fn delete_challenge(&self, _token: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn add_credential(&self, _cred: &WebauthnCredential) -> Result<(), DomainError> {
        Ok(())
    }
    async fn list_credentials(
        &self,
        _username: &str,
    ) -> Result<Vec<WebauthnCredential>, DomainError> {
        Ok(vec![])
    }
    async fn find_credential_by_id(
        &self,
        _credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError> {
        Ok(None)
    }
    async fn update_credential_counter(
        &self,
        _credential_id: &str,
        _sign_count: i64,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn delete_credential(&self, _id: i64, _username: &str) -> Result<(), DomainError> {
        Ok(())
    }
    async fn has_credentials(&self, _username: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
}

pub struct NullTotpService;

impl TotpService for NullTotpService {
    fn generate_secret(&self) -> String {
        "AAAAAAAAAAAAAAAA".to_string()
    }
    fn provisioning_uri(&self, _secret: &str, _account: &str) -> Result<String, DomainError> {
        Ok("otpauth://totp/test".to_string())
    }
    fn qr_svg(&self, _otpauth_uri: &str) -> Result<String, DomainError> {
        Ok("<svg/>".to_string())
    }
    fn verify(&self, _secret: &str, _code: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
}

pub struct NullWebauthnService;

impl WebauthnService for NullWebauthnService {
    fn is_configured(&self) -> bool {
        false
    }
    fn start_registration(
        &self,
        _username: &str,
        _display_name: &str,
        _existing_passkeys: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_registration(
        &self,
        _response: serde_json::Value,
        _state_json: &str,
    ) -> Result<RegisteredCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn start_authentication(
        &self,
        _passkeys_json: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_authentication(
        &self,
        _response: serde_json::Value,
        _state_json: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn start_discoverable(&self) -> Result<(serde_json::Value, String), DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn identify_discoverable(&self, _response: serde_json::Value) -> Result<String, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
    fn finish_discoverable(
        &self,
        _response: serde_json::Value,
        _state_json: &str,
        _passkey_json: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        Err(DomainError::WebauthnNotConfigured)
    }
}

pub fn build_test_auth_use_cases() -> AuthUseCases {
    let session_repo: Arc<dyn SessionRepository> = Arc::new(NullSessionRepository);
    let user_repo: Arc<dyn UserRepository> = Arc::new(NullUserRepository);
    let user_provider: Arc<dyn UserProvider> = Arc::new(NullUserProvider);
    let password_hasher: Arc<dyn PasswordHasher> = Arc::new(NullPasswordHasher);
    let api_token_repo: Arc<dyn ApiTokenRepository> = Arc::new(NullApiTokenRepository);
    let mfa_repo: Arc<dyn MfaRepository> = Arc::new(NullMfaRepository);
    let totp: Arc<dyn TotpService> = Arc::new(NullTotpService);
    let webauthn: Arc<dyn WebauthnService> = Arc::new(NullWebauthnService);
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
            mfa_repo.clone(),
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
        get_active_sessions: Arc::new(GetActiveSessionsUseCase::new(session_repo.clone())),
        create_api_token: Arc::new(CreateApiTokenUseCase::new(api_token_repo.clone())),
        get_api_tokens: Arc::new(GetApiTokensUseCase::new(api_token_repo.clone())),
        update_api_token: Arc::new(UpdateApiTokenUseCase::new(api_token_repo.clone())),
        delete_api_token: Arc::new(DeleteApiTokenUseCase::new(api_token_repo.clone())),
        validate_api_token: Arc::new(ValidateApiTokenUseCase::new(api_token_repo)),
        create_user: Arc::new(CreateUserUseCase::new(
            user_repo.clone(),
            user_provider.clone(),
            password_hasher.clone(),
        )),
        get_users: Arc::new(GetUsersUseCase::new(user_provider.clone())),
        delete_user: Arc::new(DeleteUserUseCase::new(user_repo)),
        verify_mfa: Arc::new(VerifyMfaUseCase::new(
            mfa_repo.clone(),
            totp.clone(),
            password_hasher.clone(),
            user_provider.clone(),
            session_repo.clone(),
            auth_config.clone(),
        )),
        setup_totp: Arc::new(SetupTotpUseCase::new(mfa_repo.clone(), totp.clone())),
        confirm_totp: Arc::new(ConfirmTotpUseCase::new(
            mfa_repo.clone(),
            totp,
            password_hasher.clone(),
        )),
        disable_mfa: Arc::new(DisableMfaUseCase::new(
            user_provider.clone(),
            password_hasher,
            mfa_repo.clone(),
        )),
        get_mfa_status: Arc::new(GetMfaStatusUseCase::new(mfa_repo.clone())),
        register_passkey: Arc::new(RegisterPasskeyUseCase::new(
            webauthn.clone(),
            mfa_repo.clone(),
            auth_config.mfa_challenge_ttl_secs,
        )),
        authenticate_passkey: Arc::new(AuthenticatePasskeyUseCase::new(
            webauthn.clone(),
            mfa_repo.clone(),
            user_provider.clone(),
            session_repo.clone(),
            auth_config.clone(),
        )),
        discoverable_passkey_login: Arc::new(DiscoverablePasskeyLoginUseCase::new(
            webauthn,
            mfa_repo.clone(),
            user_provider,
            session_repo,
            auth_config,
            300,
        )),
        delete_passkey: Arc::new(DeletePasskeyUseCase::new(mfa_repo)),
    }
}
