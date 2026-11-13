use ferrous_dns_api::AuthUseCases;
use ferrous_dns_application::ports::{TotpService, UserProvider, WebauthnService};
use ferrous_dns_application::use_cases::{
    AppPasswordLoginUseCase, AuthenticatePasskeyUseCase, ChangePasswordUseCase, ConfirmTotpUseCase,
    CreateApiTokenUseCase, CreateUserUseCase, DeleteApiTokenUseCase, DeletePasskeyUseCase,
    DeleteUserUseCase, DisableMfaUseCase, DiscoverablePasskeyLoginUseCase,
    GetActiveSessionsUseCase, GetApiTokensUseCase, GetAuthStatusUseCase, GetMfaStatusUseCase,
    GetUsersUseCase, LoginRateLimiter, LoginUseCase, LogoutUseCase, RegisterPasskeyUseCase,
    RevokeSessionUseCase, SetupPasswordUseCase, SetupTotpUseCase, UpdateApiTokenUseCase,
    ValidateApiTokenUseCase, ValidateSessionUseCase, VerifyMfaUseCase,
};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::auth::{
    Argon2PasswordHasher, CompositeUserProvider, TomlAdminProvider, TotpRsService,
    WebauthnRsService,
};
use ferrous_dns_infrastructure::repositories::TomlConfigFilePersistence;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::app_state::resolve_config_file;
use super::Repositories;

/// Auth use cases built once and shared by the native API and the Pi-hole
/// compatible API, so every credential check — on either API — counts toward
/// the same login lockout.
pub struct AuthServices {
    pub use_cases: AuthUseCases,
    pub app_password_login: Arc<AppPasswordLoginUseCase>,
}

pub async fn build_auth_services(
    repos: &Repositories,
    config: Arc<RwLock<Config>>,
    config_path: Option<&str>,
) -> AuthServices {
    let auth_config = {
        let cfg = config.read().await;
        Arc::new(cfg.auth.clone())
    };

    let password_hasher = Arc::new(Argon2PasswordHasher::new());
    let rate_limiter = Arc::new(LoginRateLimiter::from_config(&auth_config));

    let totp_service: Arc<dyn TotpService> =
        Arc::new(TotpRsService::new(auth_config.totp_issuer.clone()));
    let webauthn_service: Arc<dyn WebauthnService> = Arc::new(WebauthnRsService::new(
        &auth_config.webauthn.rp_id,
        &auth_config.webauthn.rp_origin,
    ));

    let toml_admin = TomlAdminProvider::new(auth_config.admin.clone());
    let user_provider: Arc<dyn UserProvider> = Arc::new(CompositeUserProvider::new(
        toml_admin,
        repos.user.clone(),
        config.clone(),
        Some(resolve_config_file(config_path)),
        Arc::new(TomlConfigFilePersistence),
    ));

    let validate_api_token = Arc::new(ValidateApiTokenUseCase::new(repos.api_token.clone()));

    let app_password_login = Arc::new(AppPasswordLoginUseCase::new(
        validate_api_token.clone(),
        user_provider.clone(),
        repos.session.clone(),
        auth_config.clone(),
        rate_limiter.clone(),
    ));

    let use_cases = AuthUseCases {
        login: Arc::new(
            LoginUseCase::new(
                user_provider.clone(),
                repos.session.clone(),
                password_hasher.clone(),
                repos.mfa.clone(),
                auth_config.clone(),
            )
            .with_rate_limiter(rate_limiter.clone()),
        ),
        logout: Arc::new(LogoutUseCase::new(repos.session.clone())),
        revoke_session: Arc::new(RevokeSessionUseCase::new(repos.session.clone())),
        validate_session: Arc::new(ValidateSessionUseCase::new(repos.session.clone())),
        setup_password: Arc::new(SetupPasswordUseCase::new(
            user_provider.clone(),
            password_hasher.clone(),
            auth_config.admin.username.clone(),
        )),
        change_password: Arc::new(ChangePasswordUseCase::new(
            user_provider.clone(),
            password_hasher.clone(),
            repos.session.clone(),
        )),
        get_auth_status: Arc::new(GetAuthStatusUseCase::new(config)),
        get_active_sessions: Arc::new(GetActiveSessionsUseCase::new(repos.session.clone())),
        create_api_token: Arc::new(CreateApiTokenUseCase::new(repos.api_token.clone())),
        get_api_tokens: Arc::new(GetApiTokensUseCase::new(repos.api_token.clone())),
        update_api_token: Arc::new(UpdateApiTokenUseCase::new(repos.api_token.clone())),
        delete_api_token: Arc::new(DeleteApiTokenUseCase::new(repos.api_token.clone())),
        validate_api_token,
        create_user: Arc::new(CreateUserUseCase::new(
            repos.user.clone(),
            user_provider.clone(),
            password_hasher.clone(),
            auth_config.admin.username.clone(),
        )),
        get_users: Arc::new(GetUsersUseCase::new(user_provider.clone())),
        delete_user: Arc::new(DeleteUserUseCase::new(repos.user.clone())),
        verify_mfa: Arc::new(
            VerifyMfaUseCase::new(
                repos.mfa.clone(),
                totp_service.clone(),
                password_hasher.clone(),
                user_provider.clone(),
                repos.session.clone(),
                auth_config.clone(),
            )
            .with_rate_limiter(rate_limiter),
        ),
        setup_totp: Arc::new(SetupTotpUseCase::new(
            repos.mfa.clone(),
            totp_service.clone(),
        )),
        confirm_totp: Arc::new(ConfirmTotpUseCase::new(
            repos.mfa.clone(),
            totp_service,
            password_hasher.clone(),
        )),
        disable_mfa: Arc::new(DisableMfaUseCase::new(
            user_provider.clone(),
            password_hasher,
            repos.mfa.clone(),
        )),
        get_mfa_status: Arc::new(GetMfaStatusUseCase::new(repos.mfa.clone())),
        register_passkey: Arc::new(RegisterPasskeyUseCase::new(
            webauthn_service.clone(),
            repos.mfa.clone(),
            auth_config.mfa_challenge_ttl_secs,
        )),
        authenticate_passkey: Arc::new(AuthenticatePasskeyUseCase::new(
            webauthn_service.clone(),
            repos.mfa.clone(),
            user_provider.clone(),
            repos.session.clone(),
            auth_config.clone(),
        )),
        discoverable_passkey_login: Arc::new(DiscoverablePasskeyLoginUseCase::new(
            webauthn_service,
            repos.mfa.clone(),
            repos.pending_challenges.clone(),
            user_provider,
            repos.session.clone(),
            auth_config.clone(),
            auth_config.mfa_challenge_ttl_secs,
        )),
        delete_passkey: Arc::new(DeletePasskeyUseCase::new(repos.mfa.clone())),
    };

    AuthServices {
        use_cases,
        app_password_login,
    }
}
