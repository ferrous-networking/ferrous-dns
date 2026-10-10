//! A password change signs out every other session of that user, keeps the
//! session that made the change, and leaves other users alone. Drives the real
//! use cases over SQLite.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ferrous_dns_application::ports::{
    MfaRepository, PasswordHasher, SessionRepository, UserProvider, UserRepository,
};
use ferrous_dns_application::use_cases::{
    ChangePasswordUseCase, LoginOutcome, LoginUseCase, ValidateSessionUseCase,
};
use ferrous_dns_domain::{AuthConfig, AuthSession, Config, DomainError, UserRole};
use ferrous_dns_infrastructure::auth::{
    Argon2PasswordHasher, CompositeUserProvider, SqliteMfaRepository, TomlAdminProvider,
};
use ferrous_dns_infrastructure::repositories::{
    SqliteSessionRepository, SqliteUserRepository, TomlConfigFilePersistence,
};
use tokio::sync::RwLock;

#[path = "support/db.rs"]
mod db;

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OLD_PASSWORD: &str = "old-password-1";

struct Fixture {
    login: LoginUseCase,
    change_password: ChangePasswordUseCase,
    validate: ValidateSessionUseCase,
}

async fn fixture() -> Fixture {
    let pool = db::migrated_pool().await;
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2PasswordHasher::new());
    let users = SqliteUserRepository::new(pool.clone());
    let hash = hasher.hash(OLD_PASSWORD).await.unwrap();
    for name in ["alice", "bob"] {
        users
            .create(name, None, &hash, UserRole::Viewer)
            .await
            .unwrap();
    }
    let config = Config::default();
    let provider: Arc<dyn UserProvider> = Arc::new(CompositeUserProvider::new(
        TomlAdminProvider::new(config.auth.admin.clone()),
        Arc::new(SqliteUserRepository::new(pool.clone())),
        Arc::new(RwLock::new(config)),
        None,
        Arc::new(TomlConfigFilePersistence),
    ));
    let sessions: Arc<dyn SessionRepository> =
        Arc::new(SqliteSessionRepository::new(pool.clone(), pool.clone()));
    let mfa: Arc<dyn MfaRepository> = Arc::new(SqliteMfaRepository::new(pool));

    Fixture {
        login: LoginUseCase::new(
            provider.clone(),
            sessions.clone(),
            hasher.clone(),
            mfa,
            Arc::new(AuthConfig::default()),
        ),
        change_password: ChangePasswordUseCase::new(provider, hasher, sessions.clone()),
        validate: ValidateSessionUseCase::new(sessions),
    }
}

async fn login(f: &Fixture, username: &str) -> AuthSession {
    match f
        .login
        .execute(username, OLD_PASSWORD, false, PEER, "127.0.0.1", "agent")
        .await
        .unwrap()
    {
        LoginOutcome::Authenticated(session) => session,
        LoginOutcome::MfaRequired { .. } => panic!("no second factor is enrolled"),
    }
}

#[tokio::test]
async fn a_password_change_signs_out_the_users_other_sessions_only() {
    let f = fixture().await;
    let current = login(&f, "alice").await;
    let other_device = login(&f, "alice").await;
    let someone_else = login(&f, "bob").await;

    f.change_password
        .execute("alice", &current.id, OLD_PASSWORD, "new-password-2")
        .await
        .unwrap();

    assert!(f.validate.execute(&current.id).await.is_ok());
    assert!(matches!(
        f.validate.execute(&other_device.id).await,
        Err(DomainError::SessionNotFound)
    ));
    assert!(f.validate.execute(&someone_else.id).await.is_ok());
}

#[tokio::test]
async fn a_rejected_password_change_keeps_every_session() {
    let f = fixture().await;
    let current = login(&f, "alice").await;
    let other_device = login(&f, "alice").await;

    let result = f
        .change_password
        .execute("alice", &current.id, "wrong-password", "new-password-2")
        .await;

    assert!(matches!(result, Err(DomainError::InvalidCredentials)));
    assert!(f.validate.execute(&other_device.id).await.is_ok());
}
