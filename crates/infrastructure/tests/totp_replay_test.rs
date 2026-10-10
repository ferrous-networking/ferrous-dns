//! A TOTP code is single-use (RFC 6238 §5.2): once accepted, the same code must
//! not complete another login while it is still inside the clock-drift window.
//! Drives the real use cases over SQLite and `TotpRsService`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ferrous_dns_application::ports::{MfaRepository, TotpService};
use ferrous_dns_application::use_cases::{ConfirmTotpUseCase, VerifyMfaUseCase};
use ferrous_dns_domain::{AuthConfig, DomainError};
use ferrous_dns_infrastructure::auth::{Argon2PasswordHasher, SqliteMfaRepository, TotpRsService};
use ferrous_dns_infrastructure::repositories::SqliteSessionRepository;
use totp_rs::{Algorithm, Secret, TOTP};

#[path = "support/auth.rs"]
mod auth;
#[path = "support/db.rs"]
mod db;

use auth::{admin_user_provider, password_accepted, ADMIN};

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct Fixture {
    mfa: Arc<dyn MfaRepository>,
    verify: VerifyMfaUseCase,
    confirm: ConfirmTotpUseCase,
    code: String,
}

/// `ADMIN` with a fresh (unconfirmed) TOTP secret and that secret's current code.
async fn fixture() -> Fixture {
    let pool = db::migrated_pool().await;
    let mfa: Arc<dyn MfaRepository> = Arc::new(SqliteMfaRepository::new(pool.clone()));
    let totp: Arc<dyn TotpService> = Arc::new(TotpRsService::new("Ferrous DNS"));
    let hasher = Arc::new(Argon2PasswordHasher::new());
    let secret = totp.generate_secret();
    mfa.upsert_secret(ADMIN, &secret).await.unwrap();

    Fixture {
        verify: VerifyMfaUseCase::new(
            mfa.clone(),
            totp.clone(),
            hasher.clone(),
            admin_user_provider(pool.clone()),
            Arc::new(SqliteSessionRepository::new(pool.clone(), pool)),
            Arc::new(AuthConfig::default()),
        ),
        confirm: ConfirmTotpUseCase::new(mfa.clone(), totp, hasher),
        mfa,
        code: current_code(&secret),
    }
}

fn current_code(secret_base32: &str) -> String {
    let bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .unwrap();
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "account".into())
        .unwrap()
        .generate_current()
        .unwrap()
}

async fn login(f: &Fixture, token: &str) -> Result<(), DomainError> {
    password_accepted(f.mfa.as_ref(), token).await;
    f.verify
        .execute(token, &f.code, PEER, "127.0.0.1", "agent")
        .await
        .map(drop)
}

#[tokio::test]
async fn an_accepted_totp_code_cannot_complete_a_second_login() {
    let f = fixture().await;
    f.mfa.enable(ADMIN).await.unwrap();

    login(&f, "first").await.unwrap();

    assert!(matches!(
        login(&f, "second").await,
        Err(DomainError::InvalidMfaCode)
    ));
}

#[tokio::test]
async fn the_enrollment_code_cannot_also_complete_a_login() {
    let f = fixture().await;

    f.confirm.execute(ADMIN, &f.code).await.unwrap();

    assert!(matches!(
        login(&f, "after-enrollment").await,
        Err(DomainError::InvalidMfaCode)
    ));
}
