use std::sync::Arc;

use ferrous_dns_application::ports::{MfaRepository, SessionRepository, UserRepository};
use ferrous_dns_domain::{AuthSession, DomainError, UserRole, WebauthnCredential};
use ferrous_dns_infrastructure::auth::SqliteMfaRepository;
use ferrous_dns_infrastructure::repositories::{SqliteSessionRepository, SqliteUserRepository};

#[path = "support/db.rs"]
mod db;

fn session(id: &str, username: &str) -> AuthSession {
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    AuthSession {
        id: Arc::from(id),
        username: Arc::from(username),
        role: UserRole::Viewer,
        ip_address: Arc::from("127.0.0.1"),
        user_agent: Arc::from("test"),
        remember_me: false,
        created_at: expires_at.clone(),
        last_seen_at: expires_at.clone(),
        expires_at,
    }
}

#[tokio::test]
async fn create_duplicate_username_is_rejected() {
    let users = SqliteUserRepository::new(db::migrated_pool().await);
    users
        .create("bob", None, "hash", UserRole::Viewer)
        .await
        .unwrap();

    assert!(matches!(
        users.create("bob", None, "hash", UserRole::Viewer).await,
        Err(DomainError::DuplicateUsername(name)) if name == "bob"
    ));
}

#[tokio::test]
async fn update_password_of_missing_user_is_not_found() {
    let users = SqliteUserRepository::new(db::migrated_pool().await);

    assert!(matches!(
        users.update_password(42, "hash").await,
        Err(DomainError::UserNotFound(_))
    ));
}

#[tokio::test]
async fn delete_revokes_sessions_and_second_factors_of_that_user_only() {
    let pool = db::migrated_pool().await;
    let users = SqliteUserRepository::new(pool.clone());
    let sessions = SqliteSessionRepository::new(pool.clone(), pool.clone());
    let mfa = SqliteMfaRepository::new(pool);

    let bob = users
        .create("bob", None, "hash", UserRole::Viewer)
        .await
        .unwrap();
    users
        .create("carol", None, "hash", UserRole::Viewer)
        .await
        .unwrap();
    for name in ["bob", "carol"] {
        sessions
            .create(&session(&format!("{name}-session"), name))
            .await
            .unwrap();
        mfa.upsert_secret(name, "SECRET").await.unwrap();
        mfa.replace_recovery_codes(name, &["h".into()])
            .await
            .unwrap();
        mfa.add_credential(&WebauthnCredential {
            id: None,
            username: Arc::from(name),
            credential_id: Arc::from(format!("{name}-cred").as_str()),
            label: None,
            passkey: "{}".into(),
            sign_count: 0,
            created_at: None,
            last_used_at: None,
        })
        .await
        .unwrap();
    }

    users.delete(bob.id.unwrap()).await.unwrap();

    assert!(sessions.get_by_id("bob-session").await.unwrap().is_none());
    assert!(mfa.get("bob").await.unwrap().is_none());
    assert!(mfa
        .list_unused_recovery_codes("bob")
        .await
        .unwrap()
        .is_empty());
    assert!(!mfa.has_credentials("bob").await.unwrap());

    assert!(sessions.get_by_id("carol-session").await.unwrap().is_some());
    assert!(mfa.get("carol").await.unwrap().is_some());
    assert!(mfa.has_credentials("carol").await.unwrap());
}

#[tokio::test]
async fn delete_missing_user_is_not_found() {
    let users = SqliteUserRepository::new(db::migrated_pool().await);

    assert!(matches!(
        users.delete(42).await,
        Err(DomainError::UserNotFound(_))
    ));
}
