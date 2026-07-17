use std::sync::Arc;

use ferrous_dns_application::ports::MfaRepository;
use ferrous_dns_domain::{MfaChallenge, MfaMethod, WebauthnCredential};
use ferrous_dns_infrastructure::auth::SqliteMfaRepository;
use sqlx::sqlite::SqlitePoolOptions;

async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite pool");

    for ddl in [
        "CREATE TABLE user_mfa (
            username TEXT PRIMARY KEY,
            totp_secret TEXT NOT NULL,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
            confirmed_at TEXT
        )",
        "CREATE TABLE mfa_recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
        )",
        "CREATE TABLE mfa_challenges (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            remember_me INTEGER NOT NULL DEFAULT 0,
            kind TEXT NOT NULL,
            state TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
        )",
        "CREATE TABLE webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            label TEXT,
            passkey TEXT NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
            last_used_at TEXT
        )",
    ] {
        sqlx::query(ddl).execute(&pool).await.expect("create table");
    }
    pool
}

fn repo(pool: sqlx::SqlitePool) -> SqliteMfaRepository {
    SqliteMfaRepository::new(Arc::new(pool))
}

fn future_ts(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

#[tokio::test]
async fn totp_secret_upsert_enable_roundtrip() {
    let repo = repo(create_test_db().await);

    assert!(repo.get("admin").await.unwrap().is_none());

    repo.upsert_secret("admin", "SECRET32").await.unwrap();
    let mfa = repo.get("admin").await.unwrap().unwrap();
    assert_eq!(mfa.totp_secret.as_ref(), "SECRET32");
    assert!(!mfa.totp_enabled);

    repo.enable("admin").await.unwrap();
    assert!(repo.get("admin").await.unwrap().unwrap().totp_enabled);

    // Re-enrolling resets the enabled flag.
    repo.upsert_secret("admin", "NEWSECRET").await.unwrap();
    let mfa = repo.get("admin").await.unwrap().unwrap();
    assert_eq!(mfa.totp_secret.as_ref(), "NEWSECRET");
    assert!(!mfa.totp_enabled);
}

#[tokio::test]
async fn recovery_codes_replace_and_consume() {
    let repo = repo(create_test_db().await);

    repo.replace_recovery_codes("admin", &["h1".into(), "h2".into(), "h3".into()])
        .await
        .unwrap();
    let codes = repo.list_unused_recovery_codes("admin").await.unwrap();
    assert_eq!(codes.len(), 3);

    repo.mark_recovery_code_used(codes[0].id).await.unwrap();
    assert_eq!(
        repo.list_unused_recovery_codes("admin")
            .await
            .unwrap()
            .len(),
        2
    );

    // Replace wipes the old set.
    repo.replace_recovery_codes("admin", &["x".into()])
        .await
        .unwrap();
    assert_eq!(
        repo.list_unused_recovery_codes("admin")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn challenge_lifecycle_and_expiry_cleanup() {
    let repo = repo(create_test_db().await);

    let ch = MfaChallenge {
        token: Arc::from("tok1"),
        username: Arc::from("admin"),
        remember_me: true,
        kind: MfaMethod::Totp,
        state: None,
        expires_at: future_ts(300),
    };
    repo.create_challenge(&ch).await.unwrap();

    let got = repo.get_challenge("tok1").await.unwrap().unwrap();
    assert_eq!(got.username.as_ref(), "admin");
    assert!(got.remember_me);
    assert_eq!(got.kind, MfaMethod::Totp);

    // An already-expired challenge is removed by the cleanup sweep.
    let expired = MfaChallenge {
        token: Arc::from("tok2"),
        username: Arc::from("admin"),
        remember_me: false,
        kind: MfaMethod::Webauthn,
        state: Some("{}".into()),
        expires_at: future_ts(-10),
    };
    repo.create_challenge(&expired).await.unwrap();
    let removed = repo.delete_expired_challenges().await.unwrap();
    assert_eq!(removed, 1);
    assert!(repo.get_challenge("tok2").await.unwrap().is_none());
    assert!(repo.get_challenge("tok1").await.unwrap().is_some());

    repo.delete_challenge("tok1").await.unwrap();
    assert!(repo.get_challenge("tok1").await.unwrap().is_none());
}

#[tokio::test]
async fn webauthn_credentials_crud() {
    let repo = repo(create_test_db().await);

    assert!(!repo.has_credentials("admin").await.unwrap());

    repo.add_credential(&WebauthnCredential {
        id: None,
        username: Arc::from("admin"),
        credential_id: Arc::from("cred-abc"),
        label: Some(Arc::from("YubiKey")),
        passkey: "{\"k\":1}".into(),
        sign_count: 0,
        created_at: None,
        last_used_at: None,
    })
    .await
    .unwrap();

    assert!(repo.has_credentials("admin").await.unwrap());
    let creds = repo.list_credentials("admin").await.unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].credential_id.as_ref(), "cred-abc");

    repo.update_credential_counter("cred-abc", 5).await.unwrap();
    assert_eq!(
        repo.list_credentials("admin").await.unwrap()[0].sign_count,
        5
    );

    let id = creds[0].id.unwrap();
    repo.delete_credential(id, "admin").await.unwrap();
    assert!(!repo.has_credentials("admin").await.unwrap());
}

#[tokio::test]
async fn find_credential_by_id_resolves_owner() {
    let repo = repo(create_test_db().await);

    // Unknown id → None.
    assert!(repo.find_credential_by_id("nope").await.unwrap().is_none());

    repo.add_credential(&WebauthnCredential {
        id: None,
        username: Arc::from("alice"),
        credential_id: Arc::from("cred-xyz"),
        label: Some(Arc::from("Phone")),
        passkey: "{\"pk\":true}".into(),
        sign_count: 3,
        created_at: None,
        last_used_at: None,
    })
    .await
    .unwrap();

    // Usernameless login resolves the owner + stored passkey from the credential id.
    let found = repo
        .find_credential_by_id("cred-xyz")
        .await
        .unwrap()
        .expect("credential found by id");
    assert_eq!(found.username.as_ref(), "alice");
    assert_eq!(found.passkey, "{\"pk\":true}");
    assert_eq!(found.sign_count, 3);
}

#[tokio::test]
async fn delete_all_wipes_every_factor() {
    let repo = repo(create_test_db().await);

    repo.upsert_secret("admin", "S").await.unwrap();
    repo.enable("admin").await.unwrap();
    repo.replace_recovery_codes("admin", &["h".into()])
        .await
        .unwrap();
    repo.add_credential(&WebauthnCredential {
        id: None,
        username: Arc::from("admin"),
        credential_id: Arc::from("c1"),
        label: None,
        passkey: "{}".into(),
        sign_count: 0,
        created_at: None,
        last_used_at: None,
    })
    .await
    .unwrap();

    repo.delete_all("admin").await.unwrap();

    assert!(repo.get("admin").await.unwrap().is_none());
    assert!(repo
        .list_unused_recovery_codes("admin")
        .await
        .unwrap()
        .is_empty());
    assert!(!repo.has_credentials("admin").await.unwrap());
}
