use std::sync::Arc;

use ferrous_dns_application::ports::SessionRepository;
use ferrous_dns_domain::{AuthSession, UserRole};
use ferrous_dns_infrastructure::repositories::SqliteSessionRepository;

#[path = "support/db.rs"]
mod db;

fn session(id: &str, remember_me: bool, expires_in_secs: i64) -> AuthSession {
    let fmt = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%d %H:%M:%S").to_string();
    let now = chrono::Utc::now();
    AuthSession {
        id: Arc::from(id),
        username: Arc::from("admin"),
        role: UserRole::Admin,
        ip_address: Arc::from("::1"),
        user_agent: Arc::from("test"),
        remember_me,
        created_at: fmt(now),
        last_seen_at: fmt(now),
        expires_at: fmt(now + chrono::Duration::seconds(expires_in_secs)),
    }
}

#[tokio::test]
async fn remember_me_round_trips_and_expiry_splits_active_from_expired() {
    let pool = db::migrated_pool().await;
    let repo = SqliteSessionRepository::new(pool.clone(), pool);
    repo.create(&session("remembered", true, 3600))
        .await
        .unwrap();
    repo.create(&session("plain", false, 3600)).await.unwrap();
    repo.create(&session("stale", true, -60)).await.unwrap();

    assert!(
        repo.get_by_id("remembered")
            .await
            .unwrap()
            .unwrap()
            .remember_me
    );
    assert!(!repo.get_by_id("plain").await.unwrap().unwrap().remember_me);

    let mut active: Vec<_> = repo
        .get_all_active()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    active.sort();
    assert_eq!(active, [Arc::from("plain"), Arc::from("remembered")]);

    assert_eq!(repo.delete_expired().await.unwrap(), 1);
    assert!(repo.get_by_id("stale").await.unwrap().is_none());
}
