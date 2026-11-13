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

/// Clones every log line, spans included, into a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A revoke can hand the repository a raw session token, so no session
/// method may record its id in a span.
#[tokio::test]
async fn test_deleting_a_session_keeps_its_id_out_of_the_logs() {
    let captured = Captured::default();
    let sink = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let pool = db::migrated_pool().await;
    let repo = SqliteSessionRepository::new(pool.clone(), pool);
    repo.delete("raw-session-token-0123456789").await.unwrap();

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("delete"), "the span was not logged: {logs}");
    assert!(
        !logs.contains("raw-session-token-0123456789"),
        "the token reached the logs: {logs}"
    );
}
