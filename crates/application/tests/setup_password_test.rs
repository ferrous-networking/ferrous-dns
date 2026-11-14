//! First-run setup sets the admin password once: two setups racing on a fresh
//! install must not both succeed, or the last one silently replaces the first.

use async_trait::async_trait;
use ferrous_dns_application::ports::{PasswordHasher, UserProvider};
use ferrous_dns_application::use_cases::SetupPasswordUseCase;
use ferrous_dns_domain::{DomainError, User, UserRole, UserSource};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The TOML admin, whose hash starts empty and holds whatever setup wrote.
#[derive(Default)]
struct AdminProvider {
    hash: Mutex<String>,
    writes: Mutex<Vec<String>>,
}

#[async_trait]
impl UserProvider for AdminProvider {
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        Ok((username == "admin").then(|| User {
            id: None,
            username: Arc::from("admin"),
            display_name: None,
            password_hash: Arc::from(self.hash.lock().unwrap().as_str()),
            role: UserRole::Admin,
            source: UserSource::Toml,
            enabled: true,
            created_at: None,
            updated_at: None,
        }))
    }
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        Ok(Vec::new())
    }
    async fn update_password(&self, _: &str, password_hash: &str) -> Result<(), DomainError> {
        *self.hash.lock().unwrap() = password_hash.to_string();
        self.writes.lock().unwrap().push(password_hash.to_string());
        Ok(())
    }
}

/// Hashes slowly, as Argon2 does, so concurrent setups overlap.
struct SlowHasher;

#[async_trait]
impl PasswordHasher for SlowHasher {
    async fn hash(&self, password: &str) -> Result<String, DomainError> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(format!("hash-of-{password}"))
    }
    async fn verify(&self, _: &str, _: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
    async fn hash_many(&self, _: &[String]) -> Result<Vec<String>, DomainError> {
        Ok(Vec::new())
    }
    async fn verify_any(&self, _: &str, _: Vec<Arc<str>>) -> Result<Option<usize>, DomainError> {
        Ok(None)
    }
}

#[tokio::test]
async fn test_concurrent_setups_set_the_password_once() {
    let provider = Arc::new(AdminProvider::default());
    let setup = SetupPasswordUseCase::new(provider.clone(), Arc::new(SlowHasher), "admin".into());

    let (first, second) = tokio::join!(
        setup.execute("first-password"),
        setup.execute("second-password")
    );

    let outcomes = [first, second];
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Err(DomainError::PasswordAlreadyConfigured))),
        "{outcomes:?}"
    );
    assert_eq!(provider.writes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_setup_after_a_password_is_set_is_refused() {
    let provider = Arc::new(AdminProvider::default());
    let setup = SetupPasswordUseCase::new(provider.clone(), Arc::new(SlowHasher), "admin".into());

    setup.execute("first-password").await.unwrap();
    let again = setup.execute("second-password").await;

    assert!(matches!(again, Err(DomainError::PasswordAlreadyConfigured)));
    assert_eq!(*provider.hash.lock().unwrap(), "hash-of-first-password");
}
