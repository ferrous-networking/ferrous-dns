use std::sync::Arc;

use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString,
    },
    Argon2, Params,
};
use async_trait::async_trait;
use ferrous_dns_application::ports::PasswordHasher;
use ferrous_dns_domain::DomainError;
use tokio::sync::Semaphore;

// Process-wide: each active Argon2 operation uses 19 MiB, even across instances.
static HASHING_CAPACITY: Semaphore = Semaphore::const_new(2);

/// Argon2id password hasher using OWASP-recommended parameters.
///
/// Parameters: m=19456 (19 MiB), t=2 iterations, p=1 parallelism.
/// Every operation is admitted before submission to the blocking pool.
#[derive(Default)]
pub struct Argon2PasswordHasher;
impl Argon2PasswordHasher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash(&self, password: &str) -> Result<String, DomainError> {
        let password = password.to_owned();
        run_crypto(move || hash_password(&password)).await
    }

    async fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
        let password = password.to_owned();
        let hash = hash.to_owned();
        run_crypto(move || verify_password(&password, &hash)).await
    }

    async fn hash_many(&self, passwords: &[String]) -> Result<Vec<String>, DomainError> {
        let passwords = passwords.to_vec();
        run_crypto(move || passwords.iter().map(|p| hash_password(p)).collect()).await
    }

    async fn verify_any(
        &self,
        password: &str,
        hashes: Vec<Arc<str>>,
    ) -> Result<Option<usize>, DomainError> {
        let password = password.to_owned();
        run_crypto(move || {
            for (index, hash) in hashes.iter().enumerate() {
                if verify_password(&password, hash)? {
                    return Ok(Some(index));
                }
            }
            Ok(None)
        })
        .await
    }
}

async fn run_crypto<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, DomainError> + Send + 'static,
) -> Result<T, DomainError> {
    let permit = HASHING_CAPACITY
        .acquire()
        .await
        .map_err(|e| DomainError::ConfigError(format!("Password hashing unavailable: {e}")))?;
    tokio::task::spawn_blocking(move || {
        // The submitted job, not its cancellable waiter, owns admission until exit.
        let _permit = permit;
        work()
    })
    .await
    .map_err(|e| DomainError::ConfigError(format!("Password hashing task failed: {e}")))?
}

fn hash_password(password: &str) -> Result<String, DomainError> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, None)
        .map_err(|e| DomainError::ConfigError(format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| DomainError::ConfigError(format!("Password hash failed: {e}")))?;

    Ok(hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, DomainError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| DomainError::ConfigError(format!("Invalid hash format: {e}")))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};
    use tokio::{sync::oneshot, time::timeout};

    #[tokio::test]
    async fn recovery_batches_preserve_hash_strength_order_and_match_errors() {
        let hasher = Argon2PasswordHasher::new();
        let hashes = hasher
            .hash_many(&["first-code".to_owned(), "second-code".to_owned()])
            .await
            .unwrap();
        let parsed = PasswordHash::new(&hashes[0]).unwrap();
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert_eq!(parsed.version, Some(19));
        assert_eq!(parsed.params.get_decimal("m"), Some(19456));
        assert_eq!(parsed.params.get_decimal("t"), Some(2));
        assert_eq!(parsed.params.get_decimal("p"), Some(1));
        assert!(hasher.verify("first-code", &hashes[0]).await.unwrap());
        assert!(!hasher.verify("wrong-code", &hashes[0]).await.unwrap());

        let hashes: Vec<Arc<str>> = hashes.into_iter().map(Arc::from).collect();
        assert_eq!(
            hasher
                .verify_any("second-code", hashes.clone())
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            hasher
                .verify_any("wrong-code", hashes.clone())
                .await
                .unwrap(),
            None
        );
        let malformed: Arc<str> = Arc::from("not a PHC hash");
        assert_eq!(
            hasher
                .verify_any("first-code", vec![hashes[0].clone(), malformed.clone()])
                .await
                .unwrap(),
            Some(0)
        );
        assert!(matches!(
            hasher.verify_any("first-code", vec![malformed]).await,
            Err(DomainError::ConfigError(_))
        ));
    }

    #[tokio::test]
    async fn cancelled_waiters_keep_running_work_admitted_across_instances() {
        let mut releases = Vec::new();
        let mut jobs = Vec::new();
        for _ in 0..2 {
            let (started, ready) = oneshot::channel();
            let (release, held) = mpsc::channel::<()>();
            releases.push(release);
            jobs.push(tokio::spawn(run_crypto(move || {
                started.send(()).unwrap();
                let _ = held.recv();
                Ok(())
            })));
            timeout(Duration::from_secs(5), ready)
                .await
                .unwrap()
                .unwrap();
        }

        for job in jobs {
            job.abort();
            assert!(job.await.unwrap_err().is_cancelled());
        }

        // Invalid PHC parsing is immediate if incorrectly admitted. These calls
        // must wait even though their instances differ and both waiters are gone.
        let first = Argon2PasswordHasher::new();
        let second = Argon2PasswordHasher::new();
        let probes = async {
            tokio::join!(
                first.verify("password", "invalid"),
                second.verify("password", "invalid")
            )
        };
        tokio::pin!(probes);
        assert!(timeout(Duration::from_millis(50), &mut probes)
            .await
            .is_err());

        drop(releases);
        let (first, second) = timeout(Duration::from_secs(5), probes).await.unwrap();
        assert!(matches!(first, Err(DomainError::ConfigError(_))));
        assert!(matches!(second, Err(DomainError::ConfigError(_))));
    }
}
