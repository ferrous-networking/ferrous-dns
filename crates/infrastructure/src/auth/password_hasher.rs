use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString,
    },
    Argon2, Params,
};
use ferrous_dns_application::ports::PasswordHasher;
use ferrous_dns_domain::DomainError;

/// Argon2id password hasher using OWASP-recommended parameters.
///
/// Parameters: m=19456 (19 MiB), t=2 iterations, p=1 parallelism.
/// Hashing is CPU-intensive — callers must use `spawn_blocking`.
pub struct Argon2PasswordHasher;

impl Default for Argon2PasswordHasher {
    fn default() -> Self {
        Self
    }
}

impl Argon2PasswordHasher {
    pub fn new() -> Self {
        Self
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash(&self, password: &str) -> Result<String, DomainError> {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(19456, 2, 1, None)
            .map_err(|e| DomainError::ConfigError(format!("Argon2 params: {e}")))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| DomainError::ConfigError(format!("Password hash failed: {e}")))?;

        Ok(hash.to_string())
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| DomainError::ConfigError(format!("Invalid hash format: {e}")))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}
