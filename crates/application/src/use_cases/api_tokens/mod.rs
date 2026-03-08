mod create_api_token;
mod delete_api_token;
mod get_api_tokens;
mod update_api_token;
mod validate_api_token;

pub use create_api_token::{CreateApiTokenUseCase, CreatedApiToken};
pub use delete_api_token::DeleteApiTokenUseCase;
pub use get_api_tokens::GetApiTokensUseCase;
pub use update_api_token::UpdateApiTokenUseCase;
pub use validate_api_token::ValidateApiTokenUseCase;

use ferrous_dns_domain::DomainError;
use std::fmt::Write;

/// Generates a cryptographically random 64-char hex token.
fn generate_token() -> Result<String, DomainError> {
    use ring::rand::SecureRandom;
    let mut buf = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| DomainError::IoError("CSPRNG fill failed".to_string()))?;
    let mut hex = String::with_capacity(64);
    for byte in &buf {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// Computes SHA-256 hash of a raw token, returning hex string.
fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result.as_slice() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
