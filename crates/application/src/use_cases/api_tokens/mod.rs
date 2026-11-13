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

use super::auth::session_factory::sha256_hex;

/// Most leading bytes of a key shown to admins so they can tell keys apart.
const KEY_PREFIX_LEN: usize = 8;

/// Display prefix and SHA-256 hash stored for a raw API key. The prefix is at
/// most a quarter of the key, so a short custom key is never listed whole.
fn key_material(raw_token: &str) -> (&str, String) {
    let shown = KEY_PREFIX_LEN.min(raw_token.len() / 4);
    // Custom keys may be any UTF-8; cut at the last char boundary within the prefix length.
    let end = (0..=shown)
        .rev()
        .find(|&i| raw_token.is_char_boundary(i))
        .unwrap_or(0);
    (&raw_token[..end], sha256_hex(raw_token))
}
