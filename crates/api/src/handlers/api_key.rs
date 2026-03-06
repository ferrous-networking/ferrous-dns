use axum::Json;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use tracing::instrument;

#[derive(Serialize)]
pub struct GeneratedApiKey {
    pub key: String,
}

/// Generates a cryptographically secure random 32-character hex API key (128 bits).
/// The key is not saved — the client must POST it via `/config` to persist it.
#[instrument(name = "api_generate_key")]
pub async fn generate_api_key() -> Json<GeneratedApiKey> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("OS CSPRNG unavailable");
    let key = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Json(GeneratedApiKey { key })
}
