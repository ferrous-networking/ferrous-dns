//! A passkey login folds the authenticator's signature counter into the stored
//! passkey, so the next WebAuthn ceremony itself refuses a cloned authenticator
//! replaying an old counter (WebAuthn §7.2). A software ES256 authenticator
//! drives the real use cases, `WebauthnRsService` and SQLite.

use std::sync::Arc;

use data_encoding::BASE64URL_NOPAD;
use ferrous_dns_application::ports::{MfaRepository, WebauthnService};
use ferrous_dns_application::use_cases::{AuthenticatePasskeyUseCase, RegisterPasskeyUseCase};
use ferrous_dns_domain::{AuthConfig, DomainError};
use ferrous_dns_infrastructure::auth::{SqliteMfaRepository, WebauthnRsService};
use ferrous_dns_infrastructure::repositories::SqliteSessionRepository;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "support/auth.rs"]
mod auth;
#[path = "support/db.rs"]
mod db;

use auth::{admin_user_provider, password_accepted, ADMIN};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";
const CREDENTIAL_ID: [u8; 16] = [7; 16];

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;

/// One resident ES256 key answering creation and assertion requests with `none` attestation.
struct SoftAuthenticator {
    key: EcdsaKeyPair,
    rng: SystemRandom,
}

impl SoftAuthenticator {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self { key, rng }
    }

    fn register(&self, creation: &Value) -> Value {
        let client_data = client_data("webauthn.create", creation);
        // Uncompressed SEC1 point: 0x04 || x || y.
        let point = self.key.public_key().as_ref();

        let mut auth_data = authenticator_data(
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL,
            0,
        );
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&(CREDENTIAL_ID.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&CREDENTIAL_ID);
        // COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
        auth_data.extend_from_slice(&[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        auth_data.extend_from_slice(&point[1..33]);
        auth_data.extend_from_slice(&[0x22, 0x58, 0x20]);
        auth_data.extend_from_slice(&point[33..65]);

        // {"fmt": "none", "attStmt": {}, "authData": auth_data}.
        let mut attestation = vec![0xA3, 0x63];
        attestation.extend_from_slice(b"fmt");
        attestation.push(0x64);
        attestation.extend_from_slice(b"none");
        attestation.push(0x67);
        attestation.extend_from_slice(b"attStmt");
        attestation.push(0xA0);
        attestation.push(0x68);
        attestation.extend_from_slice(b"authData");
        attestation.extend_from_slice(&[0x58, u8::try_from(auth_data.len()).unwrap()]);
        attestation.extend_from_slice(&auth_data);

        json!({
            "id": b64(&CREDENTIAL_ID),
            "rawId": b64(&CREDENTIAL_ID),
            "type": "public-key",
            "response": {
                "attestationObject": b64(&attestation),
                "clientDataJSON": b64(&client_data),
            },
        })
    }

    fn assert(&self, request: &Value, counter: u32) -> Value {
        let client_data = client_data("webauthn.get", request);
        let auth_data = authenticator_data(FLAG_USER_PRESENT | FLAG_USER_VERIFIED, counter);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature = self.key.sign(&self.rng, &signed).unwrap();

        json!({
            "id": b64(&CREDENTIAL_ID),
            "rawId": b64(&CREDENTIAL_ID),
            "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth_data),
                "clientDataJSON": b64(&client_data),
                "signature": b64(signature.as_ref()),
                "userHandle": null,
            },
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

fn client_data(kind: &str, options: &Value) -> Vec<u8> {
    json!({
        "type": kind,
        "challenge": options["publicKey"]["challenge"],
        "origin": ORIGIN,
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes()
}

fn authenticator_data(flags: u8, counter: u32) -> Vec<u8> {
    let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    data
}

#[tokio::test]
async fn a_passkey_login_moves_the_stored_passkey_to_the_new_counter() {
    let pool = db::migrated_pool().await;
    let mfa: Arc<dyn MfaRepository> = Arc::new(SqliteMfaRepository::new(pool.clone()));
    let webauthn: Arc<dyn WebauthnService> = Arc::new(WebauthnRsService::new(RP_ID, ORIGIN));
    let authenticator = SoftAuthenticator::new();

    let registration = RegisterPasskeyUseCase::new(webauthn.clone(), mfa.clone(), 300);
    let start = registration.start(ADMIN, ADMIN).await.unwrap();
    registration
        .finish(
            ADMIN,
            &start.ceremony_token,
            authenticator.register(&start.challenge),
            None,
        )
        .await
        .unwrap();

    let login = AuthenticatePasskeyUseCase::new(
        webauthn.clone(),
        mfa.clone(),
        admin_user_provider(pool.clone()),
        Arc::new(SqliteSessionRepository::new(pool.clone(), pool)),
        Arc::new(AuthConfig::default()),
    );
    password_accepted(mfa.as_ref(), "login").await;
    let request = login.start("login").await.unwrap();
    login
        .finish(
            "login",
            authenticator.assert(&request, 5),
            "127.0.0.1",
            "agent",
        )
        .await
        .unwrap();

    let stored = mfa
        .find_credential_by_id(&b64(&CREDENTIAL_ID))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.sign_count, 5);

    // A clone replaying counter 5 fails inside the ceremony, before any repository check.
    let passkeys = [stored.passkey];
    let (request, state) = webauthn.start_authentication(&passkeys).unwrap();
    assert!(matches!(
        webauthn.finish_authentication(authenticator.assert(&request, 5), &state, &passkeys),
        Err(DomainError::WebauthnError(_))
    ));
}
