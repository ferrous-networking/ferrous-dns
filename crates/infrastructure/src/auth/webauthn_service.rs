use tracing::warn;
use webauthn_rs::prelude::*;

use ferrous_dns_application::ports::{
    AuthenticatedCredential, RegisteredCredential, WebauthnService,
};
use ferrous_dns_domain::DomainError;

/// WebAuthn service backed by `webauthn-rs`.
///
/// Constructed from `[auth.webauthn]`; when `rp_id`/`rp_origin` are empty (or
/// invalid) the inner `Webauthn` is `None` and every ceremony returns
/// `WebauthnNotConfigured`, so passkeys are simply unavailable rather than
/// broken.
pub struct WebauthnRsService {
    webauthn: Option<Webauthn>,
}

impl WebauthnRsService {
    pub fn new(rp_id: &str, rp_origin: &str) -> Self {
        let webauthn = build(rp_id, rp_origin);
        if webauthn.is_none() && !(rp_id.is_empty() && rp_origin.is_empty()) {
            warn!(
                rp_id,
                rp_origin, "Invalid WebAuthn configuration; passkeys disabled"
            );
        }
        Self { webauthn }
    }

    fn wa(&self) -> Result<&Webauthn, DomainError> {
        self.webauthn
            .as_ref()
            .ok_or(DomainError::WebauthnNotConfigured)
    }
}

fn build(rp_id: &str, rp_origin: &str) -> Option<Webauthn> {
    if rp_id.is_empty() || rp_origin.is_empty() {
        return None;
    }
    let origin = Url::parse(rp_origin).ok()?;
    WebauthnBuilder::new(rp_id, &origin).ok()?.build().ok()
}

/// Derives a stable per-user handle from the username (no extra storage).
fn user_uuid(username: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, username.as_bytes())
}

fn wa_err(context: &str, e: WebauthnError) -> DomainError {
    warn!("webauthn {context}: {e}");
    DomainError::WebauthnError(e.to_string())
}

fn json_err(context: &str, e: serde_json::Error) -> DomainError {
    DomainError::WebauthnError(format!("{context}: {e}"))
}

fn credential_id_b64(cred_id: &CredentialID) -> String {
    data_encoding::BASE64URL_NOPAD.encode(cred_id.as_ref())
}

impl WebauthnService for WebauthnRsService {
    fn is_configured(&self) -> bool {
        self.webauthn.is_some()
    }

    fn start_registration(
        &self,
        username: &str,
        display_name: &str,
        existing_passkeys: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        let wa = self.wa()?;

        let exclude: Vec<CredentialID> = existing_passkeys
            .iter()
            .filter_map(|json| serde_json::from_str::<Passkey>(json).ok())
            .map(|pk| pk.cred_id().clone())
            .collect();
        let exclude = if exclude.is_empty() {
            None
        } else {
            Some(exclude)
        };

        let (ccr, state) = wa
            .start_passkey_registration(user_uuid(username), username, display_name, exclude)
            .map_err(|e| wa_err("start_registration", e))?;

        let challenge =
            serde_json::to_value(&ccr).map_err(|e| json_err("serialize challenge", e))?;
        let state_json =
            serde_json::to_string(&state).map_err(|e| json_err("serialize reg state", e))?;
        Ok((challenge, state_json))
    }

    fn finish_registration(
        &self,
        response: serde_json::Value,
        state_json: &str,
    ) -> Result<RegisteredCredential, DomainError> {
        let wa = self.wa()?;

        let reg: RegisterPublicKeyCredential =
            serde_json::from_value(response).map_err(|e| json_err("parse reg response", e))?;
        let state: PasskeyRegistration =
            serde_json::from_str(state_json).map_err(|e| json_err("parse reg state", e))?;

        let passkey = wa
            .finish_passkey_registration(&reg, &state)
            .map_err(|e| wa_err("finish_registration", e))?;

        let credential_id = credential_id_b64(passkey.cred_id());
        let passkey_json =
            serde_json::to_string(&passkey).map_err(|e| json_err("serialize passkey", e))?;

        Ok(RegisteredCredential {
            credential_id,
            passkey_json,
            sign_count: 0,
        })
    }

    fn start_authentication(
        &self,
        passkeys_json: &[String],
    ) -> Result<(serde_json::Value, String), DomainError> {
        let wa = self.wa()?;

        let passkeys: Vec<Passkey> = passkeys_json
            .iter()
            .map(|j| serde_json::from_str::<Passkey>(j))
            .collect::<Result<_, _>>()
            .map_err(|e| json_err("parse stored passkey", e))?;

        let (rcr, state) = wa
            .start_passkey_authentication(&passkeys)
            .map_err(|e| wa_err("start_authentication", e))?;

        let challenge =
            serde_json::to_value(&rcr).map_err(|e| json_err("serialize auth challenge", e))?;
        let state_json =
            serde_json::to_string(&state).map_err(|e| json_err("serialize auth state", e))?;
        Ok((challenge, state_json))
    }

    fn finish_authentication(
        &self,
        response: serde_json::Value,
        state_json: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        let wa = self.wa()?;

        let cred: PublicKeyCredential =
            serde_json::from_value(response).map_err(|e| json_err("parse auth response", e))?;
        let state: PasskeyAuthentication =
            serde_json::from_str(state_json).map_err(|e| json_err("parse auth state", e))?;

        let result = wa
            .finish_passkey_authentication(&cred, &state)
            .map_err(|e| wa_err("finish_authentication", e))?;

        Ok(AuthenticatedCredential {
            credential_id: credential_id_b64(result.cred_id()),
            sign_count: i64::from(result.counter()),
        })
    }

    fn start_discoverable(&self) -> Result<(serde_json::Value, String), DomainError> {
        let wa = self.wa()?;

        let (rcr, state) = wa
            .start_discoverable_authentication()
            .map_err(|e| wa_err("start_discoverable", e))?;

        let challenge =
            serde_json::to_value(&rcr).map_err(|e| json_err("serialize disc challenge", e))?;
        let state_json =
            serde_json::to_string(&state).map_err(|e| json_err("serialize disc state", e))?;
        Ok((challenge, state_json))
    }

    fn identify_discoverable(&self, response: serde_json::Value) -> Result<String, DomainError> {
        let wa = self.wa()?;

        let cred: PublicKeyCredential =
            serde_json::from_value(response).map_err(|e| json_err("parse disc response", e))?;
        let (_user_uuid, cred_id) = wa
            .identify_discoverable_authentication(&cred)
            .map_err(|e| wa_err("identify_discoverable", e))?;
        Ok(data_encoding::BASE64URL_NOPAD.encode(cred_id))
    }

    fn finish_discoverable(
        &self,
        response: serde_json::Value,
        state_json: &str,
        passkey_json: &str,
    ) -> Result<AuthenticatedCredential, DomainError> {
        let wa = self.wa()?;

        let cred: PublicKeyCredential =
            serde_json::from_value(response).map_err(|e| json_err("parse disc response", e))?;
        let state: DiscoverableAuthentication =
            serde_json::from_str(state_json).map_err(|e| json_err("parse disc state", e))?;
        let passkey: Passkey =
            serde_json::from_str(passkey_json).map_err(|e| json_err("parse stored passkey", e))?;

        let result = wa
            .finish_discoverable_authentication(&cred, state, &[DiscoverableKey::from(&passkey)])
            .map_err(|e| wa_err("finish_discoverable", e))?;

        Ok(AuthenticatedCredential {
            credential_id: credential_id_b64(result.cred_id()),
            sign_count: i64::from(result.counter()),
        })
    }
}
