-- Registered WebAuthn / passkey credentials, keyed by username (covers TOML
-- admin and database users). `passkey` holds the serialized webauthn-rs
-- `Passkey` value (public key + metadata); `sign_count` mirrors its counter
-- for clone-detection convenience.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL,
    credential_id TEXT    NOT NULL UNIQUE,       -- base64url credential id
    label         TEXT,                          -- user-provided nickname
    passkey       TEXT    NOT NULL,              -- serialized webauthn-rs Passkey (JSON)
    sign_count    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    last_used_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_username ON webauthn_credentials(username);
