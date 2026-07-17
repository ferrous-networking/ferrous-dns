-- Multi-factor authentication state, keyed by username so it covers BOTH the
-- TOML admin (which has no `users` row) and database users.

CREATE TABLE IF NOT EXISTS user_mfa (
    username     TEXT    PRIMARY KEY,
    totp_secret  TEXT    NOT NULL,               -- base32-encoded TOTP shared secret
    totp_enabled INTEGER NOT NULL DEFAULT 0,     -- 0 until the first code is confirmed
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    confirmed_at TEXT
);

-- Single-use recovery codes (Argon2id-hashed). Consumed one at a time at login.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL,
    code_hash  TEXT    NOT NULL,
    used_at    TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_username ON mfa_recovery_codes(username);

-- Short-lived second-factor challenges: password already verified, awaiting the
-- second factor. `state` holds the serialized WebAuthn ceremony (NULL for TOTP).
CREATE TABLE IF NOT EXISTS mfa_challenges (
    token       TEXT    PRIMARY KEY,             -- CSPRNG hex, sent to the client
    username    TEXT    NOT NULL,
    remember_me INTEGER NOT NULL DEFAULT 0,      -- carried through so the final session honors it
    kind        TEXT    NOT NULL,                -- 'totp' | 'webauthn'
    state       TEXT,                            -- JSON PasskeyAuthentication state (webauthn only)
    expires_at  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
