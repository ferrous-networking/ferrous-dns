CREATE TABLE IF NOT EXISTS auth_sessions (
    id           TEXT    PRIMARY KEY,
    username     TEXT    NOT NULL,
    role         TEXT    NOT NULL,
    ip_address   TEXT    NOT NULL,
    user_agent   TEXT    NOT NULL DEFAULT '',
    remember_me  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    last_seen_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    expires_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_username ON auth_sessions(username);
