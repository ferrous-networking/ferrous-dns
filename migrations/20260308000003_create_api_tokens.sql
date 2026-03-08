CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    key_prefix   TEXT    NOT NULL,
    key_hash     TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_name ON api_tokens(name);
