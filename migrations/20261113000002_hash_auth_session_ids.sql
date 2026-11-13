-- Sessions are now stored under the SHA-256 of their token, so a copy of the
-- database holds no cookie that signs anyone in. SQLite cannot hash, so the
-- rows written before this migration are marked here and rewritten once in
-- Rust when the database opens (hash_legacy_session_ids).
ALTER TABLE auth_sessions ADD COLUMN id_hashed INTEGER NOT NULL DEFAULT 1;
UPDATE auth_sessions SET id_hashed = 0;
