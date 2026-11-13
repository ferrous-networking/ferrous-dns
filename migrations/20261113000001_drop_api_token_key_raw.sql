-- Every token's key was kept in plaintext beside its hash, so a copy of the
-- database handed out working keys. Validation only ever reads key_hash.
-- The listed prefix was the key's first 8 characters, the whole of a short
-- custom key; it becomes at most a quarter of the key, as for new keys.
UPDATE api_tokens
SET key_prefix = substr(key_raw, 1, min(8, length(key_raw) / 4))
WHERE key_raw IS NOT NULL;
ALTER TABLE api_tokens DROP COLUMN key_raw;
