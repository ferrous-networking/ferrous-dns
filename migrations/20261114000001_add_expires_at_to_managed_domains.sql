-- When a temporary rule stops applying, in the `YYYY-MM-DD HH:MM:SS` UTC form
-- every timestamp column uses. NULL for a rule that never expires.
ALTER TABLE managed_domains ADD COLUMN expires_at TEXT;
