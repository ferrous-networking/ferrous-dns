---
name: backup-import-no-restart-flag
description: POST /api/config/import rewrites restart-requiring settings but never sets AppState.restart_pending, so the UI shows no restart banner after an import
type: project
paths: crates/api/src/handlers/backup.rs, crates/application/src/use_cases/backup/import.rs
---

Since the fix for issue #234 (branch `fix/restart-banner-stuck`, 2026-09-23) the
"restart pending" banner is driven by an in-memory flag, `AppState.restart_pending`
(`crates/api/src/state.rs`), exposed as `restart_required` on `GET /api/config`. It is
set by `update_config`, `update_settings` and the two TLS handlers — **not** by the
backup import.

`ImportConfigUseCase` (`crates/application/src/use_cases/backup/import.rs`, the
`save_config_to_file` + `*self.config.write()` block) overwrites block mode, sinkholes,
DNS64, auth and other settings that only take effect after a restart, yet the
`/config/import` handler (`crates/api/src/handlers/backup.rs`) never marks a restart.
The gap predates #234: the old localStorage banner was never raised by an import either.

**Status:** deliberately left out of PR #236 (the #234 fix, merged 2026-09-23) to keep its
scope; still open and unfiled as of 2026-09-23. The fix is to call
`state.mark_restart_pending()` in the handler when the import reports that the config
section was applied. Design background: [[restart-banner-server-flag]].
