---
name: backup-import-no-restart-flag
description: POST /api/config/import never set AppState.restart_pending, so no restart banner after an import; fixed on branch fix/backup-pools-and-detectors (2026-10-23)
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

**Status:** fixed on branch `fix/backup-pools-and-detectors` (2026-10-23). `ImportSummary.restart_required`
is true when the restored config differs from the running one, compared as serde JSON like
`config_differs`, pools included, because an import hot-applies nothing. The handler marks the
restart, the response carries `restart_required`, and `settings.js` reads it even when `success`
is false (a partial import). For an unchanged re-import not to flag a restart, the import keeps the
running `dnssec_mode`/`dnssec_enabled` when the backup's mode equals the effective one: a backup
always names the mode, a config file often doesn't. Design background: [[restart-banner-server-flag]].
