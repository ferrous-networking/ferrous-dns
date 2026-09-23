---
name: restart-banner-server-flag
description: Why the "restart required" banner is driven by a sticky in-memory server flag (PR #236), and the two alternatives rejected for it
type: project
scope: config/restart-banner
impact: functional
---

**Decision:** The web UI's "Configuration saved. Restart the server to apply changes."
banner is driven by `AppState.restart_pending` (`crates/api/src/state.rs`), an in-memory
`AtomicBool` exposed as `restart_required` on `GET /api/config`. It is set on a save that
needs a restart and stays set until the process restarts — saving a change and then
reverting it still shows the banner. Shipped for issue #234 in PR #236 (merged 2026-09-23).

**Why:** before #236 the state lived only in the browser (`localStorage.ferrous_config_saved_at`),
so the banner survived `docker restart` and was per-browser. Being in memory is the point:
a new process starts with the flag cleared, which is exactly when the banner must go.

**What changes for a teammate:** any new handler that saves a setting which only takes
effect after a restart must call `state.mark_restart_pending()` (today: `update_config`,
`update_settings` and the two TLS handlers). Do not "improve" the banner to clear itself
when a value is reverted — see Rejected. The stale `ferrous_config_saved_at` key left in
users' browsers is inert by design; nothing reads it.

**Rejected:**
- *Diffing the live config against the boot config* — local records, users and backup import
  also write `state.config` and are hot-applied (`application/src/use_cases/local_records/`,
  `infrastructure/src/auth/composite_user_provider.rs`), so a diff raises false banners.
- *A client-side boot id* — the banner would still be tracked per browser.

**Evidence:** issue #234, PR #236 (commit `6961b73`), plan `enchanted-tinkering-kahn.md`.
Known gap left out of scope: [[backup-import-no-restart-flag]].
