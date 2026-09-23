---
name: issue-216-blocklist-sync
description: Issue #216 "Blocklists not syncing" — three confirmed defects, all fixed on branch fix/blocklist-source-reload-on-change (2026-09-06), plus the index-rebuild constraint that shaped the per-row refresh
type: project
---

GitHub issue #216 (opened 2026-09-05 by Nlwilkins93) was **three independent defects**, each sufficient on its own to produce "blocklists not syncing". All three are fixed on `fix/blocklist-source-reload-on-change`.

1. **Blocklist source mutation never reloaded the engine.** The create/update/delete use cases wrote to the DB and returned without calling `block_filter_engine.reload()`, unlike the ten sites across `managed_domains`, `regex_filters`, `blocked_services` and `safe_search`. A new source only took effect on restart or on the next `BlocklistSyncJob` tick — hardcoded to 86400s with no config key. Fixed via an optional `with_block_filter(...)` builder on all three.
2. **The documented "Sync" button did not exist.** Now `POST /blocklist-sources/{id}/sync` with a refresh action in each row's Actions cell.
3. **The HaGeZi URLs in the docs were 404s.** `main/domains/{pro,tif}.txt` do not exist; the real paths are `main/wildcard/…` (pro ≈ 225k entries, tif ≈ 2.1M). A failed fetch is only `warn!`-logged and swallowed per-source, so the reload still reported success — indistinguishable from defect 1. That silence is now visible through the `last_synced_at` column.

**Why:** the reporter hit all three at once, which is why it looked like a total sync failure rather than a bad URL.

**How to apply:** two constraints worth knowing before touching this area again.

- **There is no per-source refresh, and there cannot be one cheaply.** `compile_block_index` loads every enabled source, fetches them all in parallel and swaps one immutable snapshot; each source owns a bit 0–62 of a global bitset. `POST /blocklist-sources/{id}/sync` takes an id only to record which list the operator asked for — it rebuilds everything. Don't let UI copy imply otherwise.
- **`Block index compiled exact=N` is not a "did my list load" signal.** Wildcard entries were not counted at all, so a 224k-entry HaGeZi list logged `exact=0` and the dashboard card read 0 domains. `total_blocked_domains` is now `exact.len() + wildcard.len()`; an adblock-syntax entry counts twice because it is stored as both an apex and a subdomain rule. The trustworthy per-source signal is still `Fetched blocklist source url=…`.

See [[runtime-verification-recipe]] for the harness.
