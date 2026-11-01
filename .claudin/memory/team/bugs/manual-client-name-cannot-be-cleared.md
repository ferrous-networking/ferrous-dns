---
name: manual-client-name-cannot-be-cleared
description: Since #343 (2026-10-27) a client name set by hand is kept forever — the UI cannot clear it (blank sends null = no change), and names set before the migration are still overwritten by PTR until saved again
type: project
paths:
  - web/static/clients.js
  - crates/application/src/use_cases/clients/update_client.rs
  - crates/infrastructure/src/repositories/client_row_mapper.rs
---

**Symptom 1, no way to clear a manual name:** blanking the name on the Clients page sends `hostname: null` (`clients.js:102`, `trim() || null`). `UpdateClientUseCase::execute` writes only a `Some` name that differs from the current one, so nothing changes. Before #343 the PTR sync wrote over the name within an hour, which looked like clearing it. Now the name is `hostname_source = 'manual'`, and the sync never selects or overwrites it.

**Symptom 2, old manual names are not protected:** migration `20261026000001` added `clients.hostname_source` with NULL for every existing row. NULL means automatic, so a name typed before #343 is still replaced by PTR (and by mDNS, since #346) until it is saved again.

**Where:** precedence is Manual > mDNS > PTR. It is set by the `update_hostname` SQL guard and the `get_needs_hostname_update` selection in `client_row_mapper.rs`. An mDNS name not announced for a day may be replaced by PTR. The user-facing rules are in `docs/features/client-management.md`.

**Repro (symptom 1):** rename a client, then clear the field and save. The name stays. `SELECT hostname, hostname_source FROM clients` shows `manual`.

**Status:** open as of 2026-10-28. Both were disclosed as tradeoffs in the body of PR #343 (`7b0e7993`). The "clear a manual name" control was offered as a follow-up; no issue is recorded.

**Why not fixed:** out of scope for #343, which only stopped the PTR sync from replacing names set by hand. A fix needs an explicit "clear" in the API: `null` already means "leave the name alone" on `PATCH /clients/{id}`.
