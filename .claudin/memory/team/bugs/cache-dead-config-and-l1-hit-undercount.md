---
name: cache-dead-config-and-l1-hit-undercount
description: Cache knobs that do nothing (cache_adaptive_thresholds, cache_lfuk_history_size) still open; L1 hit undercount + toml wording fixed in #286; the stale "L1 hits are not counted" wording reworded on docs/stale-ksk-and-l1-wording (10-26)
type: project
paths:
  - crates/infrastructure/src/dns/cache/storage.rs
  - crates/infrastructure/src/dns/cache/refresh.rs
  - ferrous-dns.toml
  - web/static/cache-control.html
  - crates/application/src/ports/dns_cache_port.rs
  - crates/api/src/dto/cache.rs
---

Found during a cache-refresh audit on 2026-10-12 (v0.9.22, `4d57874`). All three were confirmed in the code; none was filed.

**Symptom 1: dead config.** `cache_adaptive_thresholds` and `cache_lfuk_history_size` never change behaviour.
- **Where:** nothing outside `domain/src/config/dns.rs`, `config_persistence.rs`, the config API DTO and handlers, and backup export/import reads them. `cli/src/wiring/dns/cache.rs` passes neither to `DnsCache`.
- **Repro:** grep `crates/` for either key.

**Symptom 2: the toml comments overstate two knobs.**
- **Where:** `ferrous-dns.toml:126-127` says `cache_min_hit_rate` is the minimum "to keep an entry alive via refresh", and that `cache_min_frequency` must be reached "before an entry is eligible for refresh".
- In the code, both only sort candidates into cold or hot when a cycle's backlog does not fit the queue (`refresh.rs:90-92`, by design since #211, see [[cache-adaptive-refresh-pacer]]).
- Refresh eligibility is only `cache_access_window_secs` plus the TTL threshold. `docs/configuration/cache.md:116-117` describes this correctly.

**Symptom 3: L1 hits skip the L2 counters.**
- **Where:** `DnsCache::get` returns an L1 hit early (`storage.rs:181-194`) without `record_hit()`. So `hit_count` and `last_access` only move on L2 hits, which happen at least once per TTL per worker thread.
- **Effect:** hot A/AAAA names look cold to the `hit_rate`/LFU eviction scores and to the refresh ranking. Refresh eligibility still holds, because an L1 copy dies with the record's expiry and the next lookup goes through L2.
- Correction (2026-10-12): eligibility does *not* always hold. With a TTL longer than `cache_access_window_secs`, `last_access` can sit at insertion past the window when the renewal falls due, so a hot name is not renewed. A test reproduced that; so did HitRate eviction removing the most-hit L1 name first.

**Status:**
- Symptoms 2 and 3 are fixed by PR #286 (squash `a51f6ea`, merged 2026-10-13, shipped in v0.9.23). See [[cache-per-entry-refresh-timer]].
  - L1 batches its hits onto the L2 record, at most once per second per thread (`l1.rs` `pending_hits`, `storage.rs` `record_l1_hits`; branch commit `b40b707`).
  - The toml and the docs describe the two knobs as ranking only.
- **Stale wording left behind (2026-10-18), reworded on `docs/stale-ksk-and-l1-wording` (2026-10-26)** to say L1 hits are counted in batches. The four places were:
  - the HIT column tooltip, `web/static/cache-control.html:136`;
  - `docs/api.md:634`;
  - the `hits` doc comments in `application/src/ports/dns_cache_port.rs:50` and `api/src/dto/cache.rs:108`. The second one is also the OpenAPI description, because the DTO derives `ToSchema`.
  It was spotted while building #296 (REFRESHES column) and left out of that PR.
- Symptom 1 (dead `cache_adaptive_thresholds` / `cache_lfuk_history_size`) is still open, with no issue. Re-checked on 2026-10-18: only config, the DTOs/handlers, persistence and backup read them.
- Related, not a defect but surprising: the listing's `cached_at` (the TIME column) is the time of the last renewal, not of the first insert. `refresh_record_of` resets `inserted_at_secs` (`storage.rs:738`), and `docs/api.md` does not say so.
- Related unfixed cache items: [[cache-eviction-random-branch-deadlock]] (hardcoded `use_probabilistic_eviction`, no `l1_clear()` on eviction).

**Why not fixed:** this was an assessment, not a change request. Removing a knob touches the backup snapshot format and the config DTOs, as with [[blocking-toml-lists-dead-config]].
