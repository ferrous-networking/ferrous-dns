---
name: cache-adaptive-refresh-pacer
description: Why cache optimistic refresh is paced by backlog (PR #211) and why cache_max_refresh_per_sec was removed after PR #210
type: project
---

PR #210 (merged 2026-08, v0.9.13) moved optimistic refresh from an inline loop to a paced
queue with `cache_max_refresh_per_sec = 4.0`. The problem it set out to solve was
burstiness — a 60s cycle firing the whole working set at once — but burstiness was already
bounded by the 16-way concurrency semaphore, so the fixed rate only capped total
throughput. Symptom in production: a hot domain drifted from 15–98 us (`Cache`) to
54–290 ms (`unbound`) as the day filled the access window. See
[[cache-refresh-maximize-coverage]] for the invariant this violated.

PR #211 (2026-08-25, branch `fix/cache-adaptive-refresh-pacer`) replaced it:

- A cycle divides its own interval by the backlog it produced and publishes that period to
  the worker over a `watch` channel. Rate follows demand; the semaphore still bounds
  instantaneous upstream load.
- `cache_max_refresh_per_sec` was removed end to end. Old TOMLs and backups still load —
  there is no `deny_unknown_fields` anywhere in the config — and the key is stripped on the
  next save.
- A lead-time floor takes an entry when less than `2 x cycle interval` of TTL remains,
  whichever fires first against the proportional threshold. Without it the threshold alone
  is insufficient: a candidate waits up to one cycle to be scanned and one more to be
  drained. TTLs shorter than that window stay on the serve-stale path.
- Candidates are ordered by `(cold, death deadline)` and the queue is sized from
  `cache_max_entries` instead of a fixed 256. Previously the order was DashMap iteration
  order and the tail was dropped — stable, so the same entries starved every cycle.
- `cache_min_hit_rate` / `cache_min_frequency` now rank under pressure instead of excluding.
  On a healthy deployment nothing is trimmed and they have no effect on refresh. This is
  what the settings UI had always claimed they did.
- `FLAG_REFRESHING` was split into `FLAG_REFRESH_QUEUED` (de-dup across cycles) and
  `FLAG_REFRESHING` (resolution in flight). Only the latter blocks the unpaced serve-stale
  bypass, which a queued-but-not-started candidate used to block.
- New counters `cache_stale_refresh_drops` and `cache_optimistic_refresh_shed` on
  `/metrics` — a sustained non-zero shed means the working set outgrew the queue.

Deferred: `min_threshold` / `min_threshold_bits` is now write-only outside its own EWMA and
is a removal candidate, but that touches eviction. The 60s cycle interval is still fixed,
though it is now one shared constant because it is the pacer denominator.
