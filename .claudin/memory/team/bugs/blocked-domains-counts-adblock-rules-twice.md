---
name: blocked-domains-counts-adblock-rules-twice
description: Dashboard "Blocked Domains" (total_blocked_domains) was exact.len() + wildcard.len(), so every adblock `||domain^` line counted twice; fixed in PR #297 (e2136494), shipped in v0.9.24
type: project
paths: crates/infrastructure/src/dns/block_filter/compiler.rs
---

**Symptom:** the dashboard's *Blocked Domains* card (`GET /api/block-filter/stats`) reports almost twice
the domains the lists hold when they are in adblock format, which every HaGeZi `adblock/*.txt` list is.

**Cause:** `compiler.rs` sets `total_blocked_domains: total_exact + total_wildcard`. An adblock
`||domain^` line becomes an exact entry *and* a suffix rule (`ParsedEntry::DomainAndSubdomains`), so it
lands in both counts. Hosts-format and plain-domain lines count once. The comment above the sum ("counts
both its apex and suffix rule") came in with #233 and describes the behaviour; nothing user-facing
(dashboard label, docs) says the number is rules rather than domains.

**Measured 2026-10-18** with Viudes's home-lab lists (AdGuard mobile adservers, StevenBlack hosts,
developerdan ads-and-tracking-extended, HaGeZi fake/popupads/pro/tif adblock) on a debug build of
`fix/web-ui-standardization`: log `exact=2794950 wildcards=2325191`, card **5,120,141**; distinct
domains across the lists **2,794,950**. A Python replica of `parse_list_line` + `build_exact_and_wildcard`
reproduced both numbers exactly.

**Fix (PR #297, squash-merged as `e2136494`, shipped in v0.9.24 on 2026-10-23):** the branch commits
were red test `ea8e4186` and fix `37804564`, neither of which is on main. The
total is now `exact.len()` plus each suffix rule whose name has no exact entry; `insert_wildcard`
returns whether the suffix is new, and suffix rules (manual `*.x` included) are inserted after the exact
map is complete. Same lists: card **2,794,950**, log unchanged (`exact=2794950 wildcards=2325191`).
The log's `wildcards=` is still the rule count, not domains. Duplicates across lists were always
deduplicated (DashMap key / one trie terminal); only the exact+suffix sum double-counted.
