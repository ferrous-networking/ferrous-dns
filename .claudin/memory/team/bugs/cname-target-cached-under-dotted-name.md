---
name: cname-target-cached-under-dotted-name
description: The CNAME chain's final target is cached as "target.example." (trailing dot), a key no client lookup ever matches — the shortcut has never served a hit; unfiled
type: project
paths:
  - crates/infrastructure/src/dns/forwarding/response_parser.rs
  - crates/infrastructure/src/dns/resolver/cache_layer.rs
---

**Symptom:** `CachedResolver::store_in_cache` also caches the chain's final target under its own name, so a direct query for it skips upstream. In production that entry is never hit.

**Where:** `ResponseParser` fills `cname_chain` with `canonical.to_utf8()` (`response_parser.rs:75-79`). hickory's `Name` display keeps the trailing dot of a wire name, so the target is `lb.cdn.example.`. Client query names arrive without it: the fast path never has one, and `parse_client_query_hickory` trims it (`server.rs`). The cache stores the target under the dotted key, and every lookup uses the undotted one.

**Why tests missed it:** `cache_cname_target_test.rs` feeds a mock resolver whose chain targets have no dot. With a real wire answer (`tests/support/upstream.rs` `Answer::Cname`), only the dotted probe hits. Found 2026-10-15 while writing `cache_group_view_test.rs` for #272.

**Cost today:** one dead entry per CNAME answer, plus its refresh timer. Entries nobody reads are parked by the access window rather than renewed.

**Fix sketch:** trim the trailing dot where the chain is built, or where the target key is built in `store_in_cache`. Fixing it starts serving real hits for CDN targets, which is a behavior change: the target answer is the chain's, with the chain's TTL and DNSSEC status.

**Status:** open, unfiled. The #272 tests check both forms of the target on purpose (`TARGET_FORMS` in `cache_group_view_test.rs`), so they keep passing after a fix.
