---
name: cname-target-cached-under-dotted-name
description: CNAME chain names kept hickory's trailing dot, so the target shortcut (#325) never hit and CNAME cloaking never blocked a real answer; PR #354 normalizes them and removes the shortcut (opened 2026-11-01)
type: project
paths:
  - crates/infrastructure/src/dns/forwarding/response_parser.rs
  - crates/infrastructure/src/dns/resolver/cache_layer.rs
  - crates/application/src/use_cases/dns/handle_dns_query.rs
---

**Symptom:** `ResponseParser` filled `cname_chain` with `Name::to_utf8()`, which keeps the root dot (`lb.cdn.example.`). Client names, block rules and cache keys have none. Two features were dead for it: the chain-target cache entry (#325, never hit) and CNAME cloaking (never matched a rule on a real answer).

**Why tests missed it:** the application cloaking tests and `cache_cname_target_test.rs` fed mock chains without the dot. Only a real wire answer (`tests/support/upstream.rs` `Answer::Cname`) shows it.

**Fix (branch `fix/cname-chain-trailing-dot`, 2026-10-31 → 11-01):**
- `normalize_wire_name` in `cache/key.rs` (no trailing dot, ASCII-lowercase), used by `server.rs` and the parser.
- The chain is cached with the answer (`CachedAddresses.cname_chain`, `WireData(Arc<CachedWire>)`), and every cached hit re-checks it per group. The memo in the decision cache alone let a reload, the chain's TTL or another group's cached copy serve the alias unchecked.
- An explicit allow of the queried name now lifts cloaking (it ignored `explicitly_allowed` before).
- DNS64's synthesized AAAA keeps the A answer's chain.

**The target shortcut was removed, not fixed.** Once names matched, it cached an upstream's answer under the target's own name in the shared view, overriding a name another mechanism owns: a conditional pool for every client, a wildcard local record, a `local_domain` name. A guard would need every owner of a name. Do not bring it back without that.

**Status:** fixed in PR #354 (opened 2026-11-01, `make ci` 2543 green). The Query Log still labels `cname_cloaking` rows "Upstream" until #326.
