---
name: conditional-pool-routing
description: Conditional forwarding (#291) is three fields on [[dns.pools]]; a routed name never falls back to default pools (SERVFAIL); per-group cache views; what was rejected
type: project
scope: dns/conditional-forwarding
impact: functional
---

**Decision:** Conditional forwarding was decided on 2026-10-15 and shipped in PR #291 (`14c4db46`, closes #272). A pool gets three optional fields: `domains`, `groups` (client group ids) and `internal`. A routed name is answered only by its pool. If that pool fails, the client gets SERVFAIL, and the query never falls back to the default pools.

**Why:** issue #272 has two cases.
- A national ccTLD (`ru`/`рф`/`su`) must resolve only through government resolvers, with DNSSEC on.
- A corporate domain is split per office, and each office's DNS answers its own client group.

A fallback would leak internal names to public resolvers and resolve the ccTLD somewhere else. Rules live on the pools because pools already hot-reload, and because this matches the dnsmasq/Unbound/AdGuard model. Routing lives inside `PoolManager` (`load_balancer/routes.rs`), so the DNSSEC chain walk and the cache refresh follow routes with no extra code. For example, `.ru`'s DNSKEY is fetched through the government pool.

**What changes for a teammate:**
- **No retry.** Don't add a retry from a routed pool to the default pools.
- **Go through `PoolManager`.** Any new code that queries upstreams must do so, or routed names leak.
- **Cache keys carry a view.** `CacheKey.view` is the group id for a group route and 0 otherwise. View 0 hashes exactly as before, and L1 holds view 0 only. Anything keyed by name must carry the view: coalescing, the negative cache, refresh timers and serve-stale.
- **`internal = true` reuses the `local_dns` flag.** It skips DNSSEC and rebinding protection, and the answer counts as Local DNS. Public zones keep both.
- **Groups are referenced by id.** Ids are AUTOINCREMENT and never reused. `POST /config` rejects unknown ids. PR #293 (open as of 2026-10-16) also refuses deleting a group while a pool routes for it. Backup import re-creates groups by name with new ids: see [[backup-snapshot-omits-pools-and-detectors]].
- **Known limit, documented:** for a group-scoped pool that is not `internal`, DS/DNSKEY lookups follow only every-client routes, because the validator does not know the client's group.

**Rejected:**
- **A SQLite table** with a port, use cases, a CRUD API and a new tab. Three pool fields reuse the pools' live reload.
- **A `forwarding_only` flag.** A pool with `domains` already leaves the default path.
- **Falling back to the default pools** when the routed pool fails, for the leak reasons above.
- **A pool with `groups` but no `domains`**, i.e. per-group upstreams (ROADMAP v1.1). Validation rejects it for now, but the door is left open.
- **Removing the id from pools when a group is deleted** (2026-10-16, #293). An empty `groups` means every client, so this would silently widen a split-horizon route to the whole network. The delete is refused instead.

**Evidence:**
- Plan: `.claudin/plans/snappy-splashing-avalanche.md`.
- PRs #291 and #293.
- User docs: `docs/configuration/dns.md#conditional-forwarding`.
