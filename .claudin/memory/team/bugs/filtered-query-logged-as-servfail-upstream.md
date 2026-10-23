---
name: filtered-query-logged-as-servfail-upstream
description: block_non_fqdn / block_private_ptr refusals reached the client as a blocked answer (0.0.0.0 + EDE 15) but were logged SERVFAIL, shown as "Upstream"; fixed in PR #300 (38d257ac, v0.9.24); three follow-ups open
type: project
paths:
  - crates/application/src/use_cases/dns/handle_dns_query.rs
  - crates/infrastructure/src/dns/resolver/filters.rs
  - web/static/queries.js
---

**Symptom:** a dotless name such as `omada` (TP-Link switches look up their controller by it) shows in the Query Log with SOURCE "Upstream", an empty ANSWER and a response time of a few µs. Nothing went upstream.

**Where:** `QueryFilters::decide` refuses the name with `DomainError::FilteredQuery` (`filters.rs:79-81`, "Non-FQDN query blocked"; private PTRs take the same path at `filters.rs:72-77`). The client gets `build_blocked_wire`: NOERROR 0.0.0.0 / `::`, TTL 60, EDE 15 "query filtered by policy" (`server.rs:276-280`, `ede.rs:28`). The log, however, falls to `_ => "SERVFAIL"` with no `block_source` (`handle_dns_query.rs:939-945`). `formatSource` then falls through to `'Upstream'` (`queries.js:189`).

**Effect:** the log disagrees with the wire on both the rcode and the source. These refusals inflate the SERVFAIL count and never count as blocked.

**Repro (2026-10-22, lab with `block_non_fqdn = true`):** `dig @10.0.1.1 omada A` returns 0.0.0.0 with EDE 15 "query filtered by policy", and the switch's row for the same name reads Upstream / "–" / 8 µs.

**Fix sketch:** log FilteredQuery as a block with its own `block_source` (for example `non_fqdn` and `private_ptr`) plus a matching `formatSource` label. Check the Pi-hole `/queries` status mapping too, since it reads the same row.

**Status:** found 2026-10-22 while explaining a Query Log screenshot to Viudes. Fixed by **PR #300**, squash-merged as `38d257ac` and shipped in v0.9.24 (2026-10-23); its branch commits were the red test `1afe6156` and the fix `547def03`. In that fix:
- `DomainError::FilteredQuery` carries a `BlockSource`, either the new `NonFqdn` (11) or the new `PrivatePtr` (12).
- The use case logs the query as `BLOCKED`, and Pi-hole compat maps it to `GRAVITY`.
- The UI shows the Non-FQDN and Private PTR labels and hides the Allow button on those rows, because a managed allow cannot lift the filter.

Old rows keep `SERVFAIL`.

The PR lists three follow-ups, all predating it and still open on 2026-10-23:
- `formatSource` (`queries.js:167-191`) has no label for `cname_cloaking`, `schedule`, `nxdomain_hijack` or `response_ip_filter`, so those rows also show "Upstream".
- Filtered queries pass `admit_upstream()` before the filter runs.
- The ANSWER column renders "—" for every rcode.
