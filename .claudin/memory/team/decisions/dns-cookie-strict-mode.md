---
name: dns-cookie-strict-mode
description: DNS Cookies — every reply echoes the client cookie; strict mode is UDP-only, turns the inline cache path off, and answers BADCOOKIE (23) + EDE 18 (branch fix/dns-cookie-echo, issue #279)
type: project
scope: dns-cookies
impact: functional
---

**Decision:** made on branch `fix/dns-cookie-echo` for issue #279 (commits `9135317` and `d2f5e4f`). Viudes chose each point on 2026-10-11.
- Every reply to a query with a well-formed COOKIE carries ours: cache hits of every type, errors, blocks, and TC=1. On the slow path the cookie lives in `ClientEdns`, so each `respond`/`truncated` carries it without being handed it.
- Strict mode (`require_valid_cookie = true`):
  - It applies to UDP only (`DnsCookieGuard::requires_cookie`). TCP, DoT, DoH and DoQ are exempt.
  - A client cookie without a valid server cookie gets BADCOOKIE (23) with a fresh cookie. A query with no cookie gets REFUSED. Both carry EDE 18 (Prohibited).
  - `cache_gate` declines every hit, so all UDP queries take `execute`, the only place that validates the cookie.

**Why:**
- c-ares drops any cookie-less reply once it has learned our server cookie (RFC 7873 §5.3), which made Alpine curl/git time out.
- Before this, strict mode could not work at all. It sent REFUSED without a cookie, so no client could bootstrap. It refused every DoH client. It served cache hits unvalidated, documented in #251 as intended.
- EDE 25 is *Signature Expired before Valid* in the IANA registry, not a cookie code.

**What changes for a teammate:**
- A new reply path built from a `ClientQuery` carries the cookie automatically; don't add a `cookie` parameter back.
- The A/AAAA fast path computes the cookie only on a hit and only when the query sent one, at about +320 ns per hit (bench `a_edns_cookie` vs `a_edns`, 564 vs 245 ns).
- Don't move strict validation into `cache_gate`. It would duplicate `execute`'s rule; turning the fast path off under strict mode was the accepted cost.

**Rejected:**
- A `cookie` parameter on `try_cache_direct`/`try_cache_wire_direct`, validated in `cache_gate`: it keeps the fast path but duplicates the rule.
- Keeping REFUSED for bare client cookies.
- Applying strict mode to stream transports.

**Evidence:** issue #279; red runs in commits `f7d4ef0` and `86dc10e`; plan `cheerful-giggling-allen.md`.
