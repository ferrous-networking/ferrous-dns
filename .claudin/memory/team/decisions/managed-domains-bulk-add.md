---
name: managed-domains-bulk-add
description: Issue 353 bulk add of managed domains (2026-11-15) — one transaction + one rebuild, partial apply, "existing" = an equivalent permanent rule, "<domain> (<action>)" fallback name, every compat exact create goes through it; dry_run, counts and expiry rejected
type: project
scope: managed domains (block-filter, api, api-pihole)
impact: functional
---

**Decision:** on 2026-11-15 Viudes chose how many managed domains get added at once (#353).
- `POST /ferrous/api/v1/managed-domains/bulk` and the Single|Bulk switch in DNS Filter → Managed Domains go through `BulkCreateManagedDomainsUseCase`. It writes every valid entry in one transaction and rebuilds the block filter once. It reports each invalid entry and saves the rest (partial apply).
- An entry is `existing` when its group already has a **permanent** rule with the same domain, action **and enabled state**, whatever that rule is named.
- The opposite action is still added. An allow lifts a deny, including a blocked service's deny.
- A bulk rule is named after its domain. When the group already has a rule by that name, the rule is named `ManagedDomain::fallback_name` = `"<domain> (<action>)"`, in the same transaction.
- Every Pi-hole compat exact-domain create goes through the same use case: a POST of one item, a POST of an array, and a PUT that creates. An array then costs one rebuild. A domain can also sit in the allow and the deny list at once, as FTL's `UNIQUE(domain, type)` allows. A one-domain lookup lists allow before deny, in FTL's index order.

**Why:**
- One rebuild per entry made the issue's own workaround slow. A 260-line compat array took 15 s against a 213k list on the v0.10.0 release. On debug builds with a 200k list, main took 131 s and the branch 0.53 s, with an identical `processed` reply.
- Compat answered "already present" to an allow beside a compat-made deny, because of `UNIQUE (name, group_id)`. A live Pi-hole v6 accepts both. Viudes chose to fix this in the PR rather than file a follow-up.
- A temporary rule, such as the Query Log's "allow for 1 h", must not count as existing. Otherwise the bulk allow would expire along with it.

**What changes for a teammate:**
- A write path that adds several exact domains calls `BulkCreateManagedDomainsUseCase`. Never loop over `CreateManagedDomainUseCase`: each call awaits a full index rebuild.
- Rule names can end in ` (allow)` or ` (deny)`. Never parse a domain out of a name.
- The bulk form re-checks the domain rules in JS: [[managed-domain-validation-js-mirror]].
- v1 freezes at 1.0.0. The bulk reply is `results` only, with no counts and no ids, and the request has no `expires_in_secs`. Anything more must come as a new optional field.

**Rejected:**
- **All or nothing on one invalid line,** which is what compat does in `prepare_item`. The public reply had promised a result per line.
- **Reporting the name clash and filing a follow-up.** Viudes picked the fix.
- **Stripping a trailing dot in bulk only.** Bulk would then normalize differently from the single add, and compat would store a name FTL does not. That `validate_domain` accepts `example.com.` on every path is a separate follow-up.
- **A `?dry_run=` preview instead of the JS mirror.** A v1 parameter is permanent.
- **Regex filters in bulk:** out of scope.
- **Making the single add a batch of one.** It takes a custom name and answers 409 on a clash.

**Evidence:**
- Plan `.claudin/plans/resilient-wandering-noodle.md`. Branch `feat/managed-domains-bulk-add`, cut from `1c0c13dd`, committed on 2026-11-15 after Viudes's go-ahead: red tests `97cbca04`, core `418d3c35`, API `12000776`, compat `0c9efcc3`, web `a8d90e00`.
- Three red tests:
  - a 3-item compat array took 3 rebuilds, and takes 1;
  - an allow beside a deny got 400, and gets 201;
  - `/managed-domains/bulk` answered 405, and answers 200.
- `make ci` passed, with 2,852 tests.
- The compat replies were diffed against a live Pi-hole v6 and match.
- Playwright found the JS and the backend in parity on 19 of 19 cases.
