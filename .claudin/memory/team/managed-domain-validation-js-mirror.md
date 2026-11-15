---
name: managed-domain-validation-js-mirror
description: The Managed Domains bulk form mirrors ManagedDomain::validate_domain + validate_name in dns-filter.js (mDomainError); change both together and rerun the front×back parity check
type: project
---

The Bulk mode of **DNS Filter → Managed Domains** (#353) flags invalid lines before the paste is sent. `mDomainError()` in `web/static/dns-filter.js` re-implements `ManagedDomain::validate_domain`, plus `validate_name`, because a bulk rule is named after its domain (`crates/domain/src/entities/managed_domain.rs`). `mBulkMax` mirrors `MAX_BULK_MANAGED_DOMAINS` in `crates/api/src/handlers/managed_domains.rs`. The JS also strips text after `#` and blank lines. Those are UI-only rules: the API takes an array, and it trims and lowercases each entry itself.

Rules when either side changes:

1. **The JS may only flag what the backend rejects.** It never blocks the submit. Every line goes to `POST /managed-domains/bulk`, and the reply's per-entry `invalid` is the truth. The pre-check only drives the "N domains · M invalid (lines …)" hint.
2. **A stricter `validate_domain` changes every write path**: the single add, the bulk add, and the Pi-hole compat exact writes, which also go through the bulk use case. Rows already stored are not re-validated.
3. **The message text is not mirrored.** The report after a submit shows the backend's `error` with its `Invalid managed domain: ` prefix stripped.

**Why:** the form and the backend share no code, and CI runs no JS. On 2026-11-15 a 19-case Playwright parity run had no mismatch in either direction. The cases covered empty labels, a mid-string `*`, a lone `*.`, spaces, non-ASCII, a name over 200 chars, hosts and adblock lines, a trailing dot, case and inline comments. This is the same lesson as [[upstream-url-parser-js-mirror]] and [[malware-settings-js-mirror]].

**How to apply:** after changing either side, rerun the parity check. Paste the cases, read `Alpine.$data(document.body).mBulkParse()` for the JS verdicts, submit, and compare each `results[i].status === 'invalid'` with the JS flag. DNS Filter keeps every tab's form in the DOM, so scope the selectors to the form. Tooling is in [[runtime-live-ui-session]]; the instance setup is in [[runtime-verification-recipe]]. The design behind the bulk form is [[managed-domains-bulk-add]].
