---
name: roadmap-as-milestones
description: PR #340 (2026-10-26/27) replaced ROADMAP.md with GitHub milestones + issues and dropped six roadmap items on purpose — TLD blocking, NRD, ACME DNS-01, DDNS, generic anomaly detection, RFC 7828 — with the reasons
type: project
scope: roadmap
impact: rejected
---

**Decision:** on 2026-10-26 Viudes moved every open, still-sensible `ROADMAP.md` item into a GitHub issue under three milestones (`v0.10.0 — API v1`, `v1.0.0 — Production Ready`, `v1.1.0 — Next Features`; issues #314–#338, later #339). `ROADMAP.md` was deleted in PR #340 (`a0ca416b`). `docs/roadmap.md` stays as a page that links the milestones.

**Why:** the file mixed nine milestones of shipped checkboxes with open plans, and several open items no longer matched the code. Some were already possible; others asked for things a resolver cannot do.

**Rejected (not filed), with the reason:**
- **Suspicious-TLD blocking:** `*.tk` is already a suffix rule (`compiler.rs` suffix matching). A TLD preset is a blocklist, not a feature.
- **Newly registered domains (NRD):** public NRD lists already work as an ordinary blocklist source.
- **ACME DNS-01 endpoint:** the CA queries the zone's public authoritative servers, and a LAN resolver is not one. Local records are also A/AAAA only.
- **DDNS endpoint:** niche, and local records live in the config file, not in a table.
- **Generic anomaly detection:** too vague to act on; six detectors already exist.
- **RFC 7828 edns-tcp-keepalive:** little gain for a forwarder. Its row left the RFC table.
- Reworded instead of dropped: the WebSocket slow-query dashboard became #335 (sort and filter the Query Log by response time). "DoH bypass detection" became #336 (answer the Firefox canary, plus a DoH-resolvers blocked service), since DoH cannot be seen on the wire.

**What changes for a teammate:**
- New plans go in as issues on a milestone. Don't recreate `ROADMAP.md`. `scripts/check-docs-version.sh` no longer checks the roadmap (its old checks 2–3), and the release PR checklist no longer asks for a roadmap milestone.
- Before filing or building one of the rejected items, answer the reason above first.

**Evidence:** plan `.claudin/plans/fuzzy-watching-metcalfe.md`; the body of PR #340, "Not filed, and why".
