---
name: upstream-url-parser-js-mirror
description: DnsProtocol::from_str and settings.js upstreamUrlError must change together (same rules, same messages); tightening the parser also needs a legacy.rs pass or old configs stop starting
type: project
paths: crates/domain/src/value_objects/dns_protocol.rs, web/static/settings.js, crates/domain/src/config/legacy.rs
---

Two rules for anyone changing how upstream server URLs are parsed. They come from PR #255
(issue #250, 2026-09-25), which added both the parser hints and the form check.

1. **The Settings pool editor mirrors the Rust parser.** `upstreamUrlError()` in
   `web/static/settings.js` reimplements `DnsProtocol::from_str`, hint messages included, so the form
   can explain a bad URL before it saves. The Rust file does not point back to it. Change a rule
   or a message in one and you must change the other. The JS must only flag what the backend also
   rejects, so it never blocks a valid URL. It is allowed to let through a URL the backend rejects,
   since the save still fails server-side. A known quirk mirrored on purpose: `udp://2001:4860:4860::8888`
   (unbracketed IPv6, no port) parses as host `2001:4860:4860:` with port `8888`.
2. **Tightening the parser can stop an upgraded server from starting.** `Config::validate` does
   not parse pool servers. An unparseable server only fails later, in `PoolManager::build_pools`
   at startup. Anything older releases accepted (e.g. the empty host in `doq://:853`, which the
   API used to save) therefore needs a load-time normalization in `legacy.rs`
   (`drop_hostless_upstreams`), following that module's policy.

**Why:** there is no JS test harness in CI. Drift only shows up in a live front×backend comparison:
the 2026-09-25 run over 43 inputs caught `999.1.1.1:53`.

**How to apply:** after any parser change, rerun the parity check (Playwright
`app().upstreamUrlError(x)` against `POST /api/config`), per [[runtime-verification-recipe]].
Related: [[upstream-hostname-startup-only-resolution]].
