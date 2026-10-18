---
name: pihole-compat-ftl-mirrors
description: Pi-hole compat responses are checked against strict FTL mirror structs in crates/api-pihole/tests/helpers/ftl.rs; FTL's C code wins over its OpenAPI YAML
type: feedback
---

Every Pi-hole compat route answers with Pi-hole FTL's exact response shape, which was pinned at FTL `0bf029b` in October 2026. `crates/api-pihole/tests/helpers/ftl.rs` holds strict mirrors of those shapes (`deny_unknown_fields`), and endpoint tests call `assert_ftl_shape::<ftl::X>(&body)` on the real reply.

**Why:**
- Typed clients reject any difference. Homarr probes `/api/info/login`, python-hole needs the nested `/info/version`, and eko decodes `/stats/upstreams` as an array.
- Small differences broke all three until issue #283.
- FTL's YAML and its C code sometimes disagree: `reply.time` is in seconds, `csrf` is omitted without a session, and `flush/logs` deletes every stored query. Clients follow what FTL actually sends.

**How to apply:**
- When changing a compat reply, update or add its mirror and cite the FTL file:line.
- When the spec and the C code differ, follow the C code and leave a one-line comment.
- Fields Ferrous cannot fill keep FTL's key with a neutral value, listed in the Limitations section of `docs/features/pihole-compat.md`.
- Request bodies go through `extract::PiholeJson`, never `axum::Json`, because Homarr sends JSON as `text/plain`.
- The mirrors only know what the YAML says. Before merging, diff against a live Pi-hole too ([[pihole-compat-live-validation]]). Which routes stay unserved, and why: [[pihole-compat-scope]].
