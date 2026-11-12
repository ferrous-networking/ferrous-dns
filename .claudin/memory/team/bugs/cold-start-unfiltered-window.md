---
name: cold-start-unfiltered-window
description: After every start the server answers queries before the block index is compiled, so blocked names resolve normally for a moment (~0.2 s measured with HaGeZi Pro); lists are re-downloaded each start; open, filed as #365 on v1.0.0 (2026-11-04)
type: project
---

**Symptom:** `/health` turns 200 and DNS answers before the blocklists are compiled. During that gap a blocked name resolves to its real address. Every start downloads every list again, so the gap grows with the link speed and the list size.

**Measured on 2026-11-04** (release build, i9-9900KF): the server answered 0.17 s after start. The lists were in force 0.4 s after start for 1M entries from the LAN, 0.5 s for HaGeZi Pro from GitHub, and 1.4 s for 3M entries. `pagead2.googlesyndication.com` resolved normally for about 0.2 s after the first passing health check, then returned `0.0.0.0` once `Block index compiled` was logged.

**Repro:** Start with HaGeZi Pro enabled and `dig` a blocked name in a tight loop from the moment the process launches. Compare the answers against the timestamp of the `Block index compiled` log line.

**Status:** Open, filed 2026-11-04 as #365 on milestone v1.0.0. It is listed as a follow-up in PR #363 (#318). `docs/operations/sizing.md#restarts` documents the window. The candidate fixes were not decided: hold answers until the index compiles, or keep a cached copy of each list on disk.

**Why not fixed:** It was found while measuring for the operations guide, and is out of that PR's scope.
