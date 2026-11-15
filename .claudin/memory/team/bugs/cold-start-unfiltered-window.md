---
name: cold-start-unfiltered-window
description: After every start the server answered queries before the block index was compiled (~0.2 s with HaGeZi Pro), and lists were re-downloaded each start; #365, fixed by PR #389 (10a78b33, merged 2026-11-12)
type: project
---

**Symptom:** `/health` turns 200 and DNS answers before the blocklists are compiled. During that gap a blocked name resolves to its real address. Every start downloads every list again, so the gap grows with the link speed and the list size.

**Measured on 2026-11-04** (release build, i9-9900KF): the server answered 0.17 s after start. The lists were in force 0.4 s after start for 1M entries from the LAN, 0.5 s for HaGeZi Pro from GitHub, and 1.4 s for 3M entries. `pagead2.googlesyndication.com` resolved normally for about 0.2 s after the first passing health check, then returned `0.0.0.0` once `Block index compiled` was logged.

**Repro:** Start with HaGeZi Pro enabled and `dig` a blocked name in a tight loop from the moment the process launches. Compare the answers against the timestamp of the `Block index compiled` log line.

**Status:** Filed 2026-11-04 as #365 on milestone v1.0.0, a follow-up of PR #363 (#318). Fixed on branch `fix/startup-filter-window` (2026-11-12): red `3c98053b`, hold `fc94ddb6`, list cache `9e153767`, docs `a91f114c`. Both options were taken: no port opens until the first build (≤30 s), and each list is kept in `lists/` beside the database. The design is in [[startup-hold-and-list-cache]]. PR #389 merged 2026-11-12 as `10a78b33`, closing #365.

**Why not fixed in #363:** It was found while measuring for the operations guide, and was out of that PR's scope.
