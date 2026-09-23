---
name: docs-screenshot-recipe
description: How the docs/assets/dashboard screenshots are produced — seeding steps, capture settings, and the API quirks that bite when scripting the seed
type: project
---

Dashboard screenshots live in `docs/assets/dashboard/`, one per nav page, captured
at a **1920x1080 viewport in the light theme** via the Playwright MCP against a
real running binary. Re-captures must match those settings or the set stops
looking uniform. (The three older auth shots in `docs/assets/auth/` are
2360x1800 cropped-to-content and do *not* follow this — they predate it.)

Bring the instance up with [[runtime-verification-recipe]], then seed it. API
quirks that cost time when scripting the seed:

- **Quote request bodies from a file.** A password containing `!` passed inline
  to `curl -d '…'` comes back as `400 Invalid request body`; `--data-binary @file`
  works. Same for any body with shell metacharacters.
- **`action` is `allow` / `deny`**, never `block`, on both `/managed-domains` and
  `/regex-filters`.
- **Safe Search is `POST /safe-search/configs/{group_id}`** (not PUT); assigning a
  schedule to a group is **`PUT /groups/{id}/schedule`** (not POST).
- **Schedule slots cannot cross midnight** — `21:00`→`07:00` is rejected; split it
  into `21:00`→`23:59` and `00:00`→`07:00`. Slot actions are `block_all` /
  `allow_all`.
- **The service catalog is `/services/catalog`**; `/services` alone lists what is
  blocked for a group and returns `[]` until you block something.
- **Blocklist sources are group-scoped.** A source created with the default
  `group_ids:[1]` blocks nothing for clients you then assign to other groups —
  the page will look right while `dig` still resolves ad domains. Assign every
  group, or leave the querying clients ungrouped.
- Blocked answers are cached for `block_ttl`, so a domain that resolved while the
  index was incomplete keeps resolving; there is no cache-flush route (`DELETE
  /api/cache` is 404), so restart the process after fixing the index.

For query traffic, `dig -b 127.0.0.2 … -b 127.0.0.5` gives distinct client rows
without touching the host's network or leaking real LAN addresses; rename them
afterwards with `PATCH /clients/{id}` to get friendly hostnames and groups in the
Clients page. Around 1,900 queries with roughly a fifth blocked produces a
dashboard that reads as realistic.
