---
name: disabled-group-falls-back-to-default
description: Issue #382 (2026-11-12, branch fix/disabled-group-policy) — a disabled group's clients (IP, subnet, DoH ID) resolve to the default group, mapped in the client-group loader's SQL; a migration re-enabled existing disabled groups; the backup carries the flag. Pi-hole "unfiltered" and fall-through rejected
type: project
scope: clients/groups, block-filter, backup
impact: functional
paths:
  - crates/infrastructure/src/dns/block_filter/engine.rs
  - crates/application/src/use_cases/groups/update_group.rs
  - crates/application/src/use_cases/backup/import.rs
  - migrations/20261112000001_reenable_disabled_groups.sql
---

**Decision:** on 2026-11-12 Viudes chose what a group's **Enabled** switch means. Until then the DNS path never read it.
- A client whose match is in a disabled group resolves to the default group (Protected), whether the match is by IP, subnet or DoH ID. Every per-group policy follows, because they all read the group the engine resolves: lists, managed and regex rules, Safe Search, schedules, the malware switch, pool routes and the cache view. The Query Log records Protected for those queries.
- The match goes **straight** to Protected. An IP in disabled Kids, inside a subnet of enabled Adults, gets Protected, not Adults.
- The default group can never be disabled. The use case refuses it (`ProtectedGroupCannotBeDisabled`, 400), and so does the backup import.

**How it is built:**
- `load_client_groups_inner` (`engine.rs`) `LEFT JOIN`s `groups` in its three queries and selects `CASE WHEN g.enabled = 0 THEN <default> ELSE group_id END`. The hot path (`resolve_group*`, the L0 cache) is untouched, so no bench moved.
- `UpdateGroupUseCase` calls `load_client_groups()` only when `enabled` actually changes.
- The backup import calls it once if any group's flag changed.

**Upgrade:** migration `20261112000001` switches every disabled group back on. Earlier releases ignored the flag, so this keeps every client filtered as before, as [[upgrades-keep-existing-behaviour]] requires. The upgrade note in `installation.md` tells users to switch those groups off again.

**Backup:** `GroupSnapshot.enabled: Option<bool>`. A missing key creates the group enabled and leaves an existing group's flag alone. `restore_group_switches` sets both the Enabled and Malware Detection switches on groups that already exist, never disabling the default group.

**What changes for a teammate:**
- A new per-group policy needs nothing special for disabled groups. Read the group from `resolve_group_for_request` / `resolve_group`, and never from `clients.group_id` directly.
- A new client-to-group mapping (another kind of match) must apply the same `CASE` in the loader.
- `api-pihole`'s `PUT /api/groups/{name}` still turns an omitted `enabled` into `true`, as FTL does ([[pihole-compat-ftl-mirrors]]). Now that the flag has an effect, a Pi-hole client can re-enable a group that way.
- DNS Filter → Test with an explicit `group_id` evaluates that group's own rules, disabled or not.

**Rejected:**
- **Pi-hole semantics** (a disabled group's clients are unfiltered): routes, the cache view, malware and Safe Search would each need a "null group". A group with no lists already gives an unfiltered client.
- **Falling through to the next match** (IP → subnet → default): the result would depend on where the device sits. It is also what #378's first round did for DoH IDs, which was rejected for differing from IP clients.
- **Removing the switch:** the switch is now useful, and the Pi-hole API exposes it anyway.
- **A config opt-in key** for the upgrade: a permanent switch whose only job is to make another switch work.

**Evidence:** plan `.claudin/plans/snazzy-gathering-globe.md`. The commits on `fix/disabled-group-policy`: red `b60ef6b7`, fix `b4fedc96`, migration `6ca73e63`, backup `7f1811b9`. A live main × branch run on 2026-11-12: on main, toggling did nothing; on the branch, the Kids deny was lifted and the Protected deny applied, then reverted with no restart. An upgrade from main's database re-enabled Kids. An export → import carried `enabled: false` and took effect at once.
