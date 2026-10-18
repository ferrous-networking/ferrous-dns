---
name: backup-snapshot-omits-pools-and-detectors
description: Backup export/import carries upstream_servers but not [[dns.pools]] (or their routes), [dns.rate_limit], or the malware detectors; groups re-import with new ids
type: project
paths: crates/application/src/use_cases/backup/
---

**Symptom:** a backup moves `dns.upstream_servers` but none of these:
- `[[dns.pools]]`, including the conditional-forwarding fields `domains`, `groups` and `internal`;
- `[dns.rate_limit]`;
- the five malware detectors' tables and `malware_detection_enabled`.

On import, the target keeps its own values for all of them, with no warning.

**Where:** `crates/application/src/use_cases/backup/snapshot.rs`. `SnapshotDnsConfig` (~:47) has no field for any of these. `export.rs` and `import.rs` follow that struct.

**Trap for whoever fixes it:** `GroupSnapshot` holds only `name` and `comment`, so imported groups get new ids. Pool `groups` are ids ([[conditional-pool-routing]]), so they must be remapped by group name on import. Otherwise a route ends up on the wrong group, or on a missing one, which `POST /config` then rejects.

**Repro:** read the snapshot struct; the fields are not there. This was confirmed in code on 2026-10-16 but not run live.

**Status:** open, with no issue as of 2026-10-16. It was left out of #291 (2026-10-15) and #292 (2026-10-16) on purpose, and both list it as a follow-up.

**Why not fixed:** it changes the snapshot format, and neither PR was about backups. Related: [[backup-import-no-restart-flag]].
