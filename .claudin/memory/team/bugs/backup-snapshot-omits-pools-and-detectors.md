---
name: backup-snapshot-omits-pools-and-detectors
description: Backups omitted [[dns.pools]] (and routes), [dns.rate_limit] and the malware detectors, and re-imported groups got new ids; fixed on branch fix/backup-pools-and-detectors (2026-10-23)
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

**Status:** fixed on branch `fix/backup-pools-and-detectors` (2026-10-23; red `b2005743`/`f15e48d4`, fix `1cb4704d`/`bd10a956`). It was left out of #291 and #292 on purpose.
- `SnapshotDnsConfig` gained `pools`, `rate_limit` and `malware` (a `SnapshotMalwareConfig` of the master switch, rebinding fields and four detector configs), all `Option`: an older backup keeps the target's values.
- `GroupSnapshot` gained `id` and `is_default`. The import creates groups first, then translates ids by name (the default group to the local default). A pool route is always translated, and an unknown id rejects the config section. A blocklist source is translated when the backup carries ids and keeps raw ids otherwise, which is the old behaviour. The old raw-id import silently put a source on whatever local group had that id.
- Pool servers are parsed with `DnsProtocol` on import, since `validate` does not.

**Still not in a backup:** `query_timeout`, `health_check`, `dns_cookies`, `qname_case_randomization`, `default_strategy` and the other DNS fields `SnapshotDnsConfig` never mirrored. Related: [[backup-import-no-restart-flag]].
