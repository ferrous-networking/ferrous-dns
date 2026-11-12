---
name: backup-import-overwrites-host-fields
description: /config/import copied host-specific settings (bind address, ports, web TLS, webauthn rp_*) onto a second host. #372 (b7904e7b, 2026-11-08) added an opt-in keep_host_settings; a plain import is still a full restore
type: project
paths:
  - crates/application/src/use_cases/backup/import.rs
  - crates/application/src/use_cases/backup/snapshot.rs
---

**Symptom (before #372):** The redundancy recipe suggests importing instance A's dashboard backup on instance B. Doing that replaced several of B's own settings: `bind_address`, the DNS and web ports, web TLS on/off with its cert and key paths, and `[auth.webauthn] rp_id`/`rp_origin`. If B bound a specific IP, kept its certificates elsewhere or had its own passkey origin, it failed to bind after the restart, or its passkeys stopped working.

**Status:** fixed by #372 (`b7904e7b`, merged 2026-11-08, issue #368).
- `POST /config/import?keep_host_settings=true`, or the checkbox on the Settings import card, keeps this server's host settings. These are `dns_port`, `web_port`, `bind_address`, `web_bind_address`, `[server.web_tls]` enabled/cert/key and `[auth.webauthn]` rp_id/rp_origin. The import skips `import.rs` `restore_host_settings` when the option is set. `pihole_compat` is still copied from the backup.
- The option is off by default, so a plain import is a full restore, as before. Why: [[upgrades-keep-existing-behaviour]].
- `docs/operations/redundancy.md` tells the second host to tick the box.

**Trap for the next snapshot field:** an older backup lacks every key added after it was made.
- `web_bind_address` is an `Option<Option<String>>` in `snapshot.rs`: a missing key keeps the target's value, and `null` unsets it.
- This came out of #372's review. With a plain `Option`, an older backup cleared the field on a full restore (red `36e1ecd1`, fix `367b9108`).
- A new host-scoped field also has to go into `restore_host_settings`.

Related: [[backup-snapshot-omits-pools-and-detectors]].
