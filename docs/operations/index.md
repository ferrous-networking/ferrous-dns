# Running in Production

[Installation](../getting-started/installation.md) gets Ferrous DNS answering queries. This section covers what comes after: keeping it running for months on a network that depends on it, getting your data back when a disk dies, and noticing trouble before your users do.

Every command and configuration file in these pages was run against a real server before it was written down. Where a page quotes a version, it writes `X.Y.Z`. Replace it with the release you run, from the [releases page](https://github.com/ferrous-networking/ferrous-dns/releases).

---

## Before you go live

- [ ] **Pin a release.** Run a fixed version, `ferrousnetworking/ferrous-dns:X.Y.Z` or the release tarball, never `latest`. Then an upgrade is a decision you make, not one that happens on a pull. See [Upgrading](backups-upgrades.md#upgrading).
- [ ] **Run it unprivileged.** The Docker image runs as uid 1000. On bare metal, use the [systemd unit](systemd.md), which runs as its own user and keeps only the capability to bind port 53.
- [ ] **Size the host.** Blocklists and the cache are held in memory. The query log grows on disk with traffic and retention. See [Sizing](sizing.md).
- [ ] **Back up the database.** `--backup-database` copies it without stopping the server. Schedule it, keep the config file and the TLS files beside it, and try a restore once. See [Backups & upgrades](backups-upgrades.md).
- [ ] **Cap the logs.** journald rotates on its own. Docker keeps every line unless the log driver is capped. See [Logs](logs-monitoring.md#logs).
- [ ] **Watch it.** Turn on `/metrics` and load the [ready-made alert rules](logs-monitoring.md#alert-rules), which fire on a DNS listener that stopped serving, upstreams down, SERVFAIL and REFUSED spikes, shed queries, a TLS certificate close to expiry and a filling disk.
- [ ] **Serve the dashboard over HTTPS.** Put it behind a reverse proxy, keep the dashboard port off the network, and plan for certificate renewals. See [TLS & reverse proxy](tls-reverse-proxy.md).
- [ ] **Have a second resolver.** Hand out two independent instances over DHCP, so a restart or a dead host does not take name resolution with it. See [Redundancy](redundancy.md).
- [ ] **Go through the security checklist.** DNS cookies, rate limiting, DNSSEC mode and `trusted_proxies` are covered in [Security Hardening](../features/security-hardening.md#deployment-checklist).

---

## In this section

| Page | Covers |
|:-----|:-------|
| [Bare metal (systemd)](systemd.md) | Installing the release binary as a sandboxed systemd service |
| [Backups & upgrades](backups-upgrades.md) | Online database backups, restores, upgrades and rolling back |
| [Sizing](sizing.md) | Memory for blocklists and the cache, disk for the query log, measured |
| [Logs & monitoring](logs-monitoring.md) | Where logs go, the health check, Prometheus scraping and alert rules |
| [TLS & reverse proxy](tls-reverse-proxy.md) | The dashboard behind nginx, Caddy or Traefik, and renewing DoT/DoQ certificates |
| [Redundancy](redundancy.md) | Running two resolvers, and what they do not share |
