# Backups & Upgrades

## What to back up

| What | Where (systemd unit) | Where (Docker image) | Holds |
|:-----|:---------------------|:---------------------|:------|
| The database | `/var/lib/ferrous-dns/ferrous.db` | `/data/ferrous-dns.db` | Users, sessions, API tokens, clients, groups, blocklist sources, managed domains, the query log |
| The config file | `/etc/ferrous-dns/config.toml` | `/data/config/ferrous-dns.toml` | Every setting, the upstream pools, the local DNS records, the admin password hash, the DNS cookie secret |
| TLS files | `/var/lib/ferrous-dns/tls/` | `/data/cert.pem`, `/data/key.pem` | The dashboard and DoT/DoQ certificates and keys |

The database path is whatever `[database] path` says in your config. With the image's bundled config that is `ferrous-dns.db` in the working directory `/data`, so `/data/ferrous-dns.db`. `FERROUS_DATABASE` overrides it only when set to something other than its default, `/data/db/ferrous.db`.

The dashboard's **Settings → Backup → Download Backup** file is not a backup of the server. It carries the settings, groups, blocklist sources and local records, without secrets, users, clients or the query log. It is the tool for copying a setup to a [second instance](redundancy.md), not for getting a dead one back.

---

## Backing up the database

`--backup-database` copies the database while the server keeps running:

=== "systemd"

    ```bash
    sudo install -d -o ferrous-dns -g ferrous-dns -m 0750 /var/lib/ferrous-dns/backups
    sudo -u ferrous-dns /usr/local/bin/ferrous-dns --config /etc/ferrous-dns/config.toml \
      --backup-database "/var/lib/ferrous-dns/backups/ferrous-$(date +%F).db"
    ```

=== "Docker"

    ```bash
    docker exec ferrous-dns mkdir -p /data/backups
    docker exec ferrous-dns /entrypoint.sh \
      --backup-database "/data/backups/ferrous-$(date +%F).db"
    ```

    Going through `/entrypoint.sh` applies the same `FERROUS_*` variables the server started with, so the copy is taken from the same file.

The copy:

- **is consistent.** It is one read of the database at one instant, taken with SQLite's `VACUUM INTO`, while the server goes on answering and writing.
- **is checked.** It is written to `<PATH>.partial`, passes `PRAGMA integrity_check`, and only then is renamed to `<PATH>`. A failed or interrupted run never leaves a file under the name you would restore from.
- **is private.** It is readable by its owner only, since it holds password hashes, sessions and every client's queries.
- **never overwrites.** An existing `<PATH>` is refused, so date the file name.
- **is compact.** It has no free pages, so it is usually smaller than the live file.

The command exits non-zero with the reason on failure. Measured on the host described in [Sizing](sizing.md), it copied 1,068,604 logged queries in 5.4 s while the server logged 20,000 more queries a second, and not one query went unanswered.

### On a schedule

Run it from cron as the service user, and delete old copies. The second line also deletes what an interrupted run left: a `.partial` file under the dated name, which the next day's run does not reuse. In a crontab, `%` has to be escaped:

=== "systemd"

    ```cron
    # /etc/cron.d/ferrous-dns
    30 3 * * * ferrous-dns /usr/local/bin/ferrous-dns --config /etc/ferrous-dns/config.toml --backup-database /var/lib/ferrous-dns/backups/ferrous-$(date +\%F).db
    45 3 * * * ferrous-dns find /var/lib/ferrous-dns/backups -name 'ferrous-*.db*' -mtime +14 -delete
    ```

=== "Docker"

    ```cron
    # crontab -e, as a user allowed to run docker
    30 3 * * * docker exec ferrous-dns /entrypoint.sh --backup-database /data/backups/ferrous-$(date +\%F).db
    45 3 * * * docker exec ferrous-dns find /data/backups -name 'ferrous-*.db*' -mtime +14 -delete
    ```

A copy on the same disk does not survive the disk. Ship the backups directory, the config file and the TLS files to another machine with the backup tool you already use.

---

## Restoring

Restore with the server stopped. Set the current file aside rather than deleting it, and remove its `-wal` and `-shm` files: they belong to the old file and must not be applied to the restored one.

=== "systemd"

    ```bash
    sudo systemctl stop ferrous-dns
    D=/var/lib/ferrous-dns
    sudo mv $D/ferrous.db $D/ferrous.db.before-restore
    sudo rm -f $D/ferrous.db-wal $D/ferrous.db-shm
    sudo install -o ferrous-dns -g ferrous-dns -m 0600 $D/backups/ferrous-2026-11-04.db $D/ferrous.db
    sudo systemctl start ferrous-dns
    ```

=== "Docker"

    ```bash
    docker stop ferrous-dns
    docker run --rm --volumes-from ferrous-dns alpine sh -c 'cd /data &&
      mv ferrous-dns.db ferrous-dns.db.before-restore &&
      rm -f ferrous-dns.db-wal ferrous-dns.db-shm &&
      cp -p backups/ferrous-2026-11-04.db ferrous-dns.db'
    docker start ferrous-dns
    ```

    `--volumes-from` mounts the stopped container's `/data`, whatever the volume is called. Compose names it after the project, such as `ferrous-dns_ferrous-data`.

Put the config file and the TLS files back the same way if they were lost too. Take the config file and the database from the same day, so the settings and the data that refers to them, such as groups, pools and blocklist sources, still match.

---

## Upgrading

1. **Read the release notes** and the [upgrade notes](../getting-started/installation.md#upgrading). They list changed defaults and config values rewritten at load.
2. **Back up.** Take a database backup as above, and copy the config file. Releases before 1.0.0 have no `--backup-database`: stop the server and copy the database file instead.
3. **Pin the new version.** Images are tagged with the full version (`ferrousnetworking/ferrous-dns:X.Y.Z`) and `latest`. There are no `X` or `X.Y` tags. Change the tag in your compose file, or replace the binary.
4. **Start it and read the first log lines.** Migrations run on the first start, before the server answers. Look for the warnings the upgrade notes mention:

    ```bash
    docker logs ferrous-dns 2>&1 | grep -E "Invalid config value|Config key not read"
    journalctl -u ferrous-dns -b | grep -E "Invalid config value|Config key not read"
    ```

5. **Check health** with `/ferrous/api/v1/health`, a query and a look at the dashboard.

---

## Rolling back

Database migrations run forward only. Once a newer release has started on a database, an older one refuses it. v0.10.0, started on a database that a later build had migrated, stops with:

```text
Error: migration 20261101000001 was previously applied but is missing in the resolved migrations
```

So rolling back means going back to the files from before the upgrade:

1. Stop the server.
2. [Restore](#restoring) the database you backed up in step 2 of the upgrade, and the config file from the same moment.
3. Start the previous version: put the old image tag back, or the old binary.

Anything written after the upgrade, such as new queries in the log, settings or clients, is lost in the rollback. A backup file downloaded from the dashboard of a newer release may not import into an older one.
