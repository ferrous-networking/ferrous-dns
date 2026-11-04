# Redundancy

When the only resolver on a network restarts, everything that needs a name waits for it: a restart starts with an empty cache, and the blocklists are compiled again (see [Sizing](sizing.md#restarts)). A second resolver turns an upgrade, a reboot or a dead disk into a non-event.

---

## Two independent instances

Run two Ferrous DNS servers on different hosts, and hand out both addresses:

- **DHCP:** list both in the DNS server option (option 6) of your DHCP server or router.
- **IPv6:** list both in the router advertisement's RDNSS option, or in DHCPv6.

Each instance is a complete server with its own database, and neither knows about the other. Clients choose between them. Most try the first address and move to the second when it does not answer, after a timeout of a second or more. That is a failover, not a load balancer, so size each instance to carry all the traffic alone.

Do not chain them: configure each with public or provider upstreams, not with the other instance. A loop between two resolvers turns one slow answer into many.

---

## Keeping them alike

Clients may land on either instance at any moment, so both should filter alike. The dashboard export carries the setup from one to the other:

1. On the first instance, **Settings → Backup → Download Backup**.
2. On the second, import the file under **Settings → Backup**, then restart it.

The file carries:

- the server, DNS, blocking, DNS64, logging and authentication settings;
- the upstream pools and their routes;
- rate limiting and the malware detection settings;
- the groups, the blocklist sources and the local DNS records.

It carries no secrets: no password hashes, no API tokens and no TLS keys. It also leaves out the clients and their group assignments, managed domains, regex filters, users and the query log. Set those up on each instance, or repeat the changes on both. Groups and sources that already exist on the target are kept, so importing again after a change adds what is new. See [Import Config](../api.md#import-config) for the details.

---

## What two instances do not share

| Not shared | What it means |
|:-----------|:--------------|
| Sessions and users | You sign in to each dashboard on its own, and each has its own admin password and second factor. |
| Query log and statistics | Each dashboard, and each instance's `/metrics`, shows only the queries that reached it. |
| Clients | Client names and group assignments are learned and kept per instance. |
| Cache | Each warms its own. |

There is no clustering, replication or shared state between instances, and running two servers on one database file is not supported. A floating address that moves between two hosts, with keepalived for example, would let clients keep a single resolver address. It works at the network layer and has not been tested with Ferrous DNS, so it is not covered here.

---

## Watching both

Scrape both instances from the same Prometheus job and load the [alert rules](logs-monitoring.md#alert-rules) once: every alert carries the `instance` label, so each server is watched on its own. `FerrousDnsDown` on one instance means the other is carrying all the traffic.
