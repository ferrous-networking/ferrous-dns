-- Rewrite the v4-mapped client addresses left behind by earlier releases.
--
-- Before the DoT/DoQ peer-address fix, a listener bound on `[::]` reported an
-- IPv4 client as `::ffff:10.0.0.1`. That string was stored verbatim, so the
-- same device could end up with two client rows, two sets of query-log
-- entries, and a group assignment on whichever row the operator happened to
-- see. Now that every listener keys the device as `10.0.0.1`, the mapped rows
-- would simply stop matching, silently dropping the client back to the
-- default group.
--
-- `::ffff:` is 7 characters, so `substr(x, 8)` is the unmapped address. The
-- `%.%.%.%` guard keeps this to the dotted-quad form Rust emits and leaves any
-- genuine IPv6 address alone.

-- 1. Fold a mapped row into its plain twin where both exist. The plain row
--    keeps its identity; the mapped row contributes what the plain one lacks.
--    `group_id` matters most: NULL means the default group, so a group the
--    operator assigned to the mapped row wins over the plain row's default,
--    but never over an explicit assignment.
UPDATE clients
SET query_count = query_count + COALESCE((
        SELECT m.query_count FROM clients m
        WHERE m.ip_address = '::ffff:' || clients.ip_address
    ), 0),
    first_seen = MIN(first_seen, COALESCE((
        SELECT m.first_seen FROM clients m
        WHERE m.ip_address = '::ffff:' || clients.ip_address
    ), first_seen)),
    last_seen = MAX(last_seen, COALESCE((
        SELECT m.last_seen FROM clients m
        WHERE m.ip_address = '::ffff:' || clients.ip_address
    ), last_seen)),
    mac_address = COALESCE(mac_address, (
        SELECT m.mac_address FROM clients m
        WHERE m.ip_address = '::ffff:' || clients.ip_address
    )),
    hostname = COALESCE(hostname, (
        SELECT m.hostname FROM clients m
        WHERE m.ip_address = '::ffff:' || clients.ip_address
    )),
    group_id = COALESCE(group_id, (
        SELECT m.group_id FROM clients m
        WHERE m.ip_address = '::ffff:' || clients.ip_address
    )),
    updated_at = CURRENT_TIMESTAMP
WHERE EXISTS (
    SELECT 1 FROM clients m
    WHERE m.ip_address = '::ffff:' || clients.ip_address
);

-- 2. Drop the mapped rows just merged, so the rename below cannot collide with
--    the UNIQUE index on ip_address.
DELETE FROM clients
WHERE ip_address LIKE '::ffff:%.%.%.%'
  AND substr(ip_address, 8) IN (SELECT ip_address FROM clients);

-- 3. Rename the mapped rows that had no plain twin.
UPDATE clients
SET ip_address = substr(ip_address, 8),
    updated_at = CURRENT_TIMESTAMP
WHERE ip_address LIKE '::ffff:%.%.%.%';

-- 4. The query log joins back to clients on the address text, so stale mapped
--    entries would lose their hostname in the log view and split the
--    top-clients aggregate.
UPDATE query_log
SET client_ip = substr(client_ip, 8)
WHERE client_ip LIKE '::ffff:%.%.%.%';

-- 5. A subnet an operator wrote to work around the old behaviour
--    (`::ffff:10.0.0.0/104`) has to lose both the prefix and the 96 bits it
--    added to the mask. Same collision handling as the client rows: an
--    equivalent plain subnet already present wins.
DELETE FROM client_subnets
WHERE subnet_cidr LIKE '::ffff:%.%.%.%/%'
  AND CAST(substr(subnet_cidr, instr(subnet_cidr, '/') + 1) AS INTEGER) >= 96
  AND (
        substr(subnet_cidr, 8, instr(subnet_cidr, '/') - 8)
        || '/'
        || CAST(CAST(substr(subnet_cidr, instr(subnet_cidr, '/') + 1) AS INTEGER) - 96 AS TEXT)
      ) IN (SELECT subnet_cidr FROM client_subnets);

UPDATE client_subnets
SET subnet_cidr = substr(subnet_cidr, 8, instr(subnet_cidr, '/') - 8)
                  || '/'
                  || CAST(CAST(substr(subnet_cidr, instr(subnet_cidr, '/') + 1) AS INTEGER) - 96 AS TEXT),
    updated_at = CURRENT_TIMESTAMP
WHERE subnet_cidr LIKE '::ffff:%.%.%.%/%'
  AND CAST(substr(subnet_cidr, instr(subnet_cidr, '/') + 1) AS INTEGER) >= 96;
